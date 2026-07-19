# Fajl sistem, inode-i i oporavak

{{#include ../../banners/hacktricks-training.md}}

Zloupotreba fajl sistema često podrazumeva zbunjivanje odnosa između vidljive putanje i objekta koji se iza nje nalazi. Disk images mogu skrivati drugi fajl sistem, writable mount-ovi mogu biti iskorišćeni od strane privileged job-ova, hardlink-ovi mogu izložiti isti inode pod drugim imenom, a obrisani fajlovi i dalje mogu biti čitljivi preko otvorenog file descriptor-a.

Ova stranica se fokusira na tehniku, a ne na jednu konkretnu lab ili metu.

## Disk Images i Loop Mount-ovi

Običan fajl može sadržati kompletan fajl sistem. Backup images, kopirani block devices, VM artifacts ili preimenovani blobs stoga mogu sadržati credentials, scripts, SSH keys, configuration files ili flags, čak i kada spolja ne izgledaju korisno.

Identifikujte moguće images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ako je montiranje dozvoljeno, prvo montirajte nepoznate image-e samo za čitanje:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ako montiranje nije dostupno, direktno pregledajte metapodatke sistema datoteka:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Tehnika je korisna zato što običan fajl pretvara u drugo stablo filesystem-a. Posmatrajte je kao način za oporavak skrivenih podataka, a ne kao samostalni način za privilege escalation.

## Writable Mount Abuse

Writable mount postaje opasan kada privilegovaniji kontekst kasnije veruje nečemu što se u njemu nalazi. Važno pitanje nije samo „da li mogu da upisujem ovde?“, već i „ko će kasnije odavde čitati, izvršavati, importovati ili učitavati podatke?“.

Pronađite writable mount-ove i sumnjive potrošače:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Uobičajeni obrasci zloupotrebe:

- Privilegovani cron ili systemd unit pokreće writable skriptu sa mount-a.
- Privilegovani servis učitava plugins, config, templates ili helper binaries sa mount-a.
- Mount sadrži SUID fajlove i dozvoljava njihovu izmenu, zamenu ili manipulaciju putanjom.
- Container ili chroot izlaže host-backed putanju koja je writable iz ograničenog okruženja.

Generički obrazac validacije:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Kada dokazujete uticaj u ovlašćenom labu, neka payload bude vidljiv i minimalan, na primer upisivanjem izlaza komande `id` u privremenu datoteku. Osnovna tehnika je odloženo izvršavanje kroz pouzdanu lokaciju u koju je moguće upisivati.

## Inode-ovi i zabuna oko putanja

inode je objekat filesystema; putanja je samo naziv koji pokazuje na njega. Ovo je važno zato što dve različite putanje mogu pokazivati na isti inode, a obrisani naziv putanje ne znači uvek da su podaci nestali.

Uporedite datoteke prema inode-u i uređaju:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Pronađite svaku vidljivu putanju za isti inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pretražite direktno prema broju inode-a kada imate samo metapodatke:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ova tehnika je korisna kada se datoteka pojavljuje pod neočekivanim imenom, kada aplikacija proverava jednu putanju, ali koristi drugu, ili kada privilegovani wrapper radi sa inode-om koji je dostupan i na drugom mestu.

## Hardlink Abuse

Hardlinks kreiraju više imena za isti inode. Oni ne upućuju na ciljnu putanju kao symlinks; predstavljaju jednaka imena za isti objekat datoteke.

Pronađite SUID datoteke sa više hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Pregledajte jednu sumnjivu datoteku:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Zašto je to važno:

- Osetljiv fajl može biti dostupan kroz manje očiglednu putanju.
- SUID wrapper može biti sakriven iza imena koje ne izgleda privilegovano.
- Čišćenje koje ukloni jednu putanju može ostaviti drugi hardlink aktivnim.

Moderni kernels i mount options mogu ograničiti kreiranje hardlink-ova kako bi smanjili ovu vrstu zloupotrebe, ali postojeće hardlink-ove i dalje vredi proveriti.

## Oporavak obrisanih fajlova kroz otvorene FD-ove

Kada proces drži fajl otvorenim, podaci fajla mogu ostati dostupni čak i nakon brisanja putanje. Linux izlaže te otvorene deskriptore pod `/proc/<pid>/fd/`.

Pronađite obrisane otvorene fajlove:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Oporavite podatke kada dozvole to omogućavaju:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Ovo je praktična tehnika za oporavak obrisanih logova, privremenih secrets, odbačenih binarnih datoteka, rotiranih datoteka ili skripti uklonjenih nakon izvršavanja.

## ext oporavak pomoću debugfs

Na ext filesystemima, `debugfs` može da pregleda metapodatke inode-a i ponekad izvuče sadržaj datoteka iz image-a filesystema. Kad god je moguće, radite na kopiji ili image-u otvorenom samo za čitanje.

Izlistajte unose i pregledajte inode-e:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump poznatog inode-a:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Oporavak nije zagarantovan. Zavisi od stanja fajl sistema, od toga da li su blokovi ponovo iskorišćeni i od toga da li metapodaci još uvek postoje. Ova tehnika je i dalje korisna jer omogućava pregled stanja na nivou inode-a bez oslanjanja na normalni path traversal.

## Iscrpljivanje inode-ova i redosled

Iscrpljivanje inode-ova nastaje kada fajl sistem ostane bez objekata datoteka, čak i kada na disku i dalje ima slobodnog prostora. To obično uzrokuje probleme sa pouzdanošću, ali može objasniti i neobično ponašanje tokom incident response-a ili lab triage-a.

Proverite opterećenje inode-ova:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Brojevi inode-ova i vremenske oznake takođe mogu pomoći u rekonstrukciji aktivnosti u jednostavnim laboratorijskim okruženjima:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Tretirajte redosled kao naznaku, a ne kao dokaz. Operacije kopiranja, ekstrakcija arhiva, tip filesystema, vraćanja iz rezervnih kopija i istovremeni upisi mogu promeniti obrasce alokacije.

## Odbrambene napomene

- Montirajte nepoznate image fajlove u režimu read-only tokom analize.
- Držite privilegovane skripte, servisne jedinice, plugine i putanje pomoćnih programa izvan mountova u koje korisnici mogu da upisuju.
- Koristite `nosuid`, `nodev` i `noexec` gde je to operativno odgovarajuće, ali nemojte ih smatrati potpunom granicom.
- Ograničite pristup putanji `/proc/<pid>/fd`, metapodacima procesa i inspekciji procesa drugih korisnika gde je to moguće.
- Nadgledajte mount tačke sa dozvoljenim upisom, neočekivane hardlinkove ka privilegovanim fajlovima i osetljive fajlove koji su obrisani, ali još uvek otvoreni.
