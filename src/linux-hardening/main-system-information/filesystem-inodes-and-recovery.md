# Fajl sistemi, inode-i i oporavak

{{#include ../../banners/hacktricks-training.md}}

Abuse fajl sistema često se zasniva na zbunjivanju odnosa između vidljive putanje i objekta koji se iza nje nalazi. Disk images mogu skrivati drugi fajl sistem, writable mount-ovi mogu biti iskorišćeni od strane privileged job-ova, hardlink-ovi mogu izložiti isti inode pod drugim imenom, a obrisani fajlovi se i dalje mogu čitati preko otvorenog file descriptor-a.

Ova stranica se fokusira na tehniku, a ne na jednu konkretnu laboratoriju ili metu.

## Disk Images i Loop Mount-ovi

Običan fajl može sadržati kompletan fajl sistem. Backup images, kopirani block device-ovi, VM artifacts ili preimenovani blob-ovi zato mogu sadržati credentials, scripts, SSH keys, configuration files ili flags, čak i kada spolja ne izgledaju korisno.

Identifikujte moguće images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ako je montiranje dozvoljeno, prvo montirajte nepoznate image datoteke samo za čitanje:
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
Tehnika je korisna zato što datoteku koja izgleda uobičajeno pretvara u drugo filesystem stablo. Posmatrajte je kao način za oporavak skrivenih podataka, a ne kao samostalni privilege escalation.

## Writable Mount Abuse

Writable mount postaje opasan kada privilegovaniji kontekst kasnije veruje nečemu unutar njega. Važno pitanje nije samo „da li mogu da pišem ovde?“, već i „ko će kasnije odavde čitati, izvršavati, importovati ili učitavati podatke?“.

Pronađite writable mount-ove i sumnjive potrošače:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Uobičajeni obrasci zloupotrebe:

- Privilegovani cron ili systemd unit pokreće skriptu sa dozvolom upisa sa mount-a.
- Privilegovani servis učitava plugins, config, templates ili pomoćne binaries sa mount-a.
- Mount sadrži SUID fajlove i omogućava njihovu izmenu, zamenu ili manipulaciju putanjom.
- Container ili chroot izlaže putanju podržanu hostom koja je dostupna za upis iz ograničenog okruženja.

Opšti obrazac validacije:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Kada dokazujete uticaj u autorizovanoj laboratoriji, učinite payload vidljivim i minimalnim, na primer upisivanjem izlaza komande `id` u privremenu datoteku. Suština tehnike je odloženo izvršavanje kroz pouzdanu lokaciju sa pravom upisa.

## Inode-i i konfuzija putanja

Inode je objekat sistema datoteka; putanja je samo naziv koji pokazuje na njega. Ovo je važno zato što dve različite putanje mogu pokazivati na isti inode, a brisanje imena putanje ne znači uvek da su podaci nestali.

Uporedite datoteke prema inode-u i uređaju:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Pronađite svaku vidljivu putanju za isti inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pretražite direktno po broju inode-a kada imate samo metapodatke:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ova tehnika je korisna kada se datoteka pojavljuje pod neočekivanim imenom, kada aplikacija proverava jednu putanju, ali koristi drugu, ili kada privilegovani wrapper stupa u interakciju sa inode-om koji je takođe dostupan na drugom mestu.

## Hardlink Abuse

Hardlinkovi kreiraju više imena za isti inode. Oni ne upućuju na ciljnu putanju kao symlinkovi; predstavljaju ravnopravna imena za isti objekat datoteke.

Pronađite SUID datoteke sa više hardlinkova:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Pregledajte jednu sumnjivu datoteku:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Zašto je to važno:

- Osetljiva datoteka može biti dostupna putem manje očigledne putanje.
- SUID wrapper može biti sakriven iza naziva koji ne deluje privilegovano.
- Čišćenje koje ukloni jednu putanju može ostaviti drugi hardlink aktivnim.

Moderni kerneli i mount opcije mogu ograničiti kreiranje hardlink-ova kako bi smanjili ovu vrstu zloupotrebe, ali postojeće hardlink-ove i dalje vredi proveriti.

## Oporavak obrisanih datoteka putem otvorenih FD-ova

Kada proces drži datoteku otvorenom, podaci datoteke mogu ostati dostupni čak i nakon brisanja putanje. Linux izlaže te otvorene deskriptore u `/proc/<pid>/fd/`.

Pronađi obrisane otvorene datoteke:
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
Ovo je praktična tehnika za oporavak obrisanih logova, privremenih secrets, odbačenih binaries, rotiranih fajlova ili skripti uklonjenih nakon izvršavanja.

## ext Recovery With debugfs

Na ext filesystemima, `debugfs` može da pregleda metadata inode-a i ponekad izvuče sadržaj fajlova iz filesystem image-a. Kad god je moguće, radite na kopiji ili read-only image-u.

Izlistajte entries i pregledajte inode-e:
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
Ovo nije garantovana obnova. Zavisi od stanja filesystema, od toga da li su blokovi ponovo korišćeni i od toga da li metapodaci još uvek postoje. Tehnika je i dalje korisna jer omogućava pregled stanja na nivou inode-a bez oslanjanja na uobičajeni path traversal.

## Iscrpljivanje inode-ova i redosled

Iscrpljivanje inode-ova nastaje kada filesystem ostane bez file objekata, čak i ako na disku još uvek ima slobodnog prostora. To obično izaziva probleme sa pouzdanošću, ali može objasniti i neobično ponašanje tokom incident response-a ili analize u lab okruženju.

Proverite pritisak na inode-e:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Brojevi inode-a i vremenske oznake takođe mogu pomoći u rekonstrukciji aktivnosti u jednostavnim laboratorijskim okruženjima:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Tretirajte redosled kao naznaku, a ne kao dokaz. Operacije kopiranja, raspakivanje arhiva, tip filesystema, vraćanje podataka i istovremeni upisi mogu promeniti obrasce alokacije.

## Defanzivne napomene

- Nepoznate image datoteke montirajte samo za čitanje tokom analize.
- Privilegovane skripte, service units, plugins i helper putanje držite izvan mountova u koje korisnici mogu da upisuju.
- Koristite `nosuid`, `nodev` i `noexec` gde je to operativno prikladno, ali ih ne smatrajte potpunom granicom.
- Ograničite pristup putanji `/proc/<pid>/fd`, metapodacima procesa i inspekciji procesa drugih korisnika gde je to moguće.
- Nadgledajte mount tačke u koje je moguće upisivati, neočekivane hardlinkove ka privilegovanim datotekama i osetljive datoteke koje su obrisane, ali su i dalje otvorene.
{{#include ../../banners/hacktricks-training.md}}
