# Fajl sistemi, inode-ovi i oporavak

{{#include ../../banners/hacktricks-training.md}}

Abuse fajl sistema često se zasniva na zbunjivanju odnosa između vidljive putanje i objekta koji se iza nje nalazi. Disk images mogu skrivati drugi fajl sistem, writable mount-ovi mogu biti iskorišćeni od strane privilegovanih poslova, hardlinks mogu izložiti isti inode pod drugim imenom, a obrisane datoteke i dalje mogu biti čitljive preko otvorenog file descriptor-a.

Ova stranica se fokusira na tehniku, a ne na jednu konkretnu laboratoriju ili metu.

## Disk Images i Loop Mounts

Obična datoteka može sadržati kompletan fajl sistem. Backup images, kopirani block devices, VM artifacts ili preimenovani blobs stoga mogu sadržati credentials, skripte, SSH ključeve, configuration files ili flags, čak i kada spolja ne izgledaju korisno.

Identifikujte potencijalne images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ako je mountovanje dozvoljeno, prvo montirajte nepoznate image datoteke u režimu samo za čitanje:
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
Tehnika je korisna zato što datoteku normalnog izgleda pretvara u drugo stablo filesystem-a. Posmatrajte je kao način za oporavak skrivenih podataka, a ne kao samostalnu privilege escalation tehniku.

## Zloupotreba mount-a sa dozvolom upisa

Mount sa dozvolom upisa postaje opasan kada privilegovaniji kontekst kasnije veruje nečemu unutar njega. Važno pitanje nije samo „da li mogu da upisujem ovde?“, već i „ko će kasnije odavde čitati, izvršavati, importovati ili učitavati podatke?“.

Pronađite mount-ove sa dozvolom upisa i sumnjive potrošače:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Uobičajeni obrasci zloupotrebe:

- Privilegovani cron ili systemd unit pokreće skriptu sa dozvolom upisa sa mount-a.
- Privilegovani servis učitava plugine, config, šablone ili pomoćne binarne datoteke sa mount-a.
- Mount sadrži SUID datoteke i omogućava njihovu izmenu, zamenu ili manipulaciju putanjom.
- Container ili chroot izlaže putanju koju podržava host, a koja je upisiva iz ograničenog okruženja.

Opšti obrazac validacije:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Kada dokazujete uticaj u autorizovanoj laboratoriji, neka payload bude vidljiv i minimalan, na primer tako što ćete izlaz komande `id` upisati u privremeni fajl. Osnovna tehnika je odloženo izvršavanje kroz pouzdanu lokaciju sa dozvolom za upis.

## Inode-i i zabuna oko putanja

Inode je objekat filesystem-a; putanja je samo naziv koji upućuje na njega. Ovo je važno zato što dve različite putanje mogu upućivati na isti inode, a obrisano ime putanje ne znači uvek da su podaci nestali.

Uporedite fajlove prema inode-u i uređaju:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Pronađite sve vidljive putanje do istog inode-a:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pretražite direktno po broju inode-a kada imate samo metapodatke:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ova tehnika je korisna kada se datoteka pojavljuje pod neočekivanim imenom, kada aplikacija proverava jednu putanju, ali koristi drugu, ili kada privilegovani wrapper komunicira sa inode-om koji je dostupan i na drugom mestu.

## Hardlink Abuse

Hardlinks kreiraju više imena za isti inode. Oni ne upućuju na ciljnu putanju kao symlinks; to su jednaka imena za isti objekat datoteke.

Pronađite SUID datoteke sa više hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Pregledajte jednu sumnjivu datoteku:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Zašto je važno:

- Osetljiva datoteka može biti dostupna kroz manje očiglednu putanju.
- SUID wrapper može biti skriven iza naziva koji ne izgleda privilegovano.
- Čišćenje kojim se uklanja jedna putanja može ostaviti drugi hardlink aktivnim.

Moderni kernel-i i mount opcije mogu ograničiti kreiranje hardlink-ova kako bi se smanjila ova vrsta zloupotrebe, ali postojeće hardlink-ove i dalje vredi pregledati.

## Oporavak obrisanih datoteka putem otvorenih FD-ova

Kada proces drži datoteku otvorenom, podaci datoteke mogu ostati dostupni čak i nakon brisanja putanje. Linux izlaže te otvorene deskriptore pod `/proc/<pid>/fd/`.

Pronalaženje obrisanih otvorenih datoteka:
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
Ovo je praktična tehnika za oporavak obrisanih logova, privremenih tajni, odbačenih binarnih datoteka, rotiranih datoteka ili skripti uklonjenih nakon izvršavanja.

## Oporavak na ext sistemima pomoću debugfs

Na ext sistemima datoteka, `debugfs` može da pregleda metapodatke inode-a i ponekad izvuče sadržaj datoteka iz image-a sistema datoteka. Kad god je moguće, radite na kopiji ili image-u otvorenom samo za čitanje.

Izlistajte stavke i pregledajte inode-e:
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
Oporavak nije garantovan. Zavisi od stanja filesystem-a, od toga da li su blokovi ponovo korišćeni i od toga da li metapodaci još uvek postoje. Tehnika je i dalje korisna jer omogućava pregled stanja na nivou inode-a bez oslanjanja na uobičajeni prolazak kroz putanje.

## Iscrpljivanje inode-ova i redosled

Do iscrpljivanja inode-ova dolazi kada filesystem ostane bez objekata datoteka, čak i ako na disku i dalje ima slobodnog prostora. To obično izaziva probleme sa pouzdanošću, ali može objasniti i neobično ponašanje tokom incident response-a ili triage-a u laboratoriji.

Proverite opterećenje inode-ova:
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
Tretirajte redosled kao naznaku, a ne kao dokaz. Operacije kopiranja, raspakivanje arhiva, tip sistema datoteka, vraćanja i istovremeni upisi mogu promeniti obrasce alokacije.

## Odbrambene napomene

- Nepoznate image datoteke montirajte u režimu samo za čitanje tokom analize.
- Privilegovane skripte, service units, plugins i putanje do pomoćnih programa držite izvan mount-ova u koje korisnici mogu da upisuju.
- Koristite `nosuid`, `nodev` i `noexec` tamo gde je to operativno prikladno, ali ih nemojte smatrati potpunom granicom.
- Ograničite pristup ka `/proc/<pid>/fd`, metapodacima procesa i inspekciji procesa drugih korisnika gde je to moguće.
- Pratite mount tačke sa mogućnošću upisa, neočekivane hardlinks ka privilegovanim datotekama i osetljive datoteke koje su obrisane, ali su i dalje otvorene.

{{#include ../../banners/hacktricks-training.md}}
