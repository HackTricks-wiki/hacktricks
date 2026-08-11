# Fajl sistem, inode-i i oporavak

{{#include ../../banners/hacktricks-training.md}}

Zloupotreba fajl sistema često podrazumeva mešanje odnosa između vidljive putanje i objekta koji se iza nje nalazi.

Disk images mogu sakriti drugi fajl sistem.<sup>[[1]](#references)</sup> Mount-ovi sa dozvolom upisa mogu biti iskorišćeni od strane privilegovanih poslova.

Hardlinks mogu izložiti isti inode pod drugim imenom.<sup>[[3]](#references)</sup> Obrisane datoteke i dalje mogu biti čitljive preko otvorenog file descriptor-a.<sup>[[5]](#references)[[6]](#references)</sup>

Ova stranica se fokusira na tehniku, a ne na jednu konkretnu laboratoriju ili metu.

## Disk Images i Loop Mount-ovi

Obična datoteka može sadržati kompletan fajl sistem, pa disk image prilikom mountovanja može izložiti drugo stablo fajl sistema.<sup>[[1]](#references)</sup>

Backup images, kopirani block devices, VM artifacts ili preimenovani blobs stoga mogu sadržati credentials, scripts, SSH keys, configuration files ili flags, čak i kada spolja ne izgledaju korisno.

Identifikujte verovatne images pomoću `file` za klasifikaciju kandidata, `blkid` za ispitivanje prepoznatih metapodataka fajl sistema i `strings -a` za skeniranje cele datoteke u potrazi za sekvencama znakova koje se mogu ispisati.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Kada je montiranje dozvoljeno, koristite loop mount sa `ro` opcijom kako bi image bio prikačen samo za čitanje; komanda `find` u nastavku ograničava dubinu inspekcije i tip fajla.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ako montiranje nije dostupno, a image je ext2/ext3/ext4, pregledajte njegove metapodatke direktno pomoću `debugfs`-a.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Tehnika je korisna jer pretvara datoteku normalnog izgleda u drugo stablo filesystema.<sup>[[1]](#references)</sup> Tretirajte je kao način za oporavak skrivenih podataka, a ne kao samostalnu eskalaciju privilegija.

## Zloupotreba mount-a sa dozvolom upisa

Mount sa dozvolom upisa postaje opasan kada privilegovaniji kontekst kasnije veruje nečemu unutar njega. Važno pitanje nije samo „da li mogu da upisujem ovde?“, već i „ko će kasnije odavde čitati, izvršavati, importovati ili učitavati?“.

Koristite `findmnt` za pregled mount-ovanih filesystema i njihovih opcija.<sup>[[9]](#references)</sup>

Pronađite mount-ove sa dozvolom upisa i sumnjive korisnike koristeći dokumentovane `find` predikate za dozvole, tip i granice filesystema, a zatim koristite rekurzivni `grep` za pretragu verovatne konfiguracije korisnika.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Uobičajeni obrasci zloupotrebe:

- Cron job ili systemd service pokreće skriptu sa dozvolom upisa iz mount-a.<sup>[[13]](#references)[[14]](#references)</sup>
- Privilegovani service učitava plugins, konfiguraciju, templates ili pomoćne binarne fajlove sa mount-a.
- Mount sadrži SUID fajlove i omogućava njihovu izmenu, zamenu ili manipulaciju putanjama.
- Container ili chroot izlaže putanju zasnovanu na hostu, u koju je moguće upisivati iz ograničenog okruženja. Mount namespaces obezbeđuju zasebne hijerarhije mount-ova, dok `chroot()` menja samo razrešavanje putanja i nije potpuni sandbox.<sup>[[15]](#references)[[16]](#references)</sup>

Generički obrazac validacije koji koristi iste `find` predikate.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Kada dokazujete uticaj u ovlašćenoj laboratoriji, payload treba da bude vidljiv i minimalan, na primer upisivanjem izlaza komande `id` u privremenu datoteku.<sup>[[23]](#references)</sup> Osnovna tehnika je odloženo izvršavanje preko pouzdane lokacije sa dozvolom upisivanja.

## Inode-i i zabuna oko putanja

Inode je objekat datotečnog sistema; putanja je samo naziv koji pokazuje na njega. Metapodaci uređaja i inode-a omogućavaju razlikovanje objekata u različitim datotečnim sistemima, dok broj linkova otkriva postojanje više hard linkova.<sup>[[3]](#references)</sup> Obrisana putanja ne znači uvek da su podaci nestali dok proces još uvek ima otvorenu datoteku.<sup>[[5]](#references)</sup>

Predikati `find` navedeni u nastavku upoređuju identitet inode-a, broj linkova, granice uređaja i vremenske oznake.<sup>[[4]](#references)</sup>

Uporedite datoteke prema inode-u i uređaju pomoću komandi `ls -i` i formata metapodataka komande `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Pronađite svaku vidljivu putanju za isti inode pomoću `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pretražite direktno po broju inode-a pomoću `find -inum` kada imate samo metapodatke.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ova tehnika je korisna kada se datoteka pojavljuje pod neočekivanim imenom, kada aplikacija proverava jednu putanju, ali koristi drugu, ili kada privilegovani wrapper radi sa inode-om koji je takođe dostupan na drugom mestu.

## Hardlink Abuse

Hardlink-ovi kreiraju više imena za isti inode. Oni ne upućuju na ciljnu putanju kao symlink-ovi; to su jednaka imena za isti objekat datoteke.<sup>[[3]](#references)</sup>

Pronađite SUID datoteke sa više hardlink-ova koristeći `find` predikate za dozvole i broj linkova.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Pregledajte jednu sumnjivu datoteku pomoću `stat` i `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Zašto je važno:

- Osetljivoj datoteci može biti moguće pristupiti kroz manje očiglednu putanju.
- SUID wrapper može biti sakriven iza naziva koji ne deluje privilegovano.
- Čišćenje kojim se uklanja jedna putanja može ostaviti drugi hardlink aktivnim.

Linux-ov `fs.protected_hardlinks` sysctl može ograničiti kreiranje hardlinkova preko granica privilegija.<sup>[[7]](#references)</sup> Postojeći hardlinkovi i dalje zahtevaju proveru.

## Oporavak obrisanih datoteka kroz otvorene FD-ove

Kada proces drži datoteku otvorenom, uklanjanje njene poslednje putanje ostavlja datoteku aktivnom sve dok se poslednji descriptor ne zatvori; Linux te descriptore izlaže u `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Pronađite obrisane otvorene datoteke izlistavanjem descriptor-a u `/proc` i filtriranjem izlaza otvorenih datoteka.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Oporavak putem ovih veza zavisi od dozvola, jer dereferenciranje `/proc/<pid>/fd` podleže `ptrace` proverama pristupa i dozvolama nad datotekama.<sup>[[6]](#references)</sup>

Kada je to dozvoljeno, `readlink` prikazuje cilj deskriptora, a `cp` kopira njegov sadržaj.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Ovo je praktična tehnika za oporavak obrisanih logova, privremenih tajni, odbačenih binarnih datoteka, rotiranih datoteka ili skripti uklonjenih nakon izvršavanja.

## Oporavak ext pomoću debugfs

Na ext2/ext3/ext4 sistemima datoteka, `debugfs` može da pregleda metapodatke inode-a i izvuče sadržaj inode-a sa blok uređaja ili image-a; bez opcije `-w`, otvara sistem datoteka samo za čitanje.<sup>[[2]](#references)</sup> Kad god je moguće, radite sa kopijom ili image-om otvorenim samo za čitanje.

Izlistajte unose i pregledajte inode-e pomoću `debugfs` zahteva za izlistavanje direktorijuma, status inode-a i proveru putanje na osnovu inode-a.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Izvezite poznati inode pomoću komande `debugfs dump`, a zatim klasifikujte oporavljeni izlaz pomoću komande `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Ovo nije garantovan oporavak. Zavisi od stanja fajl sistema, od toga da li su blokovi ponovo korišćeni i od toga da li metapodaci još uvek postoje. Za ext3/ext4, priručnik za `debugfs` navodi da oporavak obrisanih inode-ova može da ne uspe zato što blokovi podataka oslobođenih inode-ova više nisu dostupni.<sup>[[2]](#references)</sup> Tehnika je i dalje vredna jer omogućava pregled stanja na nivou inode-ova bez oslanjanja na uobičajeni prolaz kroz putanje.

## Iscrpljivanje inode-ova i redosled

Iscrpljivanje inode-ova nastaje kada fajl sistem ostane bez čvorova fajlova, čak i ako na disku još uvek ima slobodnog prostora.<sup>[[8]](#references)[[17]](#references)</sup> To obično uzrokuje probleme sa pouzdanošću, ali takođe može objasniti neobično ponašanje tokom odgovora na incident ili trijaže u laboratoriji.

Koristite `df -i` za prikaz informacija o inode-ovima umesto korišćenja blokova.<sup>[[8]](#references)</sup>

Proverite opterećenje inode-ova pomoću `df` i brojanjem nadređenih direktorijuma pomoću komande `find`.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Brojevi inode-a i vremenske oznake takođe mogu pomoći u rekonstrukciji aktivnosti u jednostavnim laboratorijskim okruženjima.

Direktive formata `find` u nastavku prikazuju ta polja.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Redosled tretirajte kao smernicu, a ne kao dokaz. Operacije kopiranja, ekstrakcija arhiva, tip filesystema, vraćanje podataka i istovremeni upisi mogu promeniti obrasce alokacije.

## Defanzivne napomene

- Nepoznate images montirajte u read-only režimu tokom analize.<sup>[[1]](#references)</sup>
- Privilegovane skripte, service units, plugins i pomoćne putanje držite izvan mountova u koje korisnici mogu da upisuju.
- Koristite `nosuid`, `nodev` i `noexec` gde je to operativno prikladno; ove opcije onemogućavaju izvršavanje set-ID/capability programa, interpretaciju uređaja ili direktno izvršavanje binary fajlova na mountu.<sup>[[1]](#references)</sup> Nemojte ih tretirati kao potpunu granicu.
- Ograničite pristup putanji `/proc/<pid>/fd`; dereferenciranje ovih linkova kontrolišu ptrace provere pristupa i dozvole fajlova.<sup>[[6]](#references)</sup> Gde je moguće, ograničite šire metapodatke o procesima i inspekciju između korisnika.
- Nadgledajte writable mount point-e, neočekivane hardlinkove ka privilegovanim fajlovima i osetljive fajlove koji su obrisani, ali su i dalje otvoreni.

## References

- [1] [mount(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux stranica priručnika](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Dokumentacija za /proc/sys/fs/ — dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux stranica priručnika](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
