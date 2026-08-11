# Filesystem, inode-i i oporavak

Zloupotreba filesystem-a često se svodi na stvaranje zabune u odnosu između vidljive putanje i objekta koji se nalazi iza nje.

Disk image-i mogu sakriti drugi filesystem.<sup>[[1]](#references)</sup> Mount-ovi sa dozvolom upisivanja mogu biti iskorišćeni od strane privilegovanih job-ova.

Hardlink-ovi mogu izložiti isti inode pod drugim imenom.<sup>[[3]](#references)</sup> Obrisani fajlovi i dalje mogu biti čitljivi preko otvorenog file descriptor-a.<sup>[[5]](#references)[[6]](#references)</sup>

Ova stranica se fokusira na tehniku, a ne na jednu konkretnu laboratoriju ili target.

## Disk Images i Loop Mounts

Regularan fajl može sadržati kompletan filesystem, tako da disk image može izložiti drugo stablo filesystem-a kada se mount-uje.<sup>[[1]](#references)</sup>

Backup image-i, kopirani block device-i, VM artifact-i ili preimenovani blob-ovi stoga mogu sadržati credentials, skripte, SSH ključeve, configuration fajlove ili flags, čak i kada spolja ne izgledaju korisno.

Identifikujte potencijalne image-e pomoću `file` za klasifikaciju kandidata, `blkid` za ispitivanje prepoznatih metadata filesystem-a i `strings -a` za skeniranje celog fajla u potrazi za štampanim sekvencama.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Kada je montiranje dozvoljeno, koristite loop mount sa `ro` kako bi image bio prikačen samo za čitanje; komanda `find` u nastavku ograničava dubinu inspekcije i tip datoteke.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ako montiranje nije dostupno, a image je ext2/ext3/ext4, direktno pregledajte njegove metapodatke pomoću alata `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
The technique is useful because it turns a normal-looking file into a second filesystem tree.<sup>[[1]](#references)</sup> Tretirajte ga kao način za oporavak skrivenih podataka, a ne kao samostalni privilege escalation.

## Writable Mount Abuse

Writable mount postaje opasan kada privilegovaniji kontekst kasnije veruje nečemu unutar njega. Važno pitanje nije samo „da li mogu da pišem ovde?”, već i „ko će kasnije odavde čitati, izvršavati, importovati ili učitavati?”.

Koristite `findmnt` za pregled montiranih filesystema i njihovih opcija.<sup>[[9]](#references)</sup>

Pronađite writable mount tačke i sumnjive potrošače pomoću dokumentovanih `find` predikata za dozvole, tip i granice filesystema, a zatim koristite rekurzivni `grep` za pretragu verovatne konfiguracije potrošača.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Uobičajeni obrasci zloupotrebe:

- Cron job ili systemd service pokreće writable script sa mount-a.<sup>[[13]](#references)[[14]](#references)</sup>
- Privileged service učitava plugins, config, templates ili helper binaries sa mount-a.
- Mount sadrži SUID files i omogućava izmenu, zamenu ili manipulaciju putanjom.
- Container ili chroot izlaže host-backed path koji je writable iz restricted environment-a. Mount namespaces obezbeđuju zasebne mount hijerarhije, dok `chroot()` menja samo razrešavanje putanja i nije potpuni sandbox.<sup>[[15]](#references)[[16]](#references)</sup>

Generički obrazac validacije koji koristi iste `find` predicates.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Kada dokazujete uticaj u ovlašćenoj laboratoriji, održavajte payload vidljivim i minimalnim, na primer upisivanjem izlaza komande `id` u privremenu datoteku.<sup>[[23]](#references)</sup> Osnovna tehnika je odloženo izvršavanje putem pouzdane lokacije sa dozvolom upisa.

## Inode-i i zabuna oko putanja

Inode je objekat filesystema; putanja je samo naziv koji pokazuje na njega. Metapodaci uređaja i inode-a omogućavaju razlikovanje objekata na različitim filesystemima, dok broj linkova otkriva postojanje više hard linkova.<sup>[[3]](#references)</sup> Obrisana putanja ne znači uvek da podaci više ne postoje dok proces i dalje ima otvorenu datoteku.<sup>[[5]](#references)</sup>

Predikati komande `find` u nastavku upoređuju identitet inode-a, broj linkova, granice uređaja i vremenske oznake.<sup>[[4]](#references)</sup>

Uporedite datoteke prema inode-u i uređaju pomoću `ls -i` i formata metapodataka komande `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Pronađite svaku vidljivu putanju do istog inode-a pomoću `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Pretražujte direktno prema broju inode-a pomoću `find -inum` kada imate samo metapodatke.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Ova tehnika je korisna kada se datoteka pojavljuje pod neočekivanim imenom, kada aplikacija proverava jednu putanju, ali koristi drugu, ili kada privilegovani wrapper stupa u interakciju sa inode-om kojem se može pristupiti i na drugom mestu.

## Hardlink Abuse

Hardlink-ovi kreiraju više imena za isti inode. Oni ne upućuju na ciljnu putanju kao symlink-ovi; to su ravnopravna imena za isti objekat datoteke.<sup>[[3]](#references)</sup>

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

- Osetljivoj datoteci može se pristupiti putem manje očigledne putanje.
- SUID wrapper može biti skriven iza imena koje ne deluje privilegovano.
- Čišćenje kojim se uklanja jedna putanja može ostaviti drugu hardlink putanju aktivnom.

Linux `fs.protected_hardlinks` sysctl može ograničiti kreiranje hardlinkova između granica privilegija.<sup>[[7]](#references)</sup> Postojeći hardlinkovi i dalje zaslužuju proveru.

## Oporavak obrisanih datoteka putem otvorenih FD-ova

Kada proces drži datoteku otvorenom, uklanjanje njene poslednje putanje ostavlja datoteku aktivnom sve dok se ne zatvori poslednji descriptor; Linux te descriptore izlaže pod `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Pronađite obrisane otvorene datoteke izlistavanjem descriptorâ u `/proc` i filtriranjem izlaza otvorenih datoteka.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Oporavak putem ovih linkova zavisi od dozvola, jer je dereferenciranje `/proc/<pid>/fd` podložno ptrace proverama pristupa i dozvolama nad datotekama.<sup>[[6]](#references)</sup>

Kada je dozvoljeno, `readlink` prikazuje cilj deskriptora, a `cp` kopira njegov sadržaj.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Ovo je praktična tehnika za oporavak obrisanih logova, privremenih secrets, odbačenih binaries, rotiranih fajlova ili skripti uklonjenih nakon izvršavanja.

## ext Oporavak pomoću debugfs

Na ext2/ext3/ext4 filesystems, `debugfs` može da pregleda inode metadata i izvuče sadržaj inode-a sa block device-a ili image-a; bez opcije `-w`, filesystem se otvara samo za čitanje.<sup>[[2]](#references)</sup> Kad god je moguće, radite na kopiji ili image-u otvorenom samo za čitanje.

Izlistajte entries i pregledajte inode-ove pomoću `debugfs` zahteva za izlistavanje direktorijuma, status inode-a i provere putanje na osnovu inode-a.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Izvršite dump poznatog inode-a pomoću komande `debugfs dump`, a zatim klasifikujte oporavljeni izlaz pomoću komande `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Ovo nije garantovani oporavak. Zavisi od stanja filesystema, od toga da li su blokovi ponovo iskorišćeni i od toga da li metapodaci još uvek postoje. Za ext3/ext4, `debugfs` priručnik navodi da oporavak obrisanih inode-ova može da ne uspe jer blokovi podataka oslobođenih inode-ova više nisu dostupni.<sup>[[2]](#references)</sup> Ova tehnika je i dalje korisna jer vam omogućava da pregledate stanje na nivou inode-a bez oslanjanja na uobičajeni prolaz kroz putanje.

## Iscrpljivanje inode-ova i redosled

Iscrpljivanje inode-ova nastaje kada filesystem ostane bez čvorova datoteka, čak i ako na disku i dalje ima slobodnog prostora.<sup>[[8]](#references)[[17]](#references)</sup> To obično izaziva probleme sa pouzdanošću, ali može i da objasni neobično ponašanje tokom incident response-a ili trijaže u laboratoriji.

Koristite `df -i` za prikaz informacija o inode-ovima umesto korišćenja blokova.<sup>[[8]](#references)</sup>

Proverite opterećenje inode-ova pomoću `df` i `find` prebrojavanja roditelja direktorijuma.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Brojevi inode-a i vremenske oznake takođe mogu pomoći u rekonstrukciji aktivnosti u jednostavnim laboratorijskim okruženjima.

Direktive za formatiranje komande `find` u nastavku prikazuju ta polja.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Tretirajte redosled kao smernicu, a ne kao dokaz. Operacije kopiranja, raspakivanje arhiva, tip filesystem-a, vraćanje podataka i istovremeni upisi mogu promeniti obrasce alokacije.

## Defensive Notes

- Nepoznate image-e montirajte samo za čitanje tokom analize.<sup>[[1]](#references)</sup>
- Privilegovane skripte, service jedinice, plugins i pomoćne putanje držite izvan mount-ova u koje korisnici mogu da upisuju.
- Koristite `nosuid`, `nodev` i `noexec` tamo gde je to operativno prikladno; ove opcije onemogućavaju set-ID/capability izvršavanje, tumačenje uređaja ili direktno izvršavanje binarnih datoteka na mount-u.<sup>[[1]](#references)</sup> Nemojte ih smatrati potpunom granicom.
- Ograničite pristup ka `/proc/<pid>/fd`; dereferenciranje tih linkova kontrolišu ptrace provere pristupa i dozvole datoteka.<sup>[[6]](#references)</sup> Gde je moguće, ograničite šire metapodatke o procesima i inspekciju između korisnika.
- Nadgledajte mount tačke u koje je moguće upisivati, neočekivane hardlink-ove ka privilegovanim datotekama i osetljive datoteke koje su obrisane, ali su i dalje otvorene.

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
