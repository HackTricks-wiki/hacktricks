# Preuzimanje slike i montiranje

{{#include ../../banners/hacktricks-training.md}}

## Preuzimanje

> Uvek preuzimajte **samo za čitanje** i **računajte hash tokom kopiranja**. Originalni uređaj držite **blokiran za upis** i radite samo sa verifikovanim kopijama.

Zabeležite proizvođača, model, serijski broj i veličinu izvora, alat i verziju, vremenske oznake, operatera, odredište, greške i hash vrednosti za preuzimanje/verifikaciju. Sačuvajte arhivsku sliku i pregledajte zasebnu radnu kopiju.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` dodaje heširanje tokom rada, verifikaciju izlaza, beleženje grešaka i podelu izlaza u `dd` tok rada. `hof=` bira izlaz verifikovan hešom; `hash=`, `hlog=`, `log=` i `bufsz=` su zasebni operandi.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager je grafički, višedretveni Linux alat za kreiranje raw/dd, EWF i legacy AFF slika. **AFF i AFF4 su različiti formati**; Guymager ne navodi da podržava AFF4 izlaz. U dijalogu za prikupljanje podataka omogućite SHA-256 i proveru odredišta, pa ga pokrenite komandom `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Specifikacija AFF4 v1.0 definiše forenzički kontejner sa virtuelizovanim skladištenjem, proizvoljnim metapodacima, proširivom kompresijom i heširanjem i visokim protokom podataka.<sup>[[1]](#references)</sup>

Kanonska C/C++ implementacija koristi `-i` za izvor i `-o` za AFF4 volumen. Kreirajte i sačuvajte spoljašnji heš kontejnera kao osnovu za prikupljanje podataka.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Aktuelna dokumentacija za FTK Imager navodi raw/DD, E01 i AFF izlaz uz verifikaciju heša. Nemojte označavati njegov AFF izlaz kao AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### EWF tools (libewf)

Za akviziciju bez nadzora, odredište se zadaje pomoću `-t`, metapodaci slučaja pomoću `-C/-D/-E/-e`, `-d sha256` dodaje SHA-256, a `-l` beleži greške i sažetke akvizicije. Pre analize proverite kompletiran skup segmenata.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Snimanje cloud diskova

Snapshot provajdera je izvor za prikupljanje podataka u određenom trenutku, a ne automatski forenzička kopija usklađena sa aplikacijom. EBS snapshot ne obuhvata podatke koji su još uvek keširani u gostujućem sistemu; pauzirajte upise, obezbedite konzistentnost aplikacije, demontirajte volumen sa podacima ili zaustavite instancu čiji se root volumen snima, ako to plan odgovora na incident dozvoljava.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Nemojte opisivati EBS snapshots kao datoteke koje se mogu jednostavno kopirati u S3. Da biste rekonstruisali blokovsku sliku bez kreiranja volumena, navedite alocirane blokove pomoću `ListSnapshotBlocks`, preuzmite svaki blok od 512 KiB pomoću `GetSnapshotBlock`, proverite kontrolnu sumu u odgovoru i popunite nulama indekse blokova koji nedostaju u retkom snimku.<sup>[[14]](#references)</sup>

Za Azure kreirajte snimak, izdajte kratkotrajni SAS sa pristupom samo za **čitanje**, preuzmite VHD, opozovite pristup i izračunajte hash rezultata. Snimite svaki disk zasebno, osim ako mehanizam prikupljanja ne obezbeđuje koordinisanu konzistentnost.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Montiranje

### Tretirajte slike kao nepouzdan ulaz

Zlonamerni filesystem može da cilja parsere particija i filesystem-a u host kernelu. QEMU izričito upozorava da se nepouzdana guest slika ne povezuje sa host NBD-om radi montiranja, a libguestfs preporučuje da se nepouzdan guest filesystem nikada ne montira direktno pomoću loop-a ili `kpartx`-a.<sup>[[2]](#references)[[16]](#references)</sup>

Za nepoznatu sliku ili sliku koju kontroliše napadač, prednost dajte alatu `guestmount`. On parsira i montira guest unutar malog appliance-a, a zatim izlaže fajlove putem FUSE-a. Forsirajte poznati format umesto automatskog prepoznavanja i zadržite appliance u režimu samo za čitanje.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Ako pregledom nije moguće utvrditi OS, zamenite `-i` eksplicitnim uređajem gosta, kao što je `-m /dev/sda2`. Šifrovane LUKS volumene možete navesti pomoću selektora `--key`; nemojte direktno unositi ključ u istoriju shell-a.<sup>[[17]](#references)</sup>

### Izbor direktnog montiranja na hostu

Direktno montiranje na hostu koristite samo za pouzdane slike ili u privremenoj VM za analizu:

1. Montirajte **ceo disk** kada vam je potrebna njegova originalna particiona tabela.
2. Montirajte **sliku jedne particije** kada vam je potreban samo jedan volumen.
3. Podesite povezivanje samo za čitanje i eksplicitno navedite format slike. Montirajte i sistem datoteka samo za čitanje. Samo `ro` ne sprečava ponovnu reprodukciju dnevnika ext3/ext4, zato koristite `ro,noload` za neispravne ext sisteme datoteka.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` je koristan kada veličina sektora nije 512 bajtova ili su metapodaci particije oštećeni; `-b` navodi stvarnu veličinu sektora uređaja. Nastavite analizu particija i sistema datoteka ovde:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Raw slike (dd, izdvojene iz AFF4)

```bash
# Identify partitions without attaching the image
mmls -b 512 disk.img

# Attach a known raw image read-only and force its format
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 --read-only --format=raw disk.img
lsblk /dev/nbd0 -o NAME,SIZE,RO,TYPE,FSTYPE,LABEL,UUID

# Example ext4 partition: prevent journal replay
sudo mount -o ro,noload /dev/nbd0p2 /mnt/evidence
```

Odmontirajte kada završite:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

Za qcow2, VMDK ili VHD/VHDX utvrdite format na osnovu pouzdanog porekla ili ga proverite unutar privremene VM za analizu, a zatim zamenite `--format=raw` eksplicitno navedenim formatom. Nikada se ne oslanjajte na automatsko otkrivanje formata na hostu za nepouzdani ulaz.<sup>[[2]](#references)</sup>

### EWF (E01/EWFX)

```bash
# Verify, then expose the embedded raw media stream
mkdir -p /mnt/ewf /mnt/evidence
ewfverify evidence.E01
ewfmount evidence.E01 /mnt/ewf

# ewf1 is raw media data; attach it explicitly as raw and read-only
sudo qemu-nbd --connect=/dev/nbd1 --read-only --format=raw /mnt/ewf/ewf1
# Example XFS partition
sudo mount -o ro,norecovery /dev/nbd1p1 /mnt/evidence
```

Za mountove bez ponovne reprodukcije specifične za filesystem, ext3/ext4 koriste `noload`, dok XFS koristi `norecovery` i zahteva režim samo za čitanje.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` može da izloži virtuelni raw prikaz, ali taj prikaz i dalje sadrži originalnu particionu tabelu. Prosledite ga istom `mmls`, izolovanom `guestmount` ili read-only NBD postupku, umesto da datoteku celog diska montirate kao filesystem.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### BitLocker volumeni

Koristite režim samo za čitanje na oba sloja. Opcija `-u` bez vrednosti traži lozinku, čime se izbegava njeno navođenje u argumentima procesa ili istoriji shell-a.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

Za LUKS ili LVM, dajte prednost komandi `guestmount -i --ro`; njen appliance može da pregleda uobičajene rasporede šifrovanih particija i logičkih volumena bez aktiviranja tuđe grupe volumena na hostu.<sup>[[17]](#references)</sup>

### kpartx pomoćni alati

`kpartx` kreira host device-mapper čvorove i zato nije prikladan za nepouzdane slike. Kada je direktno mapiranje opravdano, dodajte `-r` da bi mapiranja particija bila samo za čitanje i uklonite mapiranja prosleđivanjem iste putanje do slike koja je korišćena za njihovo kreiranje.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Uobičajene greške pri montiranju i rešenja

| Greška | Uobičajen uzrok | Bezbedan sledeći korak |
|-------|---------------|----------------|
| `cannot mount ... read-only` | Prljav journaling fajl-sistem | koristite opciju bez ponovnog puštanja dnevnika specifičnu za fajl-sistem, kao što je ext4 `ro,noload` |
| `bad superblock ...` | Pogrešna particija/offset sektora ili oštećen fajl-sistem | proverite veličinu sektora i offset pomoću `mmls`; pokrenite `fsck -n` samo nad proverenom kopijom |
| `unknown filesystem type 'LVM2_member'` | Izabrana particija je fizički volumen LVM-a | prepustite libguestfs-u da ga pregleda ili izolujte ručno aktiviranje LVM-a u privremenoj VM mašini |

### Čišćenje

Demontirajte fajl-sisteme pre nego što isključite uređaje koji ih podržavaju. Uklonite i FUSE sloj za EWF/xmount, kao i sva crypt ili device-mapper mapiranja koja su kreirana:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Specifikacija standarda AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Dokumentacija za QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Linux man-stranica za mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [Datotečni sistem SGI XFS (dokumentacija Linux kernela)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [SWGDE najbolje prakse za prikupljanje digitalnih dokaza](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [SWGDE najbolje prakse za forenzičko prikupljanje podataka sa računara](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Man-stranica za dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Početna stranica Guymager-a i dokumentacija za konfiguraciju](https://guymager.sourceforge.io/)
- [9] [Dokumentacija za c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formati i provera u Exterro FTK Imager-u](https://www.exterro.com/digital-forensics-software)
- [11] [Priručnik za libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Priručnik za libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Kreiranje Amazon EBS snimaka](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Čitanje Amazon EBS snimaka pomoću EBS direct API-ja](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Referenca za Azure CLI snapshot](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Bezbednost libguestfs-a](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
