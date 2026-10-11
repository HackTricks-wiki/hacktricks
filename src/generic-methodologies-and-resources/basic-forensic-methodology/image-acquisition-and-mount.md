# Pozyskiwanie obrazu i montowanie

{{#include ../../banners/hacktricks-training.md}}

## Pozyskiwanie

> Zawsze pozyskuj dane w trybie tylko do odczytu i obliczaj hash podczas kopiowania. Zabezpiecz oryginalne urządzenie przed zapisem i pracuj wyłącznie na zweryfikowanych kopiach.

Zapisz producenta, model, numer seryjny i pojemność źródła, narzędzie i jego wersję, znaczniki czasu, operatora, miejsce docelowe, błędy oraz hashe pozyskiwania i weryfikacji. Zachowaj obraz archiwalny i analizuj oddzielną kopię roboczą.<sup>[[5]](#references)[[6]](#references)</sup>

### DD

```bash
# Generate a raw, bit-by-bit image (no on-the-fly hashing)
dd if=/dev/sdb of=disk.img bs=4M status=progress conv=noerror,sync
# Verify integrity afterwards
sha256sum disk.img > disk.img.sha256
```

### dc3dd / dcfldd

`dc3dd` dodaje do procesu `dd` haszowanie w locie, weryfikację danych wyjściowych, rejestrowanie błędów i dzielenie danych wyjściowych na części. `hof=` wybiera dane wyjściowe weryfikowane za pomocą skrótu; `hash=`, `hlog=`, `log=` i `bufsz=` to osobne argumenty.<sup>[[7]](#references)</sup>

```bash
sudo dc3dd if=/dev/sdc hof=/forensics/pc.img hash=sha256 \
  hlog=/forensics/pc.hashes log=/forensics/pc.log bufsz=1M
```

### Guymager

Guymager to wielowątkowy, graficzny program do tworzenia obrazów dysków w systemie Linux, obsługujący formaty raw/dd, EWF i starszy format AFF. **AFF i AFF4 to różne formaty**; Guymager nie oferuje zapisu w formacie AFF4. W oknie akwizycji włącz SHA-256 oraz weryfikację miejsca docelowego, a następnie uruchom program poleceniem `sudo guymager`.<sup>[[8]](#references)</sup>

### AFF4 (Advanced Forensics Format 4)

Specyfikacja AFF4 v1.0 definiuje kontener kryminalistyczny z wirtualizowanym magazynem danych, dowolnymi metadanymi, rozszerzalną kompresją i haszowaniem oraz wysoką przepustowością.<sup>[[1]](#references)</sup>

Kanoniczna implementacja w C/C++ używa `-i` jako źródła i `-o` jako woluminu AFF4. Utwórz zewnętrzny hash kontenera i zachowaj go jako punkt odniesienia dla akwizycji.<sup>[[5]](#references)[[9]](#references)</sup>

```bash
sudo aff4imager -i /dev/nvme0n1 -o /evidence/nvme.aff4
sha256sum /evidence/nvme.aff4 > /evidence/nvme.aff4.sha256
```

### FTK Imager

Aktualna dokumentacja FTK Imager wymienia formaty raw/DD, E01 i AFF oraz weryfikację skrótów. Nie określaj formatu AFF jako AFF4.<sup>[[10]](#references)</sup>

```bash
ftkimager /dev/sdb evidence --e01 --case-number 1 --evidence-number 1 \
          --description 'Laptop seizure 2025-07-22' --examiner 'AnalystName' --compress 6
```

### Narzędzia EWF (libewf)

W przypadku pozyskiwania danych bez nadzoru cel określa `-t`, metadane sprawy — `-C/-D/-E/-e`, `-d sha256` dodaje SHA-256, a `-l` zapisuje błędy pozyskiwania danych i skróty. Przed analizą zweryfikuj kompletny zestaw segmentów.<sup>[[11]](#references)[[12]](#references)</sup>

```bash
sudo ewfacquire -u -t /forensics/evidence -C 1 -D 'Seizure 2025-07-22' \
  -E 1 -e 'AnalystName' -f encase6 -c deflate:best -d sha256 \
  -l /forensics/evidence.acquire.log /dev/sdb
ewfverify -d sha256 -l /forensics/evidence.verify.log /forensics/evidence.E01
```

### Tworzenie obrazów dysków w chmurze

Migawka dostawcy to źródło danych z określonego momentu, a nie automatycznie obraz kryminalistyczny spójny z aplikacją. Migawka EBS nie obejmuje danych wciąż przechowywanych w pamięci podręcznej systemu gościa; wstrzymaj zapis, wstrzymaj działanie aplikacji, odmontuj wolumin danych lub zatrzymaj instancję, której wolumin główny jest przechwytywany, jeśli pozwala na to plan reagowania.<sup>[[13]](#references)</sup>

```bash
aws ec2 create-snapshot --volume-id vol-01234567 \
  --description 'IR-case-1234 web-server 2025-07-22'
```

Nie opisuj migawek EBS jako plików, które można po prostu skopiować do S3. Aby odtworzyć obraz blokowy bez tworzenia woluminu, wylistuj przydzielone bloki za pomocą `ListSnapshotBlocks`, pobierz każdy blok o rozmiarze 512 KiB za pomocą `GetSnapshotBlock`, zweryfikuj zwróconą sumę kontrolną i wypełnij zerami indeksy bloków nieobecne w migawce rzadkiej.<sup>[[14]](#references)</sup>

W Azure utwórz migawkę, wygeneruj krótkotrwały token SAS **tylko do odczytu**, pobierz plik VHD, cofnij dostęp i oblicz sumę kontrolną wyniku. Twórz migawki poszczególnych dysków niezależnie, chyba że mechanizm zbierania danych zapewnia spójność skoordynowaną.<sup>[[15]](#references)</sup>

```bash
snap=$(az snapshot create -g IR-RG -n case123-os --source "$disk_id" --query id -o tsv)
sas=$(az snapshot grant-access --ids "$snap" --access-level Read \
  --duration-in-seconds 3600 --query accessSas -o tsv)
azcopy copy "$sas" case123-os.vhd
az snapshot revoke-access --ids "$snap"
sha256sum case123-os.vhd > case123-os.vhd.sha256
```

## Montowanie

### Traktuj obrazy jako niezaufane dane wejściowe

Złośliwy system plików może zaatakować analizatory partycji i systemów plików w jądrze hosta. QEMU wyraźnie ostrzega przed podłączaniem niezaufanego obrazu gościa do NBD hosta w celu montowania, a libguestfs zaleca, by nigdy nie montować bezpośrednio niezaufanego systemu plików gościa za pomocą loop lub `kpartx`.<sup>[[2]](#references)[[16]](#references)</sup>

W przypadku nieznanego obrazu lub obrazu kontrolowanego przez atakującego używaj `guestmount`. Analizuje on system plików gościa i montuje go w małym urządzeniu wirtualnym, a następnie udostępnia pliki za pośrednictwem FUSE. Wymuś znany format zamiast autodetekcji i ustaw urządzenie wirtualne w trybie tylko do odczytu.<sup>[[17]](#references)</sup>

```bash
mkdir -p /mnt/evidence
virt-filesystems --format=raw -a disk.img --all --long -h
guestmount --ro --format=raw -a disk.img -i /mnt/evidence
# Inspect/copy files, but never execute content from the image.
guestunmount /mnt/evidence
```

Jeśli inspekcja nie pozwala ustalić systemu operacyjnego, zastąp `-i` jawnie wskazanym urządzeniem gościa, np. `-m /dev/sda2`. Zaszyfrowane woluminy LUKS można podać za pomocą selektorów `--key`; unikaj umieszczania klucza bezpośrednio w historii powłoki.<sup>[[17]](#references)</sup>

### Wybór bezpośredniego montowania na hoście

Używaj bezpośredniego montowania na hoście tylko w przypadku zaufanych obrazów lub w jednorazowej maszynie wirtualnej do analizy:

1. Zamontuj **cały dysk**, jeśli potrzebujesz oryginalnej tablicy partycji.
2. Zamontuj **obraz pojedynczej partycji**, jeśli potrzebujesz tylko jednego woluminu.
3. Podłącz obraz tylko do odczytu i jawnie określ jego format. System plików również zamontuj tylko do odczytu. Samo `ro` nie zapobiega odtwarzaniu dziennika ext3/ext4, dlatego w przypadku systemów plików ext z nieczystym dziennikiem użyj `ro,noload`.<sup>[[2]](#references)[[3]](#references)</sup>

`mmls` jest przydatne, gdy rozmiar sektora nie wynosi 512 bajtów lub metadane partycji są uszkodzone; `-b` określa rzeczywisty rozmiar sektora urządzenia. Dalsza analiza partycji i systemów plików znajduje się tutaj:<sup>[[18]](#references)</sup>

{{#ref}}
partitions-file-systems-carving/README.md
{{#endref}}

### Obrazy raw (dd, wyodrębnione z AFF4)

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

Odłącz po zakończeniu:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0
```

W przypadku qcow2, VMDK lub VHD/VHDX ustal format na podstawie zaufanego źródła albo sprawdź go w jednorazowej maszynie wirtualnej do analizy, a następnie zastąp `--format=raw` jawnym określeniem formatu. Nigdy nie polegaj na automatycznym wykrywaniu formatu po stronie hosta dla niezaufanych danych wejściowych.<sup>[[2]](#references)</sup>

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

W przypadku montowań bez odtwarzania dziennika, specyficznych dla systemu plików, ext3/ext4 używają `noload`, natomiast XFS używa `norecovery` i wymaga trybu tylko do odczytu.<sup>[[3]](#references)[[4]](#references)</sup>

`xmount` może udostępnić wirtualny widok surowy, ale ten widok nadal zawiera oryginalną tablicę partycji. Przekaż go do tego samego przepływu pracy z `mmls`, izolowanym `guestmount` lub NBD tylko do odczytu, zamiast montować plik całego dysku jako system plików.<sup>[[21]](#references)</sup>

```bash
mkdir -p /tmp/raw_mount
xmount --in aewf evidence.E?? --out raw /tmp/raw_mount
mmls /tmp/raw_mount/evidence.dd
```

### Woluminy BitLocker

Używaj trybu tylko do odczytu na obu warstwach. `-u` bez wartości wyświetla monit o hasło, dzięki czemu nie trafia ono do argumentów procesu ani historii powłoki.<sup>[[19]](#references)</sup>

```bash
mkdir -p /mnt/bitlocker /mnt/evidence
sudo dislocker -r -V /dev/nbd0p3 -u -- /mnt/bitlocker
sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/evidence
```

W przypadku LUKS lub LVM preferuj `guestmount -i --ro`; jego appliance może sprawdzać typowe układy z szyfrowaniem i woluminami logicznymi bez aktywowania obcej grupy woluminów na hoście.<sup>[[17]](#references)</sup>

### Narzędzia pomocnicze kpartx

`kpartx` tworzy węzły hosta device-mapper, dlatego nie nadaje się do niezaufanych obrazów. Gdy bezpośrednie mapowanie jest uzasadnione, dodaj `-r`, aby mapowania partycji były tylko do odczytu, a mapowania usuń, przekazując tę samą ścieżkę obrazu, której użyto do ich utworzenia.<sup>[[16]](#references)[[20]](#references)</sup>

```bash
sudo kpartx -arv disk.img
sudo mount -o ro,noload /dev/mapper/loop0p2 /mnt/evidence
sudo umount /mnt/evidence
sudo kpartx -dv disk.img
```

### Typowe błędy montowania i ich rozwiązania

| Błąd | Typowa przyczyna | Bezpieczny następny krok |
|-------|---------------|----------------|
| `cannot mount ... read-only` | System plików z dziennikiem wymagający odtworzenia dziennika | użyj właściwej dla danego systemu plików opcji wyłączającej odtwarzanie dziennika, np. `ro,noload` dla ext4 |
| `bad superblock ...` | Nieprawidłowa partycja lub przesunięcie sektora albo uszkodzony system plików | potwierdź rozmiar sektora i przesunięcie za pomocą `mmls`; uruchom `fsck -n` wyłącznie na zweryfikowanej kopii |
| `unknown filesystem type 'LVM2_member'` | Wybrana partycja jest woluminem fizycznym LVM | pozwól libguestfs ją sprawdzić albo odizoluj ręczną aktywację LVM w tymczasowej maszynie wirtualnej |

### Sprzątanie

Odmontuj systemy plików przed odłączeniem urządzeń, na których się znajdują. Usuń też warstwę FUSE dla EWF/xmount oraz wszystkie utworzone mapowania crypt lub device-mapper:

```bash
sudo umount /mnt/evidence
sudo qemu-nbd --disconnect /dev/nbd0  # or /dev/nbd1
fusermount -u /mnt/ewf                # when ewfmount was used
# fusermount -u /tmp/raw_mount         # when xmount was used
```



## References

- [1] [Specyfikacja standardu AFF4 (Advanced Forensic Format v4)](https://github.com/aff4/Standard)
- [2] [Dokumentacja QEMU qemu-nbd](https://www.qemu.org/docs/master/tools/qemu-nbd.html)
- [3] [Strona podręcznika Linux mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
- [4] [System plików SGI XFS (dokumentacja jądra Linux)](https://kernel.org/doc/html/v5.9/admin-guide/xfs.html)
- [5] [Najlepsze praktyki SWGDE dotyczące zabezpieczania dowodów cyfrowych](https://www.swgde.org/documents/published-complete-listing/18-f-002-2-0/)
- [6] [Najlepsze praktyki SWGDE dotyczące pozyskiwania danych w informatyce śledczej](https://www.swgde.org/wp-content/uploads/2024/03/2023-06-15-SWGDE-Best-Practices-for-Computer-Forensic-Acquisitions-17-F-002-2.0.pdf)
- [7] [Strona podręcznika dc3dd(1)](https://manpages.opensuse.org/Leap-16.0/dc3dd/dc3dd.1.en.html)
- [8] [Strona główna Guymager i dokumentacja konfiguracji](https://guymager.sourceforge.io/)
- [9] [Dokumentacja c-aff4](https://github.com/Velocidex/c-aff4/blob/master/docs/index.rst)
- [10] [Formaty i weryfikacja w Exterro FTK Imager](https://www.exterro.com/digital-forensics-software)
- [11] [Podręcznik libewf ewfacquire(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfacquire.1)
- [12] [Podręcznik libewf ewfverify(1)](https://github.com/libyal/libewf/blob/main/manuals/ewfverify.1)
- [13] [Tworzenie migawek Amazon EBS](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-creating-snapshot.html)
- [14] [Odczytywanie migawek Amazon EBS za pomocą interfejsów API EBS direct](https://docs.aws.amazon.com/ebs/latest/userguide/readsnapshots.html)
- [15] [Dokumentacja referencyjna migawek Azure CLI](https://learn.microsoft.com/en-us/cli/azure/snapshot?view=azure-cli-latest)
- [16] [Bezpieczeństwo libguestfs](https://libguestfs.org/guestfs-security.1.html)
- [17] [guestmount(1)](https://libguestfs.org/guestmount.1.html)
- [18] [mmls(1)](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [19] [dislocker(1)](https://manpages.debian.org/testing/dislocker/dislocker.1.en.html)
- [20] [kpartx(8)](https://man.archlinux.org/man/kpartx.8.en)
- [21] [xmount(1)](https://manpages.debian.org/testing/xmount/xmount.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
