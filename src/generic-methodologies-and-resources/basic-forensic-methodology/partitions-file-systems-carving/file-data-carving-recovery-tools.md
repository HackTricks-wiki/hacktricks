# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat korišćen u forenzici za ekstrakciju fajlova iz slika je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i omogućite mu da unese fajl kako bi pronašao "sakrivene" fajlove. Imajte na umu da je Autopsy napravljen da podržava disk slike i druge vrste slika, ali ne i obične fajlove.

> **2024-2025 ažuriranje** – Verzija **4.21** (objavljena februara 2025) dodala je obnovljeni **carving modul zasnovan na SleuthKit v4.13** koji je primetno brži kada se radi sa multi-terabajt slikama i podržava paralelnu ekstrakciju na multi-core sistemima.¹ Takođe je uveden mali CLI omotač (`autopsycli ingest <case> <image>`), što omogućava skriptovanje carving-a unutar CI/CD ili velikih laboratorijskih okruženja.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih fajlova radi pronalaženja ugrađenog sadržaja. Može se instalirati putem `apt`, a njegov izvor je na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Napomena o bezbednosti** – Verzije **≤2.3.3** su pogođene **Path Traversal** ranjivošću (CVE-2022-4510). Ažurirajte (ili izolujte sa kontejnerom/neprivilegovanom UID) pre nego što izrezujete nepouzdane uzorke.

### Foremost

Još jedan uobičajen alat za pronalaženje skrivenih fajlova je **foremost**. Možete pronaći konfiguracioni fajl foremost u `/etc/foremost.conf`. Ako želite da pretražujete neke specifične fajlove, otkomentarišite ih. Ako ne otkomentarišete ništa, foremost će pretraživati svoje podrazumevane konfiguracione tipove fajlova.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i ekstrakciju **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da odkomentarišete tipove datoteka iz konfiguracione datoteke (_/etc/scalpel/scalpel.conf_) koje želite da ekstraktujete.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Ovaj alat dolazi unutar kali, ali ga možete pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može skenirati sliku dokaza i izrezati **pcap fragmente**, **mrežne artefakte (URL-ove, domene, IP adrese, MAC adrese, e-poštu)** i mnoge druge objekte **paralelno koristeći više skenera**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Korisni skripti za post-procesiranje (`bulk_diff`, `bulk_extractor_reader.py`) mogu da de-dupliraju artefakte između dve slike ili konvertuju rezultate u JSON za SIEM unos.

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete odabrati **tipove fajlova** koje želite da PhotoRec pretražuje.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging neispravnih diskova)

Kada je fizički disk nestabilan, najbolje je prvo **napraviti sliku** i samo pokretati alate za carving protiv slike. `ddrescue` (GNU projekat) se fokusira na pouzdano kopiranje loših diskova dok vodi evidenciju o nečitljivim sektorima.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (decembar 2024) je uveo **`--cluster-size`** koji može ubrzati imidžiranje SSD-ova velike kapaciteta gde tradicionalne veličine sektora više ne odgovaraju flash blokovima.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ako je izvorni fajl sistem zasnovan na Linux EXT, možda ćete moći da povratite nedavno obrisane fajlove **bez potpunog karvinga**. Obe alatke rade direktno na imidžu samo za čitanje:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Ako je fajl sistem montiran nakon brisanja, podaci mogu već biti ponovo korišćeni – u tom slučaju je još uvek potrebna pravilna karving (Foremost/Scalpel).

### binvis

Proverite [kod](https://code.google.com/archive/p/binvis/) i [web alat](https://binvis.io/#/).

#### Karakteristike BinVis

- Vizuelni i aktivni **pregledač strukture**
- Više grafika za različite tačke fokusa
- Fokusiranje na delove uzorka
- **Prikazivanje stringova i resursa**, u PE ili ELF izvršnim datotekama npr.
- Dobijanje **šablona** za kriptoanalizu na fajlovima
- **Prepoznavanje** pakera ili enkodera
- **Identifikacija** steganografije po šablonima
- **Vizuelno** binarno poređenje

BinVis je odlična **polazna tačka za upoznavanje sa nepoznatim ciljem** u scenariju crne kutije.

## Specifični alati za karving podataka

### FindAES

Pretražuje AES ključeve tražeći njihove rasporede ključeva. Sposoban je da pronađe 128, 192 i 256-bitne ključeve, kao što su oni koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust prepis YARA objavljen 2024. godine. **10-30× brži** je od klasične YARA i može se koristiti za klasifikaciju hiljada izrezanih objekata vrlo brzo:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Ubrzanje čini realnim **auto-tag** svih izrezanih fajlova u velikim istragama.

## Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu) da vidite slike iz terminala.  \
Možete koristiti linux alat komandne linije **pdftotext** da transformišete pdf u tekst i pročitate ga.

## Reference

1. Autopsy 4.21 beleške o izdanju – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
