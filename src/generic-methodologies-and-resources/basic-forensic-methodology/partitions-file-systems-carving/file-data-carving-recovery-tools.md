# Alati za carving i oporavak datoteka/podataka

{{#include ../../../banners/hacktricks-training.md}}

## Alati za carving i oporavak

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat koji se koristi u forenzici za izdvajanje datoteka iz image-a jeste [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i omogućite mu da obradi datoteku kako bi pronašao „skrivene“ datoteke. Imajte na umu da je Autopsy napravljen za podršku disk image-a i drugih vrsta image-a, ali ne i jednostavnih datoteka.

> **Ažuriranje za 2024–2025.** – Verzija **4.21** (objavljena u februaru 2025.) dodala je redizajnirani **carving modul zasnovan na SleuthKit v4.13**, koji je primetno brži pri radu sa image-ima veličine više terabajta i podržava paralelno izdvajanje na sistemima sa više jezgara. Takođe je uveden mali CLI omotač (`autopsycli ingest <case> <image>`), što omogućava automatizaciju carving-a unutar CI/CD ili laboratorijskih okruženja velikih razmera.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih datoteka radi pronalaženja ugrađenog sadržaja. Može se instalirati putem `apt`-a, a njegov izvorni kod nalazi se na [GitHub-u](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Bezbednosna napomena** – Verzije **≤2.3.3** su pogođene ranjivošću **Path Traversal** (CVE-2022-4510). Nadogradite ih (ili ih izolujte pomoću container-a/neprivilegovanog UID-a) pre carving-a nepouzdanih uzoraka.<sup>[[2]](#references)</sup>

### Foremost

Još jedan čest alat za pronalaženje skrivenih fajlova je **foremost**. Konfiguracioni fajl programa foremost možete pronaći u `/etc/foremost.conf`. Ako želite da pretražujete samo određene fajlove, odkomentarišite ih. Ako ništa ne odkomentarišete, foremost će pretraživati podrazumevano konfigurisane tipove fajlova.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da iz konfiguracione datoteke (_/etc/scalpel/scalpel.conf_) uklonite komentare za tipove datoteka koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Ovaj alat dolazi uz Kali, ali ga možete pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može da skenira image dokaza i da carve-uje **pcap fragmente**, **mrežne artefakte (URL-ove, domene, IP adrese, MAC adrese, e-mail adrese)** i mnoge druge objekte **paralelno, koristeći više scanner-a**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Korisne skripte za post-processing (`bulk_diff`, `bulk_extractor_reader.py`) mogu da uklone duplikate artefakata između dve slike ili da konvertuju rezultate u JSON za SIEM unos.

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete da izaberete **tipove datoteka** koje želite da PhotoRec traži.

![Pokrenite svaki skener, agresivno izdvojite JPEG datoteke i generišite bodyfile - PhotoRec: Dolazi sa GUI i CLI verzijama. Možete da izaberete tipove datoteka koje želite da PhotoRec traži](<../../../images/image (242).png>)

### ddrescue + ddrescueview (kreiranje image-a nestabilnih diskova)

Kada je fizički disk nestabilan, najbolja praksa je da ga prvo **image-ujete** i da alate za carving pokrećete samo nad image-om. `ddrescue` (GNU projekat) je fokusiran na pouzdano kopiranje oštećenih diskova uz čuvanje dnevnika nečitljivih sektora.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Verzija **1.28** (decembar 2024) uvela je **`--cluster-size`**, što može ubrzati izradu image-a SSD diskova velikog kapaciteta, kod kojih tradicionalne veličine sektora više nisu usklađene sa flash blokovima.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ako je izvorni fajl sistem zasnovan na Linux EXT-u, možda ćete moći da oporavite nedavno obrisane fajlove **bez potpunog carving-a**. Oba alata rade direktno na read-only image-u:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Ako je sistem datoteka montiran nakon brisanja, blokovi podataka su možda već ponovo iskorišćeni – u tom slučaju je i dalje potreban odgovarajući carving (Foremost/Scalpel).

### binvis

Pogledajte [kod](https://code.google.com/archive/p/binvis/) i [web alat](https://binvis.io/#/).

#### Funkcije alata BinVis

- Vizuelni i aktivni **pregledač strukture**
- Višestruki grafikoni za različite tačke fokusa
- Fokusiranje na delove uzorka
- **Prikaz stringova i resursa**, npr. u PE ili ELF izvršnim datotekama
- Dobijanje **obrazaca** za kriptoanalizu datoteka
- **Otkrivanje** packer ili encoder algoritama
- **Identifikovanje** Steganography na osnovu obrazaca
- **Vizuelni** binary-diffing

BinVis je odlična **početna tačka za upoznavanje sa nepoznatim ciljem** u black-boxing scenariju.

## Specifični alati za Data Carving

### FindAES

Pretražuje AES ključeve traženjem njihovih key schedule vrednosti. Može da pronađe ključeve od 128, 192 i 256 bita, poput onih koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (trijaža izdvojenih artefakata)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust rewrite alata YARA, objavljen 2024. godine. **10-30× je brži** od klasičnog alata YARA i može veoma brzo da klasifikuje hiljade izdvojenih objekata:<sup>[[3]](#references)</sup>.
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Ubrzanje čini realnim **automatsko označavanje** svih izdvojenih datoteka u istragama velikih razmera.

## Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu)da biste pregledali slike iz terminala.  \
Možete koristiti alat Linux komandne linije **pdftotext** da biste PDF pretvorili u tekst i pročitali ga.



## Reference

- [1] [Napomene o izdanju Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal u binwalk-u (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA is dead, long live YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
