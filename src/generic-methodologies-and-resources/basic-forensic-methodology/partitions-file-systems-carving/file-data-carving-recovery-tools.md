# Alati za carving i recovery podataka

## Alati za carving i recovery

Više alata možete pronaći na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat koji se koristi u forenzici za izdvajanje fajlova iz image datoteka je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i učitajte fajl u njega kako biste pronašli „skrivene“ fajlove. Imajte na umu da je Autopsy napravljen za podršku disk image datotekama i drugim vrstama image datoteka, ali ne i običnim fajlovima.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih fajlova radi pronalaženja ugrađenog sadržaja. Može se instalirati pomoću `apt` komande, a njegov izvorni kod nalazi se na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Bezbednosna napomena** – Verzije **2.1.2b do 2.3.3** pogođene su ranjivošću **Path Traversal** (CVE-2022-4510); savet ne navodi nijednu zakrpljenu pip verziju. Izbegavajte raspakivanje nepouzdanih uzoraka pomoću pogođenih izdanja ili izolujte alat pomoću containera/neprivilegovanog UID-a.<sup>[[4]](#references)</sup>

### Foremost

Još jedan uobičajen alat za pronalaženje skrivenih datoteka je **foremost**. Konfiguracionu datoteku alata foremost možete pronaći u `/etc/foremost.conf`. Ako želite da pretražite samo određene datoteke, odkomentarišite ih. Ako ništa ne odkomentarišete, foremost će pretraživati podrazumevano konfigurisane tipove datoteka.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **fajlova ugrađenih u fajl**. U ovom slučaju, potrebno je da uklonite komentar iz konfiguracione datoteke (_/etc/scalpel/scalpel.conf_) za tipove fajlova koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Ovaj alat dolazi uz kali, ali ga možete pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može da skenira image dokaza i da **carve-uje pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** i mnoge druge objekte **paralelno, koristeći više scanners**.

Izdanje v2.1.1 dokumentuje Autotools build i podešavanje `-S jpeg_carve_mode=2` za carving svih uzastopnih JPEG-ova.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
Bundled `bulk_diff.py` poredi dva pokretanja alata bulk_extractor, dok `bulk_extractor_reader.py` čita izveštaj i feature datoteke.<sup>[[3]](#references)</sup>

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete izabrati **tipove datoteka** koje želite da PhotoRec pretraži.

![Pokrenite svaki scanner, agresivno izdvojite JPEG datoteke i generišite bodyfile - PhotoRec: Dolazi sa GUI i CLI verzijama. Možete izabrati tipove datoteka koje želite da PhotoRec pretraži](<../../../images/image (242).png>)

### ddrescue + ddrescueview (kreiranje image-a neispravnih diskova)

Kada je fizički disk nestabilan, najbolja praksa je da ga prvo **snimite u image** i da alate za carving pokrećete samo nad tim image-om. `ddrescue` (GNU projekat) je usmeren na pouzdano kopiranje neispravnih diskova uz vođenje evidencije o nečitljivim sektorima.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Opcija **`--cluster-size`** određuje koliko se sektora kopira odjednom; manje vrednosti mogu pomoći kod sporih diskova.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ako je izvorni sistem datoteka zasnovan na Linux EXT-u, možda ćete moći da oporavite nedavno obrisane datoteke **bez potpunog carving-a**; ovi alati zasnovani na journaling-u rade na demontiranom sistemu datoteka ili image-u samo za čitanje.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Napomena o kompatibilnosti** – ext4magic je napušten; stranica projekta upozorava da savremeni file systems više nisu kompatibilni s njim.<sup>[[10]](#references)</sup>

> 🛈 Ako je file system montiran nakon brisanja, blokovi podataka su možda već ponovo iskorišćeni – u tom slučaju je i dalje potrebno pravilno carving izdvajanje (Foremost/Scalpel).

### binvis

Pogledajte [code](https://code.google.com/archive/p/binvis/) i [web page tool](https://binvis.io/#/).

#### Funkcije alata BinVis

- Vizuelni i aktivni **pregledač strukture**
- Više grafičkih prikaza za različite tačke fokusa
- Fokusiranje na delove uzorka
- **Uočavanje stringova i resursa**, npr. u PE ili ELF izvršnim datotekama
- Dobijanje **obrazaca** za kriptoanalizu datoteka
- **Uočavanje** packer ili encoder algoritama
- **Identifikovanje** steganografije na osnovu obrazaca
- **Vizuelno** binary-diffing poređenje

BinVis je odlična **polazna tačka za upoznavanje s nepoznatim targetom** u black-boxing scenariju.

## Specific Data Carving Tools

### FindAES

Pretražuje AES ključeve tražeći njihove rasporede ključeva. Može da pronađe ključeve dužine 128, 192 i 256 bita, kakvi se koriste u alatima TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (trijaža izdvojenih artefakata)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust rewrite alata YARA, predstavljen 2024. godine; VirusTotal navodi da neka pravila regularnih izraza i složenih petlji mogu da se izvršavaju znatno brže.<sup>[[5]](#references)</sup> Njegov CLI se zove `yr`, a komanda `scan` podržava rekurzivna skeniranja, broj thread-ova i izlaz metapodataka.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu) da vidite slike iz terminala.  \
Možete koristiti Linux alat komandne linije **pdftotext** da pretvorite PDF u tekst i pročitate ga.



## References

- [1] [Napomene o izdanju Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README za bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README za Python alate bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal u binwalk-u (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA je mrtva, živela YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [CLI komande za YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue priručnik](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic priručnik](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projekta ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
