# Alati za carving i oporavak datoteka/podataka

{{#include ../../../banners/hacktricks-training.md}}

## Alati za carving i oporavak

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat koji se koristi u forenzici za ekstrakciju datoteka iz image-ova je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i omogućite mu da obradi fajl kako bi pronašao „skrivene“ datoteke. Imajte na umu da je Autopsy napravljen za podršku diskovnim image-ovima i drugim vrstama image-ova, ali ne i običnim fajlovima.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih fajlova radi pronalaženja ugrađenog sadržaja. Može se instalirati putem `apt`-a, a njegov source code se nalazi na [GitHub-u](https://github.com/ReFirmLabs/binwalk).

**Korisne komande**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Bezbednosna napomena** – Verzije **2.1.2b do 2.3.3** pogođene su ranjivošću **Path Traversal** (CVE-2022-4510); savet ne navodi nijednu zakrpljenu pip verziju. Izbegavajte izdvajanje nepouzdanih uzoraka pomoću pogođenih izdanja ili izolujte alat pomoću kontejnera/neprivilegovanog UID-a.<sup>[[4]](#references)</sup>

### Foremost

Još jedan uobičajen alat za pronalaženje skrivenih datoteka je **foremost**. Konfiguracionu datoteku alata foremost možete pronaći u `/etc/foremost.conf`. Ako želite da pretražujete samo određene datoteke, odkomentarišite ih. Ako ništa ne odkomentarišete, foremost će pretraživati podrazumevano konfigurisane tipove datoteka.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da u konfiguracionoj datoteci (_/etc/scalpel/scalpel.conf_) uklonite komentar iz tipova datoteka koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Ovaj alat dolazi uz kali, ali ga možete pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može da skenira image dokaza i da izdvoji **pcap fragmente**, **mrežne artefakte (URL-ove, domene, IP adrese, MAC adrese, e-mail adrese)** i mnoge druge objekte **paralelno, koristeći više skenera**.

Izdanje v2.1.1 dokumentuje Autotools build i podešavanje `-S jpeg_carve_mode=2` za izdvajanje svih uzastopnih JPEG-ova.<sup>[[2]](#references)</sup>
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
Priloženi `bulk_diff.py` upoređuje dva pokretanja alata bulk_extractor, dok `bulk_extractor_reader.py` čita izveštaj i feature datoteke.<sup>[[3]](#references)</sup>

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete izabrati **file-types** koje želite da PhotoRec pretraži.

![Pokretanje svih scanner-a, agresivno carving JPEG-ova i generisanje bodyfile-a - PhotoRec: Dolazi sa GUI i CLI verzijama. Možete izabrati file-types koje želite da PhotoRec pretraži](<../../../images/image (242).png>)

### ddrescue + ddrescueview (kreiranje image-a sa nestabilnih diskova)

Kada je fizički disk nestabilan, najbolja praksa je da se najpre napravi njegov **image**, a da se carving alati pokreću samo nad image-om. `ddrescue` (GNU projekat) je usmeren na pouzdano kopiranje neispravnih diskova uz čuvanje loga nečitljivih sektora.
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

Ako je izvorni sistem datoteka zasnovan na Linux EXT-u, možda ćete moći da oporavite nedavno obrisane datoteke **bez potpunog carving-a**; ovi alati zasnovani na dnevniku rade na demontiranom sistemu datoteka ili image-u samo za čitanje.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Napomena o kompatibilnosti** – ext4magic je napušten; stranica projekta upozorava da trenutni fajl sistemi više nisu kompatibilni sa njim.<sup>[[10]](#references)</sup>

> 🛈 Ako je fajl sistem montiran nakon brisanja, blokovi podataka su možda već ponovo iskorišćeni – u tom slučaju je i dalje potrebno pravilno carving izdvajanje (Foremost/Scalpel).

### binvis

Pogledajte [kod](https://code.google.com/archive/p/binvis/) i [web alat](https://binvis.io/#/).

#### Funkcije alata BinVis

- Vizuelni i aktivni **pregledač strukture**
- Višestruki grafikoni za različite fokusne tačke
- Fokusiranje na delove uzorka
- **Uočavanje stringova i resursa**, npr. u PE ili ELF izvršnim fajlovima
- Dobijanje **obrazaca** za kriptoanalizu fajlova
- **Prepoznavanje** algoritama za pakovanje ili kodiranje
- **Identifikovanje** steganografije na osnovu obrazaca
- **Vizuelno** binarno diff-ovanje

BinVis je odlična **početna tačka za upoznavanje sa nepoznatom metom** u black-boxing scenariju.

## Specifični alati za Data Carving

### FindAES

Pretražuje AES ključeve traženjem njihovih rasporeda ključeva. Može da pronađe ključeve dužine 128, 192 i 256 bitova, kakvi se koriste u alatima TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (trijaža izdvojenih artefakata)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust rewrite alata YARA, predstavljen 2024. godine; VirusTotal navodi da se neka pravila sa regularnim izrazima i složenim petljama mogu izvršavati značajno brže.<sup>[[5]](#references)</sup> Njegov CLI se zove `yr`, a komanda `scan` podržava rekurzivna skeniranja, broj niti i izlaz metapodataka.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu)da pregledate slike iz terminala.  \
Možete koristiti Linux alat komandne linije **pdftotext** da transformišete PDF u tekst i pročitate ga.



## References

- [1] [Napomene o izdanju Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README za bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README za Python alate bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal u binwalk-u (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA je mrtav, živela YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komande](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue priručnik](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic priručnik](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projekta ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
