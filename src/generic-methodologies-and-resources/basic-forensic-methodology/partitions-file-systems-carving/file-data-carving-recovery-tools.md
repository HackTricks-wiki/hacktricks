# Alati za carving i oporavak datoteka/podataka

{{#include ../../../banners/hacktricks-training.md}}

## Alati za carving i oporavak

Uvek radite carving nad **verifikovanom kopijom**, a ne nad originalnim uređajem. Pogledajte [Image Acquisition & Mount](../image-acquisition-and-mount.md) za postupke akvizicije samo za čitanje i heširanja.

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat koji se koristi u forenzici za izdvajanje datoteka iz image-a jeste [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i zadajte mu da obradi datoteku kako bi pronašao „skrivene“ datoteke. Imajte na umu da je Autopsy napravljen za podršku disk image-ima i drugim vrstama image-a, ali ne i jednostavnim datotekama.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih datoteka radi pronalaženja ugrađenog sadržaja. **Binwalk v3** je rewrite u Rust-u sa automatskim izdvajanjem (`-e`), raw carving-om poznatih i nepoznatih objekata (`-c`), rekurzivnim/Matryoshka skeniranjem (`-M`) i podesivim brojem worker thread-ova. Projekat preporučuje svoju Docker build verziju kada su potrebni svi eksterni extractors; `cargo install binwalk` instalira Rust CLI, ali ne i te eksterne zavisnosti.<sup>[[11]](#references)</sup>

**Korisne v3 komande**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Legacy v2 recept `--dd='.*'` **nije** v3 ekvivalent za `-c`; prvo proverite `binwalk --version` kada pratite stare CTF/ write-up komande.<sup>[[11]](#references)</sup>

⚠️  **Bezbednosna napomena** – Verzije **2.1.2b do 2.3.3** pogođene su ranjivošću **Path Traversal** (CVE-2022-4510); savetovanje ne navodi nijednu zakrpljenu pip verziju. Izbegavajte ekstrakciju nepouzdanih uzoraka pomoću pogođenih izdanja ili izolujte alat pomoću kontejnera/neprivilegovanog UID-a.<sup>[[4]](#references)</sup>

### Foremost

Još jedan uobičajen alat za pronalaženje skrivenih datoteka je **foremost**. Konfiguracionu datoteku alata foremost možete pronaći u `/etc/foremost.conf`. Ako želite da pretražujete samo određene datoteke, odkomentarišite ih. Ako ništa ne odkomentarišete, foremost će pretraživati podrazumevano konfigurisane tipove datoteka.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **fajlova ugrađenih u fajl**. U ovom slučaju, potrebno je da u konfiguracionom fajlu (_/etc/scalpel/scalpel.conf_) uklonite oznaku komentara ispred tipova fajlova koje želite da izdvojite.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Ovaj alat dolazi u okviru sistema kali, ali ga možete pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može da skenira image dokaza i da **carve-uje pcap fragmente**, **mrežne artefakte (URL-ove, domene, IP adrese, MAC adrese, e-mail adrese)** i mnoge druge objekte **paralelno koristeći više skenera**.

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
Priloženi `bulk_diff.py` upoređuje dva pokretanja alata bulk_extractor, dok `bulk_extractor_reader.py` čita report i feature fajlove.<sup>[[3]](#references)</sup>

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete izabrati **tipove datoteka** koje želite da PhotoRec traži.

![Pokrenite svaki scanner, agresivno izvršite carving JPEG-ova i generišite bodyfile - PhotoRec: Dolazi sa GUI i CLI verzijama. Možete izabrati tipove datoteka koje želite da PhotoRec traži](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Pre raw signature carving-a, pokušajte recovery uz poznavanje filesystem-a kada se metadata volumena još uvek može parsirati. `tsk_recover` podrazumevano eksportuje samo unallocated fajlove; `-a` bira allocated fajlove, a `-e` eksportuje oba tipa. Za image celog diska, prosledite **start sector** particije iz `mmls` opciji `-o` (nemojte ga konvertovati u bajtove). Ako je ulaz već image particije, izostavite `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Ovaj prolaz može očuvati nazive i putanje izvedene iz filesystema koje carving zaglavlja/podnožja ne može; nakon toga pokrenite Foremost, Scalpel ili PhotoRec za stavke čiji metapodaci nedostaju ili su neupotrebljivi.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (imaging neispravnih diskova)

Kada je fizički disk nestabilan, najbolje je najpre napraviti njegovu **image kopiju** i pokretati carving alate samo nad tom kopijom. `ddrescue` (GNU project) je usmeren na pouzdano kopiranje oštećenih diskova uz vođenje loga nečitljivih sektora.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Opcija **`--cluster-size`** kontroliše koliko se sektora kopira odjednom; manje vrednosti mogu pomoći kod sporih diskova.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Ako je izvorni filesystem zasnovan na Linux EXT-u, možda ćete moći da oporavite nedavno obrisane fajlove **bez potpunog carving-a**; ovi alati zasnovani na journalu rade na demontiranom filesystemu ili image-u samo za čitanje.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Napomena o kompatibilnosti** – ext4magic je napušten; stranica projekta upozorava da savremeni filesystems više nisu kompatibilni s njim.<sup>[[10]](#references)</sup>

> 🛈 Ako je file system montiran nakon brisanja, blokovi podataka su možda već ponovo iskorišćeni – u tom slučaju je i dalje neophodan pravilan carving (Foremost/Scalpel).

### binvis

Pogledajte [code](https://code.google.com/archive/p/binvis/) i [web page tool](https://binvis.io/#/).

#### Funkcije alata BinVis

- Vizuelni i aktivni **structure viewer**
- Više plotova za različite focus points
- Fokusiranje na delove uzorka
- **Pregled stringova i resursa**, npr. u PE ili ELF izvršnim datotekama
- Dobijanje **patterns** za cryptanalysis nad datotekama
- **Otkrivanje** packer ili encoder algorithms
- **Identifikovanje** Steganography pomoću obrazaca
- **Vizuelni** binary-diffing

BinVis je odlična **početna tačka za upoznavanje s nepoznatim targetom** u black-boxing scenariju.

## Specifični Data Carving alati

### FindAES

Traži AES ključeve pretraživanjem njihovih key schedules. Može da pronađe ključeve dužine 128, 192 i 256 bita, poput onih koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust rewrite alata YARA, predstavljen 2024. godine; VirusTotal navodi da neke regular-expression i complex-loop rules mogu da se izvršavaju znatno brže.<sup>[[5]](#references)</sup> Njegov CLI se zove `yr`, a komanda `scan` podržava recursive scans, broj threadova i ispis metapodataka.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Dodatni alati

Možete koristiti [**viu** ](https://github.com/atanunq/viu)za prikaz slika iz terminala.  \
Možete koristiti alat komandne linije za Linux **pdftotext** za pretvaranje PDF-a u tekst i njegovo čitanje.





## References

- [1] [Beleške o izdanju Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README Python alata za bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal u alatu binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA je mrtva, živela YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komande](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue priručnik](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic priručnik](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projekta ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: tsk_recover priručnik](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
