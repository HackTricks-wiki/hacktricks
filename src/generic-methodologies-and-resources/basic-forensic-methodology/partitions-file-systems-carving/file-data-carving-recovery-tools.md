# Alati za izdvajanje i oporavak datoteka/podataka

{{#include ../../../banners/hacktricks-training.md}}

## Alati za izdvajanje i oporavak

Uvek izdvajajte podatke iz **proverene kopije**, a ne sa originalnog uređaja. Pogledajte [Image Acquisition & Mount](../image-acquisition-and-mount.md) za postupke akvizicije samo za čitanje i hashiranja.

Više alata na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najčešći alat koji se koristi u forenzici za izdvajanje datoteka iz slika je [**Autopsy**](https://www.autopsy.com/download/). Preuzmite ga, instalirajte i podesite da obradi datoteku kako bi pronašao „skrivene“ datoteke. Imajte na umu da je Autopsy napravljen za rad sa slikama diskova i drugim vrstama slika, ali ne i sa običnim datotekama.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** je alat za analizu binarnih datoteka i pronalaženje ugrađenog sadržaja. **Binwalk v3** je ponovo napisana verzija u Rust-u sa automatskim izdvajanjem (`-e`), sirovim izdvajanjem poznatih i nepoznatih objekata (`-c`), rekurzivnim/Matryoshka skeniranjem (`-M`) i podesivim radnim nitima. Projekat preporučuje Docker verziju kada su potrebni svi eksterni alati za izdvajanje; `cargo install binwalk` instalira Rust CLI, ali ne i te eksterne zavisnosti.<sup>[[11]](#references)</sup>

**Korisne komande za v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Legacy v2 recept `--dd='.*'` **nije** v3 ekvivalent za `-c`; kada koristite stare CTF/write-up komande, prvo proverite `binwalk --version`.<sup>[[11]](#references)</sup>

⚠️  **Bezbednosna napomena** – Verzije **2.1.2b do 2.3.3** pogođene su ranjivošću **Path Traversal** (CVE-2022-4510); u bezbednosnom upozorenju nije navedena zakrpljena pip verzija. Izbegavajte izdvajanje nepouzdanih uzoraka pomoću pogođenih izdanja ili izolujte alat pomoću containera/neprivilegovanog UID-a.<sup>[[4]](#references)</sup>

### Foremost

Još jedan uobičajeni alat za pronalaženje skrivenih fajlova je **foremost**. Konfiguracioni fajl za foremost možete pronaći na `/etc/foremost.conf`. Ako želite da pretražite samo određene fajlove, uklonite oznaku komentara ispred njih. Ako ne uklonite nijednu oznaku komentara, foremost će pretraživati podrazumevano konfigurisane tipove fajlova.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** je još jedan alat koji se može koristiti za pronalaženje i izdvajanje **datoteka ugrađenih u datoteku**. U ovom slučaju, potrebno je da uklonite komentare iz redova za tipove datoteka koje želite da izdvoji u konfiguracionoj datoteci (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 fragmentisano izdvajanje

Kada oporavak koji prvo koristi metapodatke i alati za izdvajanje uzastopnih podataka ne uspeju da oporave kompletne podeljene fajlove, **Scalpel3** može ponovo da sastavi podržane formate pomoću validatora fajlova/blokova. Reč je o drugačijoj bazi koda od prethodno pomenute zastarele komande `scalpel`. Najpre napravite potreban blockmap, koristeći **istu veličinu bloka** kao i za izdvajanje; kada je poznata, koristite veličinu klastera sistema datoteka iz `fsstat`, ili utvrdite opravdanu vrednost pre skeniranja slike particije. Pokrećite alat samo nad verifikovanom kopijom, a izlaz smestite na zaseban volumen.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Zamenite `4096` izabranom veličinom bloka. `-w` zadržava kandidate u stanju **PROMISING**, kao i validirane kandidate, a `-b` zapisuje blockvectors koji pomažu u proveri rekonstruisanih rasporeda. Datoteka u stanju PROMISING ili datoteka sa poznatom ekstenzijom nije dokaz potpunog oporavka; proverite sadržaj pre upotrebe.<sup>[[13]](#references)[[14]](#references)</sup> Da biste pronašli obrisane particije ili praznine pre izdvajanja podataka, pogledajte [Pronalaženje podataka izvan navedenih particija](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Ovaj alat je deo Kali-ja, ali možete ga pronaći ovde: <https://github.com/simsong/bulk_extractor>

Bulk Extractor može da skenira sliku dokaza i izdvoji **pcap fragmente**, **mrežne artefakte (URL-ove, domene, IP adrese, MAC adrese, e-adrese)** i mnoge druge objekte **paralelno, koristeći više skenera**.

Izdanje v2.1.1 dokumentuje izgradnju pomoću Autotools-a i postavku `-S jpeg_carve_mode=2` za izdvajanje svih uzastopnih JPEG-ova.<sup>[[2]](#references)</sup>

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

Priloženi `bulk_diff.py` upoređuje dva pokretanja alata bulk_extractor, dok `bulk_extractor_reader.py` čita izveštaje i datoteke sa funkcijama.<sup>[[3]](#references)</sup>

### PhotoRec

Možete ga pronaći na <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dolazi sa GUI i CLI verzijama. Možete da izaberete **tipove datoteka** koje želite da PhotoRec traži.

![Pokrenite svaki skener, agresivno izdvojte JPEG-ove i generišite bodyfile - PhotoRec: Dolazi sa GUI i CLI verzijama. Možete da izaberete tipove datoteka koje želite da PhotoRec traži](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (prvo metapodaci)

Pre izdvajanja na osnovu sirovih potpisa, pokušajte sa oporavkom koji uzima u obzir sistem datoteka, ako se metapodaci volumena i dalje mogu parsirati. `tsk_recover` podrazumevano izvozi samo nedodeljene datoteke; `-a` bira dodeljene datoteke, a `-e` izvozi obe vrste. Za sliku celog diska, prosledite `-o` **početni sektor** particije iz `mmls` (nemojte ga pretvarati u bajtove). Ako je ulaz već slika particije, izostavite `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Ovaj prolaz može da sačuva nazive i putanje izvedene iz sistema datoteka, što carving zaglavlja/podnožja ne može; zatim pokrenite Foremost, Scalpel ili PhotoRec za stavke čiji metapodaci nedostaju ili su neupotrebljivi.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (pravljenje image-a nestabilnih diskova)

Kada je fizički disk nestabilan, najbolje je prvo **napraviti njegov image**, a alate za carving pokretati samo nad image-om. `ddrescue` (GNU projekat) namenjen je pouzdanom kopiranju oštećenih diskova uz vođenje evidencije o nečitljivim sektorima.

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

### Extundelete / Ext4magic (vraćanje obrisanih EXT 3/4 fajlova)

Ako je izvorni fajl-sistem zasnovan na Linux EXT-u, možda ćete moći da oporavite nedavno obrisane fajlove **bez potpunog carvinga**; ovi alati zasnovani na dnevniku rade na odmontiranom fajl-sistemu ili slici samo za čitanje.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Napomena o kompatibilnosti** – ext4magic je napušten; na stranici projekta se upozorava da savremeni sistemi datoteka više nisu kompatibilni s njim.<sup>[[10]](#references)</sup>

> 🛈 Ako je sistem datoteka montiran nakon brisanja, blokovi podataka su možda već ponovo iskorišćeni – u tom slučaju je i dalje potrebno pravilno carving-ovanje (Foremost/Scalpel).

### binvis

Pogledajte [kod](https://code.google.com/archive/p/binvis/) i [alat na veb-stranici](https://binvis.io/#/).

#### Funkcije alata BinVis

- Vizuelni i aktivni **pregledač strukture**
- Više prikaza za različite tačke fokusa
- Fokusiranje na delove uzorka
- **Pregled stringova i resursa**, npr. u PE ili ELF izvršnim datotekama
- Dobijanje **obrazaca** za kriptoanalizu datoteka
- **Otkrivanje** algoritama za pakovanje ili kodiranje
- **Prepoznavanje** steganografije na osnovu obrazaca
- **Vizuelno** poređenje binarnih datoteka

BinVis je odlična **polazna tačka za upoznavanje s nepoznatom metom** u scenariju black-box testiranja.

## Alati za specifične vrste carving-a podataka

### FindAES

Traži AES ključeve pretragom njihovih rasporeda ključeva. Može da pronađe ključeve dužine 128, 192 i 256 bita, poput onih koje koriste TrueCrypt i BitLocker.

Preuzmite [ovde](https://sourceforge.net/projects/findaes/).

### YARA-X (trijaža izdvojenih artefakata)

[YARA-X](https://github.com/VirusTotal/yara-x) je Rust verzija YARA-e predstavljena 2024. godine; VirusTotal navodi da se neka pravila sa regularnim izrazima i složenim petljama mogu izvršavati znatno brže.<sup>[[5]](#references)</sup> Njegov CLI se zove `yr`, a komanda `scan` podržava rekurzivna skeniranja, podešavanje broja niti i izlazne metapodatke.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Dodatni alati

Možete da koristite [**viu** ](https://github.com/atanunq/viu)za prikazivanje slika iz terminala.  \
Možete da koristite Linux alat komandne linije **pdftotext** za pretvaranje PDF-a u tekst i njegovo čitanje.







## References

- [1] [Beleške o izdanju Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [bulk_extractor v2.1.1 README](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README za Python alate bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal u binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA je mrtav, živeo YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [YARA-X CLI komande](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [GNU ddrescue priručnik](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [ext4magic priručnik](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projekta ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Binwalk v3 README](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: priručnik za tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Scalpel3 README](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Scalpel3 priručnik](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Scalpel3 testni workflow](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
