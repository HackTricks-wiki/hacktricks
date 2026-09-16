# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Να κάνετε πάντα carving σε ένα **verified αντίγραφο**, όχι στην αρχική συσκευή. Δείτε το [Image Acquisition & Mount](../image-acquisition-and-mount.md) για workflows απόκτησης μόνο για ανάγνωση και hashing.

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο συνηθισμένο εργαλείο που χρησιμοποιείται στο forensics για την εξαγωγή αρχείων από images είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και αφήστε το να κάνει ingest το αρχείο για να βρει "κρυφά" αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει disk images και άλλα είδη images, αλλά όχι απλά αρχεία.

### Binwalk <a href="#binwalk" id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο για την ανάλυση binary αρχείων, με σκοπό την εύρεση ενσωματωμένου περιεχομένου. Το **Binwalk v3** είναι μια επανεγγραφή σε Rust με automatic extraction (`-e`), raw carving γνωστών και άγνωστων αντικειμένων (`-c`), recursive/Matryoshka scanning (`-M`) και ρυθμιζόμενα worker threads. Το project προτείνει το Docker build του όταν απαιτούνται όλοι οι external extractors· το `cargo install binwalk` εγκαθιστά το Rust CLI, αλλά όχι αυτές τις εξωτερικές dependencies.<sup>[[11]](#references)</sup>

**Χρήσιμες εντολές v3**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Η legacy v2 συνταγή `--dd='.*'` **δεν** είναι το αντίστοιχο v3 του `-c`· ελέγξτε πρώτα το `binwalk --version` όταν ακολουθείτε παλιές εντολές από CTF/write-up.<sup>[[11]](#references)</sup>

⚠️  **Σημείωση ασφαλείας** – Οι εκδόσεις **2.1.2b έως 2.3.3** επηρεάζονται από ευπάθεια **Path Traversal** (CVE-2022-4510)· το advisory δεν αναφέρει patched έκδοση pip. Αποφύγετε την εξαγωγή μη αξιόπιστων samples με affected releases ή απομονώστε το tool με container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Ένα άλλο συνηθισμένο tool για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το configuration file του foremost στο `/etc/foremost.conf`. Αν θέλετε απλώς να αναζητήσετε συγκεκριμένα αρχεία, κάντε uncomment τις αντίστοιχες γραμμές. Αν δεν κάνετε uncomment τίποτα, το foremost θα αναζητήσει τους default configured file types.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

Το **Scalpel** είναι ένα ακόμη εργαλείο που μπορεί να χρησιμοποιηθεί για την εύρεση και εξαγωγή **αρχείων ενσωματωμένων σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα χρειαστεί να αφαιρέσετε τα σχόλια από τους τύπους αρχείων που θέλετε να εξαγάγει, μέσα από το αρχείο διαμόρφωσης (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Αυτό το tool περιλαμβάνεται στο kali, αλλά μπορείτε να το βρείτε εδώ: <https://github.com/simsong/bulk_extractor>

Το Bulk Extractor μπορεί να σαρώσει ένα evidence image και να κάνει carve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** και πολλά άλλα αντικείμενα **παράλληλα, χρησιμοποιώντας πολλαπλούς scanners**.

Η έκδοση v2.1.1 τεκμηριώνει ένα build με Autotools και τη ρύθμιση `-S jpeg_carve_mode=2` για το carving όλων των συνεχόμενων JPEGs.<sup>[[2]](#references)</sup>
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
Το bundled `bulk_diff.py` συγκρίνει δύο εκτελέσεις του bulk_extractor, ενώ το `bulk_extractor_reader.py` διαβάζει την αναφορά και τα αρχεία χαρακτηριστικών.<sup>[[3]](#references)</sup>

### PhotoRec

Μπορείτε να το βρείτε στη διεύθυνση <https://www.cgsecurity.org/wiki/TestDisk_Download>

Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **file-types** για τους οποίους θέλετε να πραγματοποιήσει αναζήτηση το PhotoRec.

![Εκτέλεση όλων των scanners, επιθετικό carving JPEG και δημιουργία bodyfile - PhotoRec: Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους file-types για τους οποίους θέλετε να πραγματοποιήσει αναζήτηση το PhotoRec](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (πρώτα τα metadata)

Πριν από το raw signature carving, δοκιμάστε recovery με επίγνωση του filesystem, όταν τα metadata του volume μπορούν ακόμη να αναλυθούν. Από προεπιλογή, το `tsk_recover` εξάγει μόνο μη εκχωρημένα αρχεία· το `-a` επιλέγει εκχωρημένα αρχεία και το `-e` εξάγει και τα δύο. Για ένα image ολόκληρου δίσκου, περάστε στο `-o` το **start sector** του partition από το `mmls` (μην το μετατρέψετε σε bytes). Αν το input είναι ήδη partition image, παραλείψτε το `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Αυτό το πέρασμα μπορεί να διατηρήσει ονόματα και διαδρομές που προέρχονται από το filesystem και τα οποία το carving βάσει header/footer δεν μπορεί να διατηρήσει· εκτελέστε στη συνέχεια Foremost, Scalpel ή PhotoRec για καταχωρίσεις των οποίων τα μεταδεδομένα λείπουν ή δεν είναι αξιοποιήσιμα.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (δημιουργία image από δίσκους που παρουσιάζουν βλάβες)

Όταν ένας φυσικός δίσκος είναι ασταθής, αποτελεί βέλτιστη πρακτική να **δημιουργήσετε πρώτα ένα image** και να εκτελέσετε τα εργαλεία carving μόνο στο image. Το `ddrescue` (GNU project) εστιάζει στην αξιόπιστη αντιγραφή προβληματικών δίσκων, διατηρώντας παράλληλα ένα log των μη αναγνώσιμων sectors.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Η επιλογή **`--cluster-size`** καθορίζει πόσοι sectors αντιγράφονται κάθε φορά· μικρότερες τιμές μπορεί να βοηθήσουν σε αργούς drives.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (EXT 3/4 undelete)

Εάν το source file system βασίζεται σε Linux EXT, ενδέχεται να μπορείτε να ανακτήσετε πρόσφατα διαγραμμένα αρχεία **χωρίς full carving**· αυτά τα journal-based tools λειτουργούν σε unmounted filesystem ή σε read-only image.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Σημείωση συμβατότητας** – το ext4magic έχει εγκαταλειφθεί· η σελίδα του project προειδοποιεί ότι τα τρέχοντα filesystems δεν είναι πλέον συμβατά με αυτό.<sup>[[10]](#references)</sup>

> 🛈 Αν το file system έγινε mount μετά τη διαγραφή, τα data blocks μπορεί να έχουν ήδη επαναχρησιμοποιηθεί – σε αυτή την περίπτωση απαιτείται και proper carving (Foremost/Scalpel).

### binvis

Δείτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [web page tool](https://binvis.io/#/).

#### Features του BinVis

- Visual και active **structure viewer**
- Πολλαπλά plots για διαφορετικά focus points
- Εστίαση σε τμήματα ενός sample
- **Προβολή strings και resources**, π.χ. σε PE ή ELF executables
- Εύρεση **patterns** για cryptanalysis σε files
- **Εντοπισμός** packer ή encoder algorithms
- **Identify** Steganography μέσω patterns
- **Visual** binary-diffing

Το BinVis είναι ένα εξαιρετικό **start-point για εξοικείωση με έναν άγνωστο στόχο** σε ένα black-boxing scenario.

## Specific Data Carving Tools

### FindAES

Αναζητά AES keys αναζητώντας τα key schedules τους. Μπορεί να εντοπίσει keys 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από τα TrueCrypt και BitLocker.

Κατεβάστε το [εδώ](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

Το [YARA-X](https://github.com/VirusTotal/yara-x) είναι ένα rewrite του YARA σε Rust, το οποίο παρουσιάστηκε το 2024· το VirusTotal αναφέρει ότι ορισμένοι κανόνες regular-expression και complex-loop μπορούν να εκτελούνται σημαντικά ταχύτερα.<sup>[[5]](#references)</sup> Το CLI του ονομάζεται `yr`, και η εντολή `scan` υποστηρίζει recursive scans, αριθμό threads και output μεταδεδομένων.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu) για να βλέπετε images από το terminal.  \
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών **pdftotext** του Linux για να μετατρέψετε ένα pdf σε text και να το διαβάσετε.





## References

- [1] [Σημειώσεις έκδοσης του Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README του bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README των Python tools του bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal στο binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [Το YARA είναι νεκρό, ζήτω το YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Εντολές CLI του YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Εγχειρίδιο του GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Εγχειρίδιο του ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Κατάσταση του project ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README του Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: εγχειρίδιο του tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
