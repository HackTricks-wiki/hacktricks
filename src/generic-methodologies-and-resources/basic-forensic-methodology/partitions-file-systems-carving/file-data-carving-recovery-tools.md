# Εργαλεία Carving & Recovery αρχείων/δεδομένων

{{#include ../../../banners/hacktricks-training.md}}

## Εργαλεία Carving & Recovery

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο συνηθισμένο εργαλείο που χρησιμοποιείται στο forensics για την εξαγωγή αρχείων από images είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να αναλύσει το αρχείο για να βρει "κρυφά" αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει disk images και άλλα είδη images, αλλά όχι απλά αρχεία.

### Binwalk <a href="#binwalk" id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο για την ανάλυση binary αρχείων με σκοπό την εύρεση embedded περιεχομένου. Μπορεί να εγκατασταθεί μέσω του `apt` και ο πηγαίος κώδικάς του βρίσκεται στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Σημείωση ασφαλείας** – Οι εκδόσεις **2.1.2b έως 2.3.3** επηρεάζονται από ευπάθεια **Path Traversal** (CVE-2022-4510)· το advisory δεν αναφέρει patched έκδοση pip. Αποφύγετε την εξαγωγή μη αξιόπιστων samples με επηρεαζόμενες εκδόσεις ή απομονώστε το tool με container/non-privileged UID.<sup>[[4]](#references)</sup>

### Foremost

Ένα άλλο κοινό tool για την εύρεση hidden files είναι το **foremost**. Μπορείτε να βρείτε το configuration file του foremost στο `/etc/foremost.conf`. Αν θέλετε να αναζητήσετε μόνο συγκεκριμένα files, κάντε uncomment τις αντίστοιχες γραμμές. Αν δεν κάνετε uncomment καμία γραμμή, το foremost θα αναζητήσει τους προεπιλεγμένους configured file types.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

Το **Scalpel** είναι ένα ακόμη εργαλείο που μπορεί να χρησιμοποιηθεί για την εύρεση και εξαγωγή **αρχείων ενσωματωμένων σε ένα αρχείο**. Σε αυτήν την περίπτωση, θα χρειαστεί να κάνετε uncomment τους τύπους αρχείων που θέλετε να εξαγάγει από το αρχείο διαμόρφωσης (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Αυτό το εργαλείο περιλαμβάνεται στο kali, αλλά μπορείτε να το βρείτε εδώ: <https://github.com/simsong/bulk_extractor>

Το Bulk Extractor μπορεί να σαρώσει ένα evidence image και να κάνει carving σε **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** και πολλά άλλα αντικείμενα **παράλληλα, χρησιμοποιώντας πολλαπλούς scanners**.

Η έκδοση v2.1.1 τεκμηριώνει ένα build με Autotools και τη ρύθμιση `-S jpeg_carve_mode=2` για carving όλων των συνεχόμενων JPEGs.<sup>[[2]](#references)</sup>
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
Το `bulk_diff.py` που περιλαμβάνεται συγκρίνει δύο εκτελέσεις του bulk_extractor, ενώ το `bulk_extractor_reader.py` διαβάζει το report και τα feature files.<sup>[[3]](#references)</sup>

### PhotoRec

Μπορείτε να το βρείτε στο <https://www.cgsecurity.org/wiki/TestDisk_Download>

Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **τύπους αρχείων** για τους οποίους θέλετε να πραγματοποιήσει αναζήτηση το PhotoRec.

![Εκτέλεση κάθε scanner, επιθετικό carving JPEG και δημιουργία bodyfile - PhotoRec: Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους τύπους αρχείων για τους οποίους θέλετε να πραγματοποιήσει αναζήτηση](<../../../images/image (242).png>)

### ddrescue + ddrescueview (δημιουργία image από failing drives)

Όταν ένας physical drive είναι ασταθής, είναι best practice να δημιουργήσετε πρώτα ένα **image** και να εκτελείτε τα carving tools μόνο σε αυτό. Το `ddrescue` (project GNU) επικεντρώνεται στην αξιόπιστη αντιγραφή κατεστραμμένων disks, διατηρώντας παράλληλα ένα log των unreadable sectors.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Η επιλογή **`--cluster-size`** ελέγχει πόσοι τομείς αντιγράφονται κάθε φορά· μικρότερες τιμές μπορούν να βοηθήσουν σε αργούς δίσκους.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (ανάκτηση διαγραμμένων EXT 3/4)

Εάν το source file system βασίζεται σε Linux EXT, ενδέχεται να μπορείτε να ανακτήσετε πρόσφατα διαγραμμένα αρχεία **χωρίς πλήρες carving**· αυτά τα journal-based tools λειτουργούν σε unmounted filesystem ή σε read-only image.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Σημείωση συμβατότητας** – το ext4magic έχει εγκαταλειφθεί· η σελίδα του project προειδοποιεί ότι τα τρέχοντα file systems δεν είναι πλέον συμβατά με αυτό.<sup>[[10]](#references)</sup>

> 🛈 Αν το file system έγινε mount μετά τη διαγραφή, τα data blocks μπορεί να έχουν ήδη επαναχρησιμοποιηθεί – σε αυτή την περίπτωση απαιτείται και πάλι proper carving (Foremost/Scalpel).

### binvis

Ελέγξτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [web page tool](https://binvis.io/#/).

#### Features του BinVis

- Visual και ενεργός **structure viewer**
- Πολλαπλά plots για διαφορετικά focus points
- Εστίαση σε τμήματα ενός sample
- **Εντοπισμός strings και resources**, για παράδειγμα σε PE ή ELF executables
- Εύρεση **patterns** για cryptanalysis σε files
- **Εντοπισμός** packer ή encoder algorithms
- **Αναγνώριση** Steganography μέσω patterns
- **Visual** binary-diffing

Το BinVis είναι ένα εξαιρετικό **start-point για εξοικείωση με έναν άγνωστο στόχο** σε ένα black-boxing scenario.

## Εξειδικευμένα Data Carving Tools

### FindAES

Αναζητά AES keys, αναζητώντας τα key schedules τους. Μπορεί να εντοπίσει keys των 128, 192 και 256 bits, όπως αυτά που χρησιμοποιούνται από τα TrueCrypt και BitLocker.

Κατεβάστε το [εδώ](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

Το [YARA-X](https://github.com/VirusTotal/yara-x) είναι ένα rewrite του YARA σε Rust, το οποίο παρουσιάστηκε το 2024· το VirusTotal αναφέρει ότι ορισμένα regular-expression και complex-loop rules μπορούν να εκτελούνται σημαντικά ταχύτερα.<sup>[[5]](#references)</sup> Το CLI του ονομάζεται `yr`, και η εντολή `scan` υποστηρίζει recursive scans, thread count και output μεταδεδομένων.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu)για να δείτε εικόνες από το terminal.  \
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών **pdftotext** του Linux για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.



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
{{#include ../../../banners/hacktricks-training.md}}
