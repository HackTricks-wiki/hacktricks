# Εργαλεία File/Data Carving και ανάκτησης

{{#include ../../../banners/hacktricks-training.md}}

## Εργαλεία Carving και ανάκτησης

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο συνηθισμένο εργαλείο που χρησιμοποιείται στο forensics για την εξαγωγή αρχείων από images είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και ρυθμίστε το ώστε να κάνει ingest στο αρχείο, για να εντοπίσει «κρυφά» αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει disk images και άλλα είδη images, αλλά όχι απλά αρχεία.

> **Ενημέρωση 2024-2025** – Η έκδοση **4.21** (κυκλοφόρησε τον Φεβρουάριο του 2025) πρόσθεσε ένα ανακατασκευασμένο **carving module βασισμένο στο SleuthKit v4.13**, το οποίο είναι αισθητά ταχύτερο κατά την επεξεργασία images πολλών terabytes και υποστηρίζει parallel extraction σε συστήματα με πολλούς πυρήνες. Παρουσιάστηκε επίσης ένα μικρό CLI wrapper (`autopsycli ingest <case> <image>`), που επιτρέπει το scripting του carving μέσα σε περιβάλλοντα CI/CD ή σε μεγάλης κλίμακας εργαστήρια.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο για την ανάλυση binary files με σκοπό τον εντοπισμό ενσωματωμένου περιεχομένου. Μπορεί να εγκατασταθεί μέσω του `apt` και ο πηγαίος κώδικάς του βρίσκεται στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Σημείωση ασφαλείας** – Οι εκδόσεις **≤2.3.3** επηρεάζονται από ευπάθεια **Path Traversal** (CVE-2022-4510). Κάντε upgrade (ή απομονώστε με container/μη προνομιούχο UID) πριν από το carving μη έμπιστων δειγμάτων.<sup>[[2]](#references)</sup>

### Foremost

Ένα ακόμη συνηθισμένο tool για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το configuration file του foremost στο `/etc/foremost.conf`. Αν θέλετε να αναζητήσετε μόνο συγκεκριμένα αρχεία, κάντε uncomment τις αντίστοιχες γραμμές. Αν δεν κάνετε uncomment καμία γραμμή, το foremost θα αναζητήσει τους προεπιλεγμένους τύπους αρχείων που έχουν ρυθμιστεί.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

Το **Scalpel** είναι ένα ακόμη εργαλείο που μπορεί να χρησιμοποιηθεί για την εύρεση και εξαγωγή **αρχείων ενσωματωμένων σε ένα αρχείο**. Σε αυτή την περίπτωση, θα χρειαστεί να αφαιρέσετε τα σχόλια από τους τύπους αρχείων που θέλετε να εξαγάγει, μέσα από το configuration file (_/etc/scalpel/scalpel.conf_).
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Αυτό το εργαλείο περιλαμβάνεται στο kali, αλλά μπορείτε να το βρείτε εδώ: <https://github.com/simsong/bulk_extractor>

Το Bulk Extractor μπορεί να σαρώσει ένα evidence image και να κάνει carve **pcap fragments**, **network artefacts (URLs, domains, IPs, MACs, e-mails)** και πολλά άλλα αντικείμενα **παράλληλα, χρησιμοποιώντας πολλαπλούς scanners**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Χρήσιμα scripts post-processing (`bulk_diff`, `bulk_extractor_reader.py`) μπορούν να αφαιρούν διπλότυπα artefacts μεταξύ δύο images ή να μετατρέπουν τα αποτελέσματα σε JSON για εισαγωγή σε SIEM.

### PhotoRec

Μπορείτε να το βρείτε στο <https://www.cgsecurity.org/wiki/TestDisk_Download>

Διατίθεται σε εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **file-types** που θέλετε να αναζητήσει το PhotoRec.

![Εκτέλεση κάθε scanner, επιθετικό carving JPEG και δημιουργία bodyfile - PhotoRec: Διατίθεται σε εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους file-types που θέλετε να αναζητήσει το PhotoRec](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging failing drives)

Όταν ένας physical drive είναι ασταθής, η βέλτιστη πρακτική είναι να δημιουργήσετε πρώτα ένα **image** και να εκτελέσετε τα εργαλεία carving μόνο στο image. Το `ddrescue` (project GNU) εστιάζει στην αξιόπιστη αντιγραφή κατεστραμμένων disks, διατηρώντας παράλληλα ένα log των sectors που δεν είναι αναγνώσιμοι.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Η **1.28** (Δεκέμβριος 2024) εισήγαγε το **`--cluster-size`**, το οποίο μπορεί να επιταχύνει τη δημιουργία image SSD υψηλής χωρητικότητας, όπου τα παραδοσιακά μεγέθη sector δεν ευθυγραμμίζονται πλέον με τα blocks της flash.

### Extundelete / Ext4magic (undelete EXT 3/4)

Εάν το source file system είναι βασισμένο σε Linux EXT, ενδέχεται να μπορείτε να ανακτήσετε πρόσφατα διαγραμμένα αρχεία **χωρίς πλήρες carving**. Και τα δύο tools λειτουργούν απευθείας σε ένα read-only image:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Εάν το file system έγινε mount μετά τη διαγραφή, τα data blocks μπορεί να έχουν ήδη επαναχρησιμοποιηθεί – σε αυτή την περίπτωση εξακολουθεί να απαιτείται proper carving (Foremost/Scalpel).

### binvis

Δείτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [web page tool](https://binvis.io/#/).

#### Features του BinVis

- Visual και ενεργός **structure viewer**
- Πολλαπλά plots για διαφορετικά focus points
- Εστίαση σε τμήματα ενός sample
- **Προβολή strings και resources**, σε PE ή ELF executables π.χ.
- Εύρεση **patterns** για cryptanalysis σε files
- **Εντοπισμός** packer ή encoder algorithms
- **Εντοπισμός** Steganography μέσω patterns
- **Visual** binary-diffing

Το BinVis αποτελεί εξαιρετικό **start-point για εξοικείωση με έναν άγνωστο στόχο** σε σενάριο black-boxing.

## Specific Data Carving Tools

### FindAES

Αναζητά AES keys εντοπίζοντας τα key schedules τους. Μπορεί να βρει keys 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από τα TrueCrypt και BitLocker.

Κάντε download [εδώ](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

Το [YARA-X](https://github.com/VirusTotal/yara-x) είναι ένα Rust rewrite του YARA, το οποίο κυκλοφόρησε το 2024. Είναι **10-30× ταχύτερο** από το classic YARA και μπορεί να χρησιμοποιηθεί για την ταξινόμηση χιλιάδων carved objects πολύ γρήγορα:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Η επιτάχυνση καθιστά ρεαλιστική την **auto-tag** όλων των αρχείων που ανακτήθηκαν μέσω carving σε έρευνες μεγάλης κλίμακας.

## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu)για να δείτε εικόνες από το terminal.  \
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών του Linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.



## Αναφορές

- [1] [Σημειώσεις έκδοσης του Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal στο binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [Το YARA είναι νεκρό, ζήτω το YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
