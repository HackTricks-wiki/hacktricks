# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο κοινό εργαλείο που χρησιμοποιείται στην ψηφιακή εγκληματολογία για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και κάντε το να επεξεργαστεί το αρχείο για να βρείτε "κρυφά" αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει δισκοεικόνες και άλλους τύπους εικόνων, αλλά όχι απλά αρχεία.

> **2024-2025 ενημέρωση** – Η έκδοση **4.21** (που κυκλοφόρησε τον Φεβρουάριο του 2025) πρόσθεσε ένα ανασχεδιασμένο **module carving βασισμένο στο SleuthKit v4.13** που είναι αισθητά ταχύτερο όταν ασχολείται με εικόνες πολλών terabyte και υποστηρίζει παράλληλη εξαγωγή σε συστήματα πολλαπλών πυρήνων.¹  Ένας μικρός CLI wrapper (`autopsycli ingest <case> <image>`) εισήχθη επίσης, καθιστώντας δυνατή την αυτοματοποίηση του carving μέσα σε CI/CD ή μεγάλης κλίμακας εργαστηριακά περιβάλλοντα.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** είναι ένα εργαλείο για την ανάλυση δυαδικών αρχείων για να βρει ενσωματωμένο περιεχόμενο. Είναι εγκαταστάσιμο μέσω του `apt` και η πηγή του είναι στο [GitHub](https://github.com/ReFirmLabs/binwalk).

**Χρήσιμες εντολές**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Σημείωση ασφαλείας** – Οι εκδόσεις **≤2.3.3** επηρεάζονται από μια ευπάθεια **Path Traversal** (CVE-2022-4510). Αναβαθμίστε (ή απομονώστε με ένα κοντέινερ/μη προνομιούχο UID) πριν από την εκτέλεση carving σε μη αξιόπιστα δείγματα.

### Foremost

Ένα άλλο κοινό εργαλείο για να βρείτε κρυφά αρχεία είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρύθμισης παραμέτρων του foremost στο `/etc/foremost.conf`. Αν θέλετε να αναζητήσετε συγκεκριμένα αρχεία, αποσχολιάστε τα. Αν δεν αποσχολιάσετε τίποτα, το foremost θα αναζητήσει τους προεπιλεγμένους τύπους αρχείων που είναι ρυθμισμένοι.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** είναι ένα άλλο εργαλείο που μπορεί να χρησιμοποιηθεί για να βρει και να εξάγει **αρχεία ενσωματωμένα σε ένα αρχείο**. Σε αυτή την περίπτωση, θα χρειαστεί να αποσχολιάσετε από το αρχείο ρυθμίσεων (_/etc/scalpel/scalpel.conf_) τους τύπους αρχείων που θέλετε να εξάγει.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Αυτό το εργαλείο έρχεται μέσα στο kali αλλά μπορείτε να το βρείτε εδώ: <https://github.com/simsong/bulk_extractor>

Το Bulk Extractor μπορεί να σαρώσει μια εικόνα αποδεικτικού στοιχείου και να ανακτήσει **pcap fragments**, **δικτυακά αντικείμενα (URLs, domains, IPs, MACs, e-mails)** και πολλά άλλα αντικείμενα **παράλληλα χρησιμοποιώντας πολλαπλούς σαρωτές**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Χρήσιμα σενάρια μετα-επεξεργασίας (`bulk_diff`, `bulk_extractor_reader.py`) μπορούν να αφαιρέσουν διπλότυπα αντικείμενα μεταξύ δύο εικόνων ή να μετατρέψουν τα αποτελέσματα σε JSON για εισαγωγή σε SIEM.

### PhotoRec

Μπορείτε να το βρείτε στο <https://www.cgsecurity.org/wiki/TestDisk_Download>

Έρχεται με εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **τύπους αρχείων** που θέλετε να αναζητήσει το PhotoRec.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (εικόνα αποτυχημένων δίσκων)

Όταν ένας φυσικός δίσκος είναι ασταθής, είναι καλύτερη πρακτική να **δημιουργήσετε πρώτα μια εικόνα** και να εκτελέσετε εργαλεία carving μόνο κατά της εικόνας.  `ddrescue` (GNU project) επικεντρώνεται στην αξιόπιστη αντιγραφή κακών δίσκων ενώ διατηρεί ένα αρχείο καταγραφής των μη αναγνώσιμων τομέων.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Version **1.28** (Δεκέμβριος 2024) εισήγαγε **`--cluster-size`** που μπορεί να επιταχύνει την απεικόνιση υψηλής χωρητικότητας SSD όπου οι παραδοσιακές διαστάσεις τομέα δεν ευθυγραμμίζονται πλέον με τα μπλοκ flash.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Εάν το σύστημα αρχείων προέλευσης είναι βασισμένο σε Linux EXT, μπορεί να είστε σε θέση να ανακτήσετε πρόσφατα διαγραμμένα αρχεία **χωρίς πλήρη carving**. Και τα δύο εργαλεία λειτουργούν απευθείας σε μια εικόνα μόνο για ανάγνωση:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Αν το σύστημα αρχείων είχε προσαρτηθεί μετά τη διαγραφή, οι μπλοκ δεδομένων μπορεί να έχουν ήδη επαναχρησιμοποιηθεί – σε αυτή την περίπτωση απαιτείται σωστό carving (Foremost/Scalpel).

### binvis

Ελέγξτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [εργαλείο ιστοσελίδας](https://binvis.io/#/).

#### Χαρακτηριστικά του BinVis

- Οπτικός και ενεργός **θεατής δομής**
- Πολλαπλά διαγράμματα για διαφορετικά σημεία εστίασης
- Εστίαση σε τμήματα ενός δείγματος
- **Βλέποντας αλυσίδες και πόρους**, σε εκτελέσιμα PE ή ELF π.χ.
- Λήψη **μοτίβων** για κρυπτοανάλυση σε αρχεία
- **Εντοπισμός** αλγορίθμων packer ή encoder
- **Αναγνώριση** Στεγανότητας μέσω μοτίβων
- **Οπτική** διαφορά δυαδικών

Το BinVis είναι ένα εξαιρετικό **σημείο εκκίνησης για να εξοικειωθείτε με έναν άγνωστο στόχο** σε ένα σενάριο black-boxing.

## Ειδικά Εργαλεία Carving Δεδομένων

### FindAES

Αναζητά κλειδιά AES ψάχνοντας για τα χρονοδιαγράμματα κλειδιών τους. Ικανό να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούνται από το TrueCrypt και το BitLocker.

Κατεβάστε [εδώ](https://sourceforge.net/projects/findaes/).

### YARA-X (ταξινόμηση carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) είναι μια επαναγραφή του YARA σε Rust που κυκλοφόρησε το 2024. Είναι **10-30× ταχύτερο** από το κλασικό YARA και μπορεί να χρησιμοποιηθεί για την ταξινόμηση χιλιάδων carved αντικειμένων πολύ γρήγορα:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Η επιτάχυνση καθιστά ρεαλιστικό το **auto-tag** όλων των carved αρχείων σε μεγάλες έρευνες.

## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε [**viu** ](https://github.com/atanunq/viu) για να δείτε εικόνες από το τερματικό.  \
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών linux **pdftotext** για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.

## Αναφορές

1. Autopsy 4.21 release notes – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
