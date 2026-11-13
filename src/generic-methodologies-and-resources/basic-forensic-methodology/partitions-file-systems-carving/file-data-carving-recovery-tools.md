# Εργαλεία Carving και ανάκτησης αρχείων/δεδομένων

{{#include ../../../banners/hacktricks-training.md}}

## Εργαλεία Carving και ανάκτησης

Να κάνετε πάντα carving σε **επαληθευμένο αντίγραφο**, όχι στην αρχική συσκευή. Δείτε την ενότητα [Απόκτηση εικόνας και προσάρτηση](../image-acquisition-and-mount.md) για ροές εργασιών απόκτησης μόνο για ανάγνωση και κατακερματισμού.

Περισσότερα εργαλεία στο [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Το πιο συνηθισμένο εργαλείο που χρησιμοποιείται στην ψηφιακή εγκληματολογία για την εξαγωγή αρχείων από εικόνες είναι το [**Autopsy**](https://www.autopsy.com/download/). Κατεβάστε το, εγκαταστήστε το και ζητήστε του να επεξεργαστεί το αρχείο για να εντοπίσει «κρυφά» αρχεία. Σημειώστε ότι το Autopsy έχει σχεδιαστεί για να υποστηρίζει εικόνες δίσκων και άλλα είδη εικόνων, αλλά όχι απλά αρχεία.

### Binwalk <a href="#binwalk" id="binwalk"></a>

Το **Binwalk** είναι ένα εργαλείο ανάλυσης δυαδικών αρχείων για τον εντοπισμό ενσωματωμένου περιεχομένου. Το **Binwalk v3** είναι μια επανεγγραφή σε Rust με αυτόματη εξαγωγή (`-e`), raw carving γνωστών και άγνωστων αντικειμένων (`-c`), αναδρομική σάρωση/σάρωση Matryoshka (`-M`) και ρυθμιζόμενα worker threads. Το project συνιστά το Docker build του όταν απαιτούνται όλα τα εξωτερικά εργαλεία εξαγωγής· η εντολή `cargo install binwalk` εγκαθιστά το Rust CLI, αλλά όχι αυτές τις εξωτερικές εξαρτήσεις.<sup>[[11]](#references)</sup>

**Χρήσιμες εντολές v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Η legacy συνταγή v2 `--dd='.*'` **δεν** είναι το ισοδύναμο του v3 για το `-c`· όταν ακολουθείτε παλιές εντολές από CTF/write-up, ελέγξτε πρώτα το `binwalk --version`.<sup>[[11]](#references)</sup>

⚠️  **Σημείωση ασφαλείας** – Οι εκδόσεις **2.1.2b έως 2.3.3** επηρεάζονται από ευπάθεια **Path Traversal** (CVE-2022-4510)· η ειδοποίηση ασφαλείας δεν αναφέρει διορθωμένη έκδοση pip. Αποφύγετε την εξαγωγή μη έμπιστων δειγμάτων με επηρεαζόμενες εκδόσεις ή απομονώστε το εργαλείο σε container/με μη προνομιούχο UID.<sup>[[4]](#references)</sup>

### Foremost

Ένα άλλο συνηθισμένο εργαλείο για την εύρεση κρυφών αρχείων είναι το **foremost**. Μπορείτε να βρείτε το αρχείο ρυθμίσεων του foremost στο `/etc/foremost.conf`. Αν θέλετε να αναζητήσετε μόνο συγκεκριμένα αρχεία, αφαιρέστε τα σχόλια από τις αντίστοιχες γραμμές. Αν δεν αφαιρέσετε κανένα σχόλιο, το foremost θα αναζητήσει τους προεπιλεγμένους τύπους αρχείων που έχουν ρυθμιστεί.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

Το **Scalpel** είναι ένα ακόμη εργαλείο που μπορεί να χρησιμοποιηθεί για τον εντοπισμό και την εξαγωγή **αρχείων ενσωματωμένων σε ένα αρχείο**. Σε αυτή την περίπτωση, θα χρειαστεί να αφαιρέσετε τα σχόλια από τους τύπους αρχείων που θέλετε να εξαγάγει, στο αρχείο ρυθμίσεων (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 fragmented carving

Όταν η ανάκτηση με προτεραιότητα στα metadata και τα εργαλεία contiguous carving αφήνουν τα αρχεία που αποτελούνται από τμήματα ημιτελή, το **Scalpel3** μπορεί να τα ανασυνθέσει για τις υποστηριζόμενες μορφές, χρησιμοποιώντας validators αρχείων/μπλοκ. Πρόκειται για διαφορετική βάση κώδικα από την παλαιότερη εντολή `scalpel` που αναφέρθηκε παραπάνω. Αρχικά, δημιουργήστε το απαιτούμενο blockmap με το **ίδιο μέγεθος block** που χρησιμοποιείται για το carving· χρησιμοποιήστε το μέγεθος cluster του filesystem από το `fsstat`, αν είναι γνωστό, ή καθορίστε μια τεκμηριωμένη τιμή πριν από τη σάρωση ενός image διαμερίσματος. Εκτελέστε το μόνο σε επαληθευμένο αντίγραφο και αποθηκεύστε τα αποτελέσματα σε ξεχωριστό volume.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Αντικαταστήστε το `4096` με το επιλεγμένο μέγεθος block. Το `-w` διατηρεί τόσο τους υποψήφιους που είναι **PROMISING** όσο και τους επικυρωμένους, ενώ το `-b` γράφει blockvectors για να διευκολύνει τον έλεγχο των ανακατασκευασμένων διατάξεων. Ένα αρχείο που είναι PROMISING ή έχει γνωστή επέκταση δεν αποδεικνύει ότι έχει ανακτηθεί πλήρως· επικυρώστε το περιεχόμενο πριν από τη χρήση του.<sup>[[13]](#references)[[14]](#references)</sup> Για να εντοπίσετε διαγραμμένα partitions ή κενά πριν από το carving, δείτε την ενότητα [Εύρεση δεδομένων εκτός των καταγεγραμμένων partitions](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Αυτό το εργαλείο περιλαμβάνεται στο Kali, αλλά μπορείτε να το βρείτε εδώ: <https://github.com/simsong/bulk_extractor>

Το Bulk Extractor μπορεί να σαρώσει ένα evidence image και να κάνει carving σε **pcap fragments**, **artefacts δικτύου (URLs, domains, IPs, MACs, e-mails)** και πολλά άλλα αντικείμενα **παράλληλα, χρησιμοποιώντας πολλαπλούς scanners**.

Η έκδοση v2.1.1 τεκμηριώνει μια διαδικασία build με Autotools και τη ρύθμιση `-S jpeg_carve_mode=2` για carving όλων των συνεχόμενων JPEG.<sup>[[2]](#references)</sup>

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

Το πακέτο περιλαμβάνει το `bulk_diff.py`, το οποίο συγκρίνει δύο εκτελέσεις του bulk_extractor, και το `bulk_extractor_reader.py`, το οποίο διαβάζει τα αρχεία αναφοράς και χαρακτηριστικών.<sup>[[3]](#references)</sup>

### PhotoRec

Μπορείτε να το βρείτε στη διεύθυνση <https://www.cgsecurity.org/wiki/TestDisk_Download>

Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους **τύπους αρχείων** για τους οποίους θέλετε να κάνει αναζήτηση το PhotoRec.

![Εκτελέστε όλους τους σαρωτές, κάντε εντατικό carving σε JPEG και δημιουργήστε ένα bodyfile - PhotoRec: Περιλαμβάνει εκδόσεις GUI και CLI. Μπορείτε να επιλέξετε τους τύπους αρχείων για τους οποίους θέλετε να κάνει αναζήτηση το PhotoRec](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (πρώτα τα μεταδεδομένα)

Πριν από το raw signature carving, δοκιμάστε ανάκτηση με βάση το σύστημα αρχείων, όταν τα μεταδεδομένα του τόμου εξακολουθούν να είναι αναγνώσιμα. Από προεπιλογή, το `tsk_recover` εξάγει μόνο μη εκχωρημένα αρχεία· η επιλογή `-a` επιλέγει εκχωρημένα αρχεία, ενώ η `-e` εξάγει και τα δύο. Για ένα είδωλο ολόκληρου δίσκου, δώστε στην επιλογή `-o` τον **τομέα έναρξης** του διαμερίσματος από το `mmls` (μην τον μετατρέψετε σε byte). Αν η είσοδος είναι ήδη είδωλο διαμερίσματος, παραλείψτε την επιλογή `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Αυτό το πέρασμα μπορεί να διατηρήσει ονόματα και διαδρομές που προέρχονται από το filesystem και δεν μπορούν να διατηρηθούν με carving κεφαλίδων/υποσέλιδων· στη συνέχεια, εκτελέστε Foremost, Scalpel ή PhotoRec για καταχωρίσεις των οποίων τα metadata λείπουν ή δεν είναι αξιοποιήσιμα.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (δημιουργία image από δίσκους που παρουσιάζουν βλάβη)

Όταν ένας φυσικός δίσκος είναι ασταθής, η βέλτιστη πρακτική είναι να **δημιουργήσετε πρώτα ένα image** και να εκτελέσετε εργαλεία carving μόνο στο image. Το `ddrescue` (έργο GNU) εστιάζει στην αξιόπιστη αντιγραφή προβληματικών δίσκων, διατηρώντας παράλληλα ένα αρχείο καταγραφής των μη αναγνώσιμων τομέων.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Η επιλογή **`--cluster-size`** καθορίζει πόσοι τομείς αντιγράφονται κάθε φορά· οι μικρότερες τιμές μπορεί να βοηθήσουν σε αργούς δίσκους.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (ανάκτηση διαγραμμένων αρχείων EXT 3/4)

Αν το σύστημα αρχείων προέλευσης βασίζεται σε Linux EXT, ίσως μπορέσετε να ανακτήσετε πρόσφατα διαγραμμένα αρχεία **χωρίς πλήρες carving**· αυτά τα εργαλεία που βασίζονται στο journal λειτουργούν σε μη προσαρτημένο σύστημα αρχείων ή σε εικόνα μόνο για ανάγνωση.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Σημείωση συμβατότητας** – το ext4magic έχει εγκαταλειφθεί· η σελίδα του έργου προειδοποιεί ότι τα σύγχρονα συστήματα αρχείων δεν είναι πλέον συμβατά με αυτό.<sup>[[10]](#references)</sup>

> 🛈 Αν το σύστημα αρχείων προσαρτήθηκε μετά τη διαγραφή, τα μπλοκ δεδομένων ενδέχεται να έχουν ήδη επαναχρησιμοποιηθεί – σε αυτή την περίπτωση εξακολουθεί να απαιτείται σωστό carving (Foremost/Scalpel).

### binvis

Δείτε τον [κώδικα](https://code.google.com/archive/p/binvis/) και το [εργαλείο ιστοσελίδας](https://binvis.io/#/).

#### Χαρακτηριστικά του BinVis

- Οπτικό και ενεργό **εργαλείο προβολής δομής**
- Πολλαπλά γραφήματα για διαφορετικά σημεία εστίασης
- Εστίαση σε τμήματα ενός δείγματος
- **Προβολή strings και πόρων**, π.χ. σε εκτελέσιμα PE ή ELF
- Εξαγωγή **μοτίβων** από αρχεία για κρυπτανάλυση
- **Εντοπισμός** αλγορίθμων packer ή encoder
- **Αναγνώριση** Steganography μέσω μοτίβων
- **Οπτική** σύγκριση δυαδικών αρχείων

Το BinVis είναι ένα εξαιρετικό **σημείο εκκίνησης για την εξοικείωση με έναν άγνωστο στόχο** σε σενάριο black-boxing.

## Ειδικά εργαλεία Data Carving

### FindAES

Αναζητά κλειδιά AES εντοπίζοντας τα key schedules τους. Μπορεί να βρει κλειδιά 128, 192 και 256 bit, όπως αυτά που χρησιμοποιούν τα TrueCrypt και BitLocker.

Κατεβάστε το [εδώ](https://sourceforge.net/projects/findaes/).

### YARA-X (διαλογή carved artefacts)

Το [YARA-X](https://github.com/VirusTotal/yara-x) είναι επανεγγραφή του YARA σε Rust, που παρουσιάστηκε το 2024· το VirusTotal αναφέρει ότι ορισμένοι κανόνες με regular expressions και σύνθετους βρόχους μπορούν να εκτελούνται σημαντικά ταχύτερα.<sup>[[5]](#references)</sup> Το CLI του ονομάζεται `yr`, και η εντολή `scan` υποστηρίζει αναδρομικές σαρώσεις, καθορισμό αριθμού threads και έξοδο μεταδεδομένων.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Συμπληρωματικά εργαλεία

Μπορείτε να χρησιμοποιήσετε το [**viu** ](https://github.com/atanunq/viu) για να δείτε εικόνες από το τερματικό.  \
Μπορείτε να χρησιμοποιήσετε το εργαλείο γραμμής εντολών **pdftotext** του Linux για να μετατρέψετε ένα pdf σε κείμενο και να το διαβάσετε.







## References

- [1] [Σημειώσεις έκδοσης του Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README του bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README των εργαλείων Python του bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal στο binwalk (CVE-2022-4510) - Βάση δεδομένων συμβουλών ασφαλείας του GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [Το YARA πέθανε, ζήτω το YARA-X - Ιστολόγιο του VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Εντολές CLI του YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Εγχειρίδιο του GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Εγχειρίδιο του ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Κατάσταση έργου του ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README του Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: εγχειρίδιο του tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README του Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Εγχειρίδιο του Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Ροή εργασιών δοκιμών του Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
