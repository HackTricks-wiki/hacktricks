# Patching ρυθμίσεων ασφαλείας UEFI IFR και NVRAM

{{#include ../../banners/hacktricks-training.md}}

Ένας κωδικός πρόσβασης setup προστατεύει το user interface του firmware, αλλά δεν αυθεντικοποιεί απαραίτητα τα bytes ρυθμίσεων που είναι αποθηκευμένα στο SPI flash. Με φυσική πρόσβαση εγγραφής, ένας ελεγκτής μπορεί να αντιστοιχίσει μια κρυφή ή κλειδωμένη ρύθμιση UEFI από το **Human Interface Infrastructure (HII) Internal Forms Representation (IFR)** στην αντίστοιχη μεταβλητή NVRAM, να κάνει patch στην τιμή offline και να την επανεγγράψει. Σε ένα επηρεαζόμενο σύστημα Dell, αυτό άλλαξε την κατάσταση IOMMU πριν από την εκκίνηση, ενώ το γραφικό setup εξακολουθούσε να εμφανίζει την προστασία DMA ως ενεργοποιημένη.<sup>[[3]](#references)</sup>

> [!CAUTION]
> Η εγγραφή στο firmware μπορεί να καταστήσει οριστικά μη λειτουργικό το target. Εργαστείτε σε εξουσιοδοτημένη, επανακτήσιμη συσκευή δοκιμών· διατηρήστε το αρχικό image και λάβετε τουλάχιστον τρεις ανεξάρτητες αναγνώσεις των οποίων τα cryptographic hashes ταιριάζουν, πριν τροποποιήσετε οτιδήποτε.<sup>[[3]](#references)</sup>

## Απόκτηση του firmware image

Διαβάστε μόνο την περιοχή BIOS όταν ο Intel flash descriptor επιτρέπει πρόσβαση από το host ή χρησιμοποιήστε εξωτερικό programmer με τη σωστή τάση και in-circuit clip. Για την επαναφορά ενός μηχανήματος που δεν εκκινεί πλέον απαιτείται συνήθως εξωτερικός programmer.<sup>[[3]](#references)[[9]](#references)</sup>
```bash
flashrom -p internal -r dump.bin --ifd -i bios
sha256sum dump*.bin
```
Μην θεωρείτε ότι ένα update capsule από τον vendor είναι ισοδύναμο με τα περιεχόμενα του chip: μπορεί να παραλείπει το NVRAM, να περιέχει encapsulation ή να είναι κρυπτογραφημένο. Το [UEFITool](https://github.com/LongSoft/UEFITool) μπορεί να αναλύσει ένα raw UEFI image σε firmware volumes, files και sections.<sup>[[7]](#references)</sup>

## Αντιστοίχιση μιας ερώτησης IFR με το NVRAM

Το [IFRExtractor-RS](https://github.com/LongSoft/IFRExtractor-RS) μετατρέπει τα HII form packages σε κείμενο και εμφανίζει settings που ένα vendor GUI αποκρύπτει, μετονομάζει ή καταστέλλει. Η έξοδός του μπορεί να προσδιορίσει την ερώτηση, το variable store, το byte offset, το storage width, τις έγκυρες τιμές και την conditional visibility.<sup>[[8]](#references)</sup>

1. Ανοίξτε το dump στο UEFITool, αναζητήστε το firmware file με όνομα `Setup`, αναπτύξτε το μέχρι το PE32 image section και χρησιμοποιήστε το **Extract body**.
2. Εκτελέστε το IFRExtractor-RS στο εξαχθέν EFI/PE32 body και, στη συνέχεια, αναζητήστε στο παραγόμενο κείμενο controls όπως `DMA`, `IOMMU`, `VT-d`, `Secure Boot` ή το label που εμφανίζει ο vendor.
3. Καταγράψτε τα `VarStoreId`, `VarOffset`, `Size`, τις έγκυρες επιλογές και το question ID. Μην συμπεραίνετε τη σημασία των τιμών μόνο από τα `Flags`.
4. Εντοπίστε τη σχετική δήλωση `VarStore`/`VarStoreEfi` και αντιστοιχίστε το αριθμητικό store ID στο **name και GUID** της μεταβλητής.
5. Αναζητήστε αυτό το GUID στο UEFITool μέχρι να φτάσετε στο αντίστοιχο NVRAM object. Ανοίξτε το **Body hex view** και μεταβείτε στο `VarOffset` σε σχέση με το variable body — όχι με ολόκληρο το flash image.<sup>[[3]](#references)</sup>
```bash
./ifrextractor Section_PE32_image_Setup_body.efi
rg -i 'dma|iommu|vt-d|secure boot' *.ifr.txt
```
Για παράδειγμα, ένα Dell image περιέγραφε τη σχετική ερώτηση ως `Control Iommu Pre-boot Behavior`, με `VarStoreId: 0x1`, `VarOffset: 0x975` και πεδίο 8 bit. Το Store `0x1` αντιστοιχιζόταν στη μεταβλητή `Setup` και στο GUID `EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9`· τα differential dumps επιβεβαίωσαν ότι το `01` σήμαινε ενεργοποιημένο και το `00` απενεργοποιημένο στο συγκεκριμένο firmware.<sup>[[3]](#references)</sup>

> [!WARNING]
> Τα GUIDs, τα offsets, τα structure layouts, τα duplicate variable instances και οι value encodings μπορεί να αλλάζουν μεταξύ μοντέλων και εκδόσεων firmware. Μην επαναχρησιμοποιείτε ποτέ το παράδειγμα offset ως καθολική τιμή για Dell.

## Επικύρωση με differential dumps

Όταν το setup interface είναι διαθέσιμο σε μια αντίστοιχη μονάδα δοκιμών, δημιουργήστε ένα dump με την επιλογή ενεργοποιημένη και άλλο ένα με την επιλογή απενεργοποιημένη. Συγκρίνετε το variable body που προέκυψε από το IFR και επιβεβαιώστε ότι αλλάζει μόνο το αναμενόμενο πεδίο. Αυτό προσδιορίζει το πραγματικό encoding και διακρίνει μια ενεργή μεταβλητή από stale/default/recovery copies. Κάντε patch σε αντίγραφο του επαληθευμένου original image, ανοίξτε το ξανά στο UEFITool και επιβεβαιώστε ότι η επεξεργασία βρίσκεται εκτός των authenticated ή measured code ranges πριν από το reflashing.<sup>[[3]](#references)[[4]](#references)</sup>

Μια στοχευμένη επεξεργασία μπορεί να έχει λιγότερες παρενέργειες από την εκκαθάριση ενός firmware password, η οποία μπορεί να θέσει τη συσκευή σε factory state, να απαιτήσει την εκ νέου εισαγωγή device-specific data ή να αλλάξει τις TPM PCR measurements. Ωστόσο, μια στοχευμένη offline επεξεργασία μπορεί επίσης να δημιουργήσει μια επικίνδυνη **απόκλιση displayed-state/effective-state**: το UI και τα management tools μπορεί να εμφανίζουν την παλιά τιμή, ενώ το early firmware καταναλώνει το patched byte. Η αλλαγή που παρουσιάστηκε δεν ζήτησε BitLocker recovery και διατηρήθηκε μετά από vendor BIOS update, επειδή το update διατήρησε την τροποποιημένη κατάσταση NVRAM.<sup>[[3]](#references)</sup>

Το [Dell UEFI Patcher](https://github.com/craigsblackie/Dell_UEFI_Patcher) του συγγραφέα παρουσιάζει έναν model-specific patcher που εντοπίζει τα Intel Boot Guard Initial Boot Block ranges και αρνείται normal writes στο εσωτερικό τους. Χρησιμοποιήστε το analysis mode πριν από το `--apply`, ελέγξτε κάθε candidate match και αντιμετωπίστε τα defaults του ως παραδείγματα και όχι ως portable offsets.<sup>[[4]](#references)</sup>
```bash
python3 dell_bios_patcher.py bios_dump.bin
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```
## Αυτοματοποιήστε τη χαρτογράφηση με το NVRAMap

Το [NVRAMap](https://github.com/PN-Tester/NVRAMap) αυτοματοποιεί την εξαγωγή IFR, αντιστοιχίζει το `VarStoreId` μιας ερώτησης στο GUID/όνομα του NVRAM, εμφανίζει τις τρέχουσες τιμές των επιλογών και μπορεί να επεξεργαστεί το επιλεγμένο πεδίο. Μπορεί να λειτουργήσει από ένα πλήρες firmware dump ή από ξεχωριστά extracted EFI και NVRAM blobs.<sup>[[5]](#references)</sup>
```bash
# EFI question -> backing NVRAM value
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --dump-ifr ifr.txt

# Interactive editor after reviewing the mapping
python3 NVRAMap.py -mode 1 -firmware dump.bin -terms DMA,IOMMU --modify
```
Ο αυτοματισμός δεν εξαλείφει την ανάγκη για matching dumps, recovery hardware, ελέγχους ακεραιότητας περιοχής ή validation μετά το flash.

## Chaining ενός pre-boot IOMMU downgrade σε Windows DMA access

Εάν η patched τιμή επιτρέπει PCIe DMA πριν από το ExitBootServices, το [DMAReaper](https://github.com/PN-Tester/DMAReaper) μπορεί να περιηγηθεί από το EFI System Table μέσω των ACPI root tables, να εντοπίσει τον πίνακα `DMAR` και να τον overwrite πριν τον αναλύσουν τα Windows. Χωρίς usable δεδομένα DMAR, τα Windows ενδέχεται να αποτύχουν να αρχικοποιήσουν το IOMMU-backed Kernel DMA Protection. Το DMAReaper **δεν** απενεργοποιεί από μόνο του τα VBS/HVCI.<sup>[[1]](#references)</sup>

Στην ακολουθία που παρουσιάζεται, το target εκκινήθηκε έπειτα σε Safe Mode για την αφαίρεση του υπολειπόμενου VBS barrier και το [PCILeech](https://github.com/ufrisk/pcileech) έκανε patch στη physical memory με ένα Sticky Keys signature:<sup>[[2]](#references)[[3]](#references)</sup>
```bash
sudo ./pcileech patch -sig stickykeys_cmd_win
```
Μετά από ένα επιτυχημένο patch συμβατό με το build, η ενεργοποίηση του Sticky Keys στην οθόνη σύνδεσης των Windows εκκινούσε ένα command prompt ως `NT AUTHORITY\SYSTEM`. Οι υπογραφές και τα προσβάσιμα ranges μνήμης εξαρτώνται από τον στόχο, το build και το hardware· ένα αναφερόμενο match δεν αποτελεί ένδειξη ότι κάθε έκδοση των Windows είναι exploitable.<sup>[[2]](#references)[[3]](#references)</sup>

Μην εμπιστεύεστε το μενού του firmware ως validation. Ελέγξτε **System Information (`msinfo32.exe`) → Kernel DMA Protection**, επαληθεύστε ξεχωριστά το VBS, ελέγξτε αν το OS έλαβε έναν έγκυρο πίνακα DMAR και δοκιμάστε την πραγματική δυνατότητα πρόσβασης μέσω DMA. Τα Windows αναφέρουν Kernel DMA Protection μόνο όταν η πλατφόρμα και το firmware υποστηρίζουν την απαιτούμενη διαμόρφωση IOMMU.<sup>[[6]](#references)</sup>

## References

- [1] [DMAReaper - Απενεργοποίηση του Kernel DMA Protection μέσω overwrite του DMAR πριν από την εκκίνηση](https://github.com/PN-Tester/DMAReaper)
- [2] [PCILeech - Λογισμικό επίθεσης Direct Memory Access](https://github.com/ufrisk/pcileech)
- [3] [MDSec - Απενεργοποίηση Security Features σε κλειδωμένο BIOS](https://mdsec.co.uk/2026/03/disabling-security-features-in-a-locked-bios)
- [4] [Dell UEFI Patcher - Patching NVRAM με επίγνωση του IBB](https://github.com/craigsblackie/Dell_UEFI_Patcher)
- [5] [NVRAMap - Αντιστοίχιση ρυθμίσεων EFI σε τιμές NVRAM](https://github.com/PN-Tester/NVRAMap)
- [6] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [7] [UEFITool - Πρόγραμμα προβολής και parser εικόνων firmware UEFI](https://github.com/LongSoft/UEFITool)
- [8] [IFRExtractor-RS - Εξαγωγή UEFI IFR σε αναγνώσιμο από τον άνθρωπο κείμενο](https://github.com/LongSoft/IFRExtractor-RS)
- [9] [Εγχειρίδιο flashrom - programmers και λειτουργίες read/write](https://flashrom.org/classic_cli_manpage.html)
{{#include ../../banners/hacktricks-training.md}}
