# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}


Για περισσότερες πληροφορίες δείτε [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτό είναι απλά μια περίληψη:

Η Microsoft έχει δημιουργήσει πολλαπλές μορφές εγγράφων Office, με δύο κύριους τύπους να είναι οι **OLE formats** (όπως RTF, DOC, XLS, PPT) και οι **Office Open XML (OOXML) formats** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορεί να περιέχουν macros, καθιστώντας τες στόχο για phishing και malware. Τα OOXML αρχεία έχουν δομή container τύπου zip, επιτρέποντας την επιθεώρηση με unzip, αποκαλύπτοντας την ιεραρχία αρχείων και φακέλων και τα περιεχόμενα των XML αρχείων.

Για να εξερευνήσει κανείς τις δομές των OOXML αρχείων, δίνεται η εντολή για unzip ενός εγγράφου και η δομή εξόδου. Έχουν τεκμηριωθεί τεχνικές απόκρυψης δεδομένων μέσα σε αυτά τα αρχεία, υποδεικνύοντας συνεχή καινοτομία στην απόκρυψη δεδομένων σε προκλήσεις CTF.

Για ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα σύνολα εργαλείων για την εξέταση τόσο των OLE όσο και των OOXML εγγράφων. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, τα οποία συχνά χρησιμεύουν ως φορείς για παράδοση malware, συνήθως κατεβάζοντας και εκτελώντας επιπλέον κακόβουλα payloads. Η ανάλυση των VBA macros μπορεί να γίνει χωρίς Microsoft Office χρησιμοποιώντας το Libre Office, που επιτρέπει debugging με breakpoints και watch variables.

Η εγκατάσταση και χρήση των **oletools** είναι απλή, με εντολές που παρέχονται για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Η αυτόματη εκτέλεση των macros ενεργοποιείται από συναρτήσεις όπως `AutoOpen`, `AutoExec`, ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως ένα [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Το σειριοποιημένο μοντέλο βρίσκεται κάτω από storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (παρατηρήθηκε στο Revit 2025):

- Κεφαλίδα
- GZIP-compressed payload (το πραγματικό σειριοποιημένο γράφημα αντικειμένων)
- Μηδενική συμπλήρωση
- Trailer του Error-Correcting Code (ECC)

Το Revit θα αυτο-επιδιορθώσει μικρές μεταβολές στο stream χρησιμοποιώντας το trailer ECC και θα απορρίψει streams που δεν ταιριάζουν με το ECC. Επομένως, η αφελής επεξεργασία των συμπιεσμένων bytes δεν θα επιμείνει: οι αλλαγές σας είτε επαναφέρονται είτε το αρχείο απορρίπτεται. Για να εξασφαλίσετε byte-ακριβή έλεγχο του τι βλέπει ο αποσειριοποιητής πρέπει να:

- Επανασυμπιέσετε με μια συμβατή με Revit υλοποίηση gzip (ώστε τα συμπιεσμένα bytes που παράγει/αποδέχεται το Revit να ταιριάζουν με αυτά που περιμένει).
- Επανυπολογίσετε το trailer ECC πάνω στο επιπλεγμένο stream ώστε το Revit να αποδεχτεί το τροποποιημένο stream χωρίς να το αυτο-επιδιορθώσει.

Πρακτική ροή εργασίας για το patching/fuzzing των περιεχομένων RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργασία Global\Latest με τήρηση των κανόνων gzip/ECC

- Αποσύνθεση του `Global/Latest`: διατήρησε το header, κάνε gunzip στο payload, αλλοίωσε bytes, και μετά κάνε gzip ξανά χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατήρησε το zero-padding και επανυπολόγισε το ECC trailer ώστε τα νέα bytes να γίνονται αποδεκτά από το Revit.
- Αν χρειάζεσαι ντετερμινιστική byte-for-byte αναπαραγωγή, δημιούργησε έναν ελάχιστο wrapper γύρω από τις DLLs του Revit για να καλέσεις τις διαδρομές gzip/gunzip και τον υπολογισμό ECC (όπως επιδεικνύεται στην έρευνα), ή επαναχρησιμοποίησε οποιονδήποτε διαθέσιμο helper που αναπαράγει αυτές τις συμπεριφορές.

3) Επανακατασκευή του OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:

- Το CompoundFileTool γράφει storages/streams στο σύστημα αρχείων με escaping για χαρακτήρες μη έγκυρους σε ονόματα NTFS· το stream path που χρειάζεσαι είναι ακριβώς `Global/Latest` στο δέντρο εξόδου.
- Όταν παραδίδεις μαζικές επιθέσεις μέσω ecosystem plugins που ανακτούν RFAs από cloud storage, βεβαιώσου πρώτα τοπικά ότι το patched RFA περνάει τους ελέγχους ακεραιότητας του Revit (gzip/ECC σωστά) πριν επιχειρήσεις network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Ο deserializer του Revit διαβάζει έναν 16-bit δείκτη κλάσης και κατασκευάζει ένα αντικείμενο. Ορισμένοι τύποι δεν είναι πολυμορφικοί και στερούνται vtables· η κατάχρηση της διαχείρισης των destructors οδηγεί σε type confusion όπου η engine εκτελεί ένα indirect call μέσω ενός pointer που ελέγχεται από τον επιτιθέμενο.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν δείκτη heap που ελέγχεται από τον επιτιθέμενο στη μετατόπιση αντικειμένου 0. Κατά τη διάρκεια του βρόχου των destructors, το Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια αντικείμενα στο σειριοποιημένο γράφο ώστε κάθε επανάληψη του destructor loop να εκτελεί ένα gadget (“weird machine”), και διαμορφώστε ένα stack pivot προς μια συμβατική x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) για επέκταση/ανακατασκευή OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD για reverse/taint; απενεργοποιήστε το page heap με TTD για να κρατήσετε τα traces συμπαγή.
- Ένας τοπικός proxy (π.χ. Fiddler) μπορεί να προσομοιώσει supply-chain delivery ανταλλάσσοντας RFAs στην κίνηση των plugins για δοκιμές.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
