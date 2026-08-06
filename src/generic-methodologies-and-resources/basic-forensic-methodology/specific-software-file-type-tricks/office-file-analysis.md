# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}


Για περισσότερες πληροφορίες, ανατρέξτε στο [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτή είναι απλώς μια σύνοψη:<sup>[[4]](#references)</sup>

Η Microsoft έχει δημιουργήσει πολλές μορφές εγγράφων Office, με δύο βασικούς τύπους: τις **OLE formats** (όπως RTF, DOC, XLS, PPT) και τις **Office Open XML (OOXML) formats** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορούν να περιλαμβάνουν macros, γεγονός που τις καθιστά στόχους για phishing και malware. Τα αρχεία OOXML είναι δομημένα ως zip containers, επιτρέποντας την επιθεώρησή τους μέσω αποσυμπίεσης, η οποία αποκαλύπτει την ιεραρχία αρχείων και φακέλων, καθώς και τα περιεχόμενα των αρχείων XML.

Για την εξερεύνηση των δομών αρχείων OOXML, παρατίθενται η εντολή αποσυμπίεσης ενός εγγράφου και η δομή εξόδου. Έχουν καταγραφεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, γεγονός που υποδεικνύει τη συνεχιζόμενη καινοτομία στην απόκρυψη δεδομένων μέσα σε CTF challenges.

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα toolsets για την εξέταση εγγράφων OLE και OOXML. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, τα οποία συχνά λειτουργούν ως vectors για την παράδοση malware και συνήθως κατεβάζουν και εκτελούν πρόσθετα malicious payloads. Η ανάλυση των VBA macros μπορεί να πραγματοποιηθεί χωρίς το Microsoft Office, με τη χρήση του Libre Office, το οποίο επιτρέπει debugging με breakpoints και watch variables.

Η εγκατάσταση και η χρήση του **oletools** είναι απλές, καθώς παρέχονται εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Η αυτόματη εκτέλεση macros ενεργοποιείται από functions όπως `AutoOpen`, `AutoExec` ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Εκμετάλλευση OLE Compound File: Autodesk Revit RFA – recomputation ECC και ελεγχόμενο gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (γνωστό και ως CFBF). Το serialized model βρίσκεται στο storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (παρατηρήθηκε στο Revit 2025):

- Header
- GZIP-compressed payload (το πραγματικό serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Το Revit κάνει αυτόματο repair σε μικρές perturbations του stream χρησιμοποιώντας το ECC trailer και απορρίπτει streams που δεν συμφωνούν με το ECC. Επομένως, η naïve επεξεργασία των compressed bytes δεν θα παραμείνει: οι αλλαγές σας είτε θα reverted είτε το αρχείο θα απορριφθεί. Για να διασφαλίσετε byte-accurate control πάνω σε αυτό που βλέπει ο deserializer, πρέπει να:

- Κάνετε recompress με Revit-compatible gzip implementation (ώστε τα compressed bytes που παράγει/δέχεται το Revit να ταιριάζουν με αυτά που αναμένει).
- Κάνετε recompute το ECC trailer πάνω στο padded stream, ώστε το Revit να αποδεχτεί το modified stream χωρίς να κάνει auto-repair.

Πρακτικό workflow για patching/fuzzing περιεχομένου RFA:<sup>[[1]](#references)</sup>

1) Κάντε expand το OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργασία του Global\Latest με gzip/ECC discipline

- Αποσυναρμολογήστε το `Global/Latest`: διατηρήστε το header, κάντε gunzip το payload, τροποποιήστε τα bytes και, στη συνέχεια, κάντε ξανά gzip χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατηρήστε το zero-padding και υπολογίστε ξανά το ECC trailer, ώστε τα νέα bytes να γίνονται αποδεκτά από το Revit.
- Αν χρειάζεστε deterministic αναπαραγωγή byte-for-byte, δημιουργήστε ένα minimal wrapper γύρω από τα DLLs του Revit για να καλέσετε τις διαδρομές gzip/gunzip και τον υπολογισμό ECC (όπως παρουσιάζεται στην έρευνα) ή χρησιμοποιήστε ξανά οποιοδήποτε διαθέσιμο helper που αναπαράγει αυτά τα semantics.

3) Ανακατασκευή του OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:<sup>[[1]](#references)</sup>

- Το CompoundFileTool γράφει storages/streams στο filesystem, χρησιμοποιώντας escaping για χαρακτήρες που δεν είναι έγκυροι σε ονόματα NTFS· το stream path που θέλετε είναι ακριβώς `Global/Latest` στο output tree.
- Κατά την παράδοση mass attacks μέσω ecosystem plugins που λαμβάνουν RFAs από cloud storage, βεβαιωθείτε πρώτα ότι το patched RFA περνά τοπικά τους integrity checks του Revit (σωστά gzip/ECC), πριν επιχειρήσετε network injection.

Exploitation insight (για καθοδήγηση σχετικά με τα bytes που πρέπει να τοποθετηθούν στο gzip payload):<sup>[[1]](#references)</sup>

- Ο Revit deserializer διαβάζει ένα 16-bit class index και δημιουργεί ένα object. Ορισμένοι τύποι είναι non-polymorphic και δεν διαθέτουν vtables· η κατάχρηση του destructor handling οδηγεί σε type confusion, όπου το engine εκτελεί ένα indirect call μέσω ενός attacker-controlled pointer.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν attacker-controlled heap pointer στο object offset 0. Κατά τη διάρκεια του destructor loop, ο Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια objects στο serialized graph, ώστε κάθε επανάληψη του destructor loop να εκτελεί από ένα gadget («weird machine»), και οργανώστε ένα stack pivot σε μια συμβατική x64 ROP chain.

Δείτε εδώ λεπτομέρειες για Windows x64 pivot/gadget building:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

και γενικές οδηγίες ROP εδώ:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) για επέκταση/ανακατασκευή OLE compound files: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD για reverse/taint· απενεργοποιήστε το page heap με TTD, ώστε τα traces να παραμένουν compact.
- Ένα local proxy (π.χ. Fiddler) μπορεί να προσομοιώσει supply-chain delivery, αντικαθιστώντας RFAs στην κίνηση των plugins για testing.

## Αναφορές

- [1] [Κατασκευή ενός πλήρους exploit RCE από ένα crash στο parsing αρχείων RFA του Autodesk Revit (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Έγγραφα OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
