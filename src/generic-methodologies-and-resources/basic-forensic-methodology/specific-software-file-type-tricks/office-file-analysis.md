# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}

Για περισσότερες πληροφορίες, ανατρέξτε στο [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτή είναι απλώς μια σύνοψη:<sup>[[4]](#references)</sup>

Τα έγγραφα Microsoft Office εμφανίζονται συνήθως ως παλαιότερες μορφές, όπως RTF και DOC, XLS και PPT που βασίζονται σε OLE/CFBF, ή ως νεότερες μορφές **Office Open XML (OOXML)**, όπως DOCX, XLSX και PPTX. Τα έγγραφα Office ενδέχεται να περιέχουν ενεργό περιεχόμενο, όπως macros, γεγονός που τα καθιστά συνηθισμένους φορείς phishing και malware. Τα αρχεία OOXML είναι ZIP containers, των οποίων η ιεραρχία αρχείων και τα περιεχόμενα XML μπορούν να εξεταστούν αφού αποσυμπιεστούν.<sup>[[3]](#references)[[4]](#references)</sup>

Για την εξερεύνηση των δομών αρχείων OOXML, παρατίθενται η εντολή για την αποσυμπίεση ενός εγγράφου και η δομή εξόδου. Έχουν καταγραφεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, γεγονός που υποδεικνύει τη συνεχιζόμενη καινοτομία στην απόκρυψη δεδομένων σε CTF challenges.<sup>[[4]](#references)</sup>

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα toolsets για την εξέταση εγγράφων OLE και OOXML. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, τα οποία συχνά λειτουργούν ως vectors για τη διανομή malware, συνήθως κατεβάζοντας και εκτελώντας πρόσθετα malicious payloads. Η ανάλυση των VBA macros μπορεί να πραγματοποιηθεί χωρίς το Microsoft Office, με τη χρήση του Libre Office, το οποίο επιτρέπει debugging με breakpoints και watch variables.<sup>[[4]](#references)</sup>

Η εγκατάσταση και η χρήση των **oletools** είναι απλές, καθώς παρέχονται εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Στο Word, τα automatic macros περιλαμβάνουν τα `AutoExec` και `AutoOpen`, ενώ το `Document_Open` είναι μια open-event procedure.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Για έγγραφα Office που είναι κρυπτογραφημένα με κωδικό πρόσβασης, δείτε το [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploitation του OLE Compound File: Autodesk Revit RFA – επανυπολογισμός ECC και ελεγχόμενο gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (γνωστό και ως CFBF). Το serialized model βρίσκεται κάτω από storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (παρατηρήθηκε στο Revit 2025):

- Header
- GZIP-compressed payload (το πραγματικό serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Το Revit εκτελεί auto-repair σε μικρές τροποποιήσεις του stream χρησιμοποιώντας το ECC trailer και απορρίπτει streams που δεν συμφωνούν με το ECC. Επομένως, η αφελής επεξεργασία των compressed bytes δεν θα διατηρηθεί: οι αλλαγές σας είτε επαναφέρονται είτε το αρχείο απορρίπτεται. Για να εξασφαλίσετε byte-accurate έλεγχο πάνω σε ό,τι βλέπει ο deserializer, πρέπει να:<sup>[[1]](#references)</sup>

- Κάνετε recompress με Revit-compatible gzip implementation, ώστε τα compressed bytes που παράγει/δέχεται το Revit να ταιριάζουν με αυτά που αναμένει.
- Υπολογίσετε ξανά το ECC trailer πάνω από το padded stream, ώστε το Revit να αποδεχτεί το modified stream χωρίς να εκτελέσει auto-repair.

Πρακτικό workflow για patching/fuzzing περιεχομένου RFA:<sup>[[1]](#references)</sup>

1) Αναπτύξτε το OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργασία του `Global\Latest` με πειθαρχία gzip/ECC

- Αποσυναρμολογήστε το `Global/Latest`: διατηρήστε την κεφαλίδα, κάντε gunzip στο payload, τροποποιήστε τα bytes και, στη συνέχεια, κάντε ξανά gzip χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατηρήστε το zero-padding και επανυπολογίστε το trailer ECC, ώστε τα νέα bytes να γίνουν αποδεκτά από το Revit.
- Αν χρειάζεστε deterministic αναπαραγωγή byte προς byte, δημιουργήστε ένα minimal wrapper γύρω από τα DLLs του Revit, ώστε να καλέσετε τα paths gzip/gunzip και τον υπολογισμό ECC (όπως παρουσιάζεται στην έρευνα), ή χρησιμοποιήστε ξανά οποιοδήποτε διαθέσιμο helper που αναπαράγει αυτά τα semantics.

3) Ανακατασκευή του OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:<sup>[[1]](#references)[[2]](#references)</sup>

- Το CompoundFileTool γράφει storages/streams στο filesystem, χρησιμοποιώντας escaping για χαρακτήρες που δεν είναι έγκυροι σε ονόματα NTFS· το stream path που χρειάζεστε είναι ακριβώς `Global/Latest` στο output tree.
- Όταν παραδίδετε μαζικές επιθέσεις μέσω ecosystem plugins που λαμβάνουν RFAs από cloud storage, βεβαιωθείτε πρώτα ότι το patched RFA περνά τοπικά τους integrity checks του Revit (σωστά gzip/ECC), πριν επιχειρήσετε network injection.

Insight για το exploitation (για να καθοδηγήσει ποια bytes θα τοποθετηθούν στο gzip payload):<sup>[[1]](#references)</sup>

- Ο Revit deserializer διαβάζει ένα class index 16-bit και κατασκευάζει ένα object. Ορισμένοι τύποι είναι non-polymorphic και δεν διαθέτουν vtables· η κατάχρηση του destructor handling προκαλεί type confusion, όπου το engine εκτελεί ένα indirect call μέσω ενός attacker-controlled pointer.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν attacker-controlled heap pointer στο object offset 0. Κατά τη διάρκεια του destructor loop, ο Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια objects στο serialized graph, ώστε κάθε iteration του destructor loop να εκτελεί ένα gadget (“weird machine”), και οργανώστε ένα stack pivot σε ένα συμβατικό x64 ROP chain.

Δείτε εδώ λεπτομέρειες για Windows x64 pivot/gadget building:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

και γενικές οδηγίες ROP εδώ:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) για επέκταση/ανακατασκευή OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD για reverse/taint· απενεργοποιήστε το page heap με TTD ώστε τα traces να παραμένουν compact.
- Ένα local proxy (π.χ. Fiddler) μπορεί να προσομοιώσει supply-chain delivery, αντικαθιστώντας RFAs στην κίνηση των plugins για testing.

## References

- [1] [Δημιουργία ενός πλήρους exploit RCE από ένα crash σε parsing αρχείων Autodesk Revit RFA (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Οδηγός πεδίου Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Τεκμηρίωση olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Event Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
