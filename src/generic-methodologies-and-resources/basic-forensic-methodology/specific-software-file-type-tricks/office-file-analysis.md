# Ανάλυση αρχείων Office

Για περισσότερες πληροφορίες, ανατρέξτε στο [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτή είναι απλώς μια σύνοψη:<sup>[[4]](#references)</sup>

Τα έγγραφα Microsoft Office εμφανίζονται συνήθως ως παλαιού τύπου formats, όπως RTF και DOC, XLS και PPT που βασίζονται σε OLE/CFBF, ή ως νεότερα formats **Office Open XML (OOXML)**, όπως DOCX, XLSX και PPTX. Τα έγγραφα Office ενδέχεται να περιέχουν ενεργό περιεχόμενο, όπως macros, γεγονός που τα καθιστά συνηθισμένα μέσα για phishing και malware. Τα αρχεία OOXML είναι ZIP containers, των οποίων η ιεραρχία αρχείων και τα περιεχόμενα XML μπορούν να εξεταστούν με αποσυμπίεση των αρχείων.<sup>[[3]](#references)[[4]](#references)</sup>

Για την εξερεύνηση των δομών αρχείων OOXML, παρουσιάζονται η εντολή αποσυμπίεσης ενός εγγράφου και η δομή εξόδου. Έχουν τεκμηριωθεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, γεγονός που υποδεικνύει τη συνεχιζόμενη καινοτομία στην απόκρυψη δεδομένων μέσα σε CTF challenges.<sup>[[4]](#references)</sup>

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα toolsets για την εξέταση εγγράφων OLE και OOXML. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, τα οποία συχνά λειτουργούν ως vectors για τη διανομή malware, συνήθως κατεβάζοντας και εκτελώντας πρόσθετα malicious payloads. Η ανάλυση των VBA macros μπορεί να πραγματοποιηθεί χωρίς Microsoft Office με τη χρήση του Libre Office, το οποίο επιτρέπει debugging με breakpoints και watch variables.<sup>[[4]](#references)</sup>

Η εγκατάσταση και η χρήση του **oletools** είναι απλές, με διαθέσιμες εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Στο Word, τα automatic macros περιλαμβάνουν τα `AutoExec` και `AutoOpen`, ενώ το `Document_Open` είναι μια open-event procedure.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Εκμετάλλευση OLE Compound File: Autodesk Revit RFA – επανυπολογισμός ECC και ελεγχόμενο gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (γνωστό και ως CFBF). Το serialized model βρίσκεται στο storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (όπως παρατηρήθηκε στο Revit 2025):

- Header
- GZIP-compressed payload (το πραγματικό serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Το Revit επιδιορθώνει αυτόματα μικρές αλλοιώσεις στο stream χρησιμοποιώντας το ECC trailer και απορρίπτει streams που δεν συμφωνούν με το ECC. Επομένως, η αφελής επεξεργασία των compressed bytes δεν θα διατηρηθεί: οι αλλαγές σας είτε αναιρούνται είτε το αρχείο απορρίπτεται. Για να διασφαλίσετε byte-accurate έλεγχο του τι θα δει ο deserializer, πρέπει να:<sup>[[1]](#references)</sup>

- Κάνετε recompress με Revit-compatible gzip implementation, ώστε τα compressed bytes που παράγει/δέχεται το Revit να συμφωνούν με αυτά που αναμένει.
- Κάνετε recompute το ECC trailer πάνω στο padded stream, ώστε το Revit να αποδεχτεί το modified stream χωρίς να το επιδιορθώσει αυτόματα.

Πρακτικό workflow για patching/fuzzing περιεχομένων RFA:<sup>[[1]](#references)</sup>

1) Κάντε expand το OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργασία του `Global\Latest` με πειθαρχία gzip/ECC

- Αποδομήστε το `Global/Latest`: διατηρήστε την κεφαλίδα, κάντε gunzip στο payload, τροποποιήστε τα bytes και, στη συνέχεια, κάντε ξανά gzip χρησιμοποιώντας Revit-compatible παραμέτρους deflate.
- Διατηρήστε το zero-padding και υπολογίστε ξανά το ECC trailer, ώστε τα νέα bytes να γίνουν αποδεκτά από το Revit.
- Αν χρειάζεστε deterministic αναπαραγωγή byte προς byte, δημιουργήστε ένα minimal wrapper γύρω από τα DLLs του Revit για να καλέσετε τις διαδρομές gzip/gunzip και τον υπολογισμό ECC (όπως παρουσιάζεται στην έρευνα) ή επαναχρησιμοποιήστε οποιοδήποτε διαθέσιμο helper που αναπαράγει αυτά τα semantics.

3) Ανακατασκευή του OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:<sup>[[1]](#references)[[2]](#references)</sup>

- Το CompoundFileTool γράφει τα storages/streams στο filesystem, χρησιμοποιώντας escaping για χαρακτήρες που δεν είναι έγκυροι σε ονόματα NTFS· το path του stream που θέλετε είναι ακριβώς `Global/Latest` στο output tree.
- Όταν πραγματοποιείτε mass attacks μέσω ecosystem plugins που λαμβάνουν RFAs από cloud storage, βεβαιωθείτε πρώτα ότι το patched RFA περνά τοπικά τους integrity checks του Revit (σωστά gzip/ECC), πριν επιχειρήσετε network injection.

Exploitation insight (για να καθοδηγήσει ποια bytes θα τοποθετηθούν στο gzip payload):<sup>[[1]](#references)</sup>

- Ο Revit deserializer διαβάζει ένα ευρετήριο κλάσης 16 bit και δημιουργεί ένα object. Ορισμένοι τύποι είναι non-polymorphic και δεν διαθέτουν vtables· η κατάχρηση του destructor handling προκαλεί type confusion, όπου η engine εκτελεί ένα indirect call μέσω attacker-controlled pointer.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν attacker-controlled heap pointer στο object offset 0. Κατά το destructor loop, ο Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια αντικείμενα στο serialized graph, ώστε κάθε επανάληψη του destructor loop να εκτελεί ένα gadget (“weird machine”), και προετοιμάστε ένα stack pivot σε μια συμβατική x64 ROP chain.

Δείτε εδώ λεπτομέρειες για τη δημιουργία Windows x64 pivot/gadget:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

και γενικές οδηγίες για ROP εδώ:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) για την αποσυσκευασία/αναδόμηση OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD για reverse/taint· απενεργοποιήστε το page heap με TTD, ώστε τα traces να παραμένουν συμπαγή.
- Ένα local proxy (π.χ. Fiddler) μπορεί να προσομοιώσει την supply-chain delivery, αντικαθιστώντας RFAs στην κίνηση των plugins για testing.

## References

- [1] [Δημιουργία ενός πλήρους exploit RCE από ένα crash στην ανάλυση αρχείων RFA του Autodesk Revit (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Οδηγός πεδίου Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Τεκμηρίωση olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Συμβάν Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
