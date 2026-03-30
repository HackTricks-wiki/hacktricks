# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}


Για περισσότερες πληροφορίες δείτε [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτή είναι απλώς μια σύνοψη:

Η Microsoft έχει δημιουργήσει πολλαπλές μορφές εγγράφων Office, με δύο κύριες κατηγορίες να είναι οι **OLE formats** (όπως RTF, DOC, XLS, PPT) και οι **Office Open XML (OOXML) formats** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορούν να περιέχουν macros, καθιστώντας τες στόχους για phishing και malware. Τα OOXML αρχεία είναι δομημένα ως zip containers, επιτρέποντας την επιθεώρηση μέσω unzipping, αποκαλύπτοντας την ιεραρχία αρχείων και φακέλων και τα περιεχόμενα XML αρχείων.

Για να εξερευνήσετε τις δομές αρχείων OOXML, δίνονται η εντολή για unzip ενός εγγράφου και η έξοδος της δομής. Έχουν τεκμηριωθεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, που δείχνουν συνεχιζόμενη καινοτομία στην απόκρυψη δεδομένων σε CTF challenges.

Για ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν πλήρη toolsets για την εξέταση τόσο OLE όσο και OOXML εγγράφων. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, που συχνά λειτουργούν ως vectors για την παράδοση malware, συνήθως κατεβάζοντας και εκτελώντας επιπλέον κακόβουλα payloads. Η ανάλυση VBA macros μπορεί να γίνει χωρίς Microsoft Office χρησιμοποιώντας Libre Office, το οποίο επιτρέπει debugging με breakpoints και watch variables.

Η εγκατάσταση και η χρήση των **oletools** είναι απλή, με εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Η αυτόματη εκτέλεση macros ενεργοποιείται από συναρτήσεις όπως `AutoOpen`, `AutoExec`, ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως μία [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Το σειριοποιημένο μοντέλο βρίσκεται στο storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Κύρια διάταξη του `Global\Latest` (παρατηρήθηκε σε Revit 2025):

- Header
- GZIP-compressed payload (το πραγματικό σειριοποιημένο γράφημα αντικειμένων)
- Zero padding
- Error-Correcting Code (ECC) trailer

Το Revit θα επιδιορθώνει αυτόματα μικρές διαταραχές στο stream χρησιμοποιώντας το trailer ECC και θα απορρίπτει streams που δεν ταιριάζουν με το ECC. Επομένως, η αφελής επεξεργασία των συμπιεσμένων bytes δεν θα επιμείνει: οι αλλαγές είτε επαναφέρονται είτε το αρχείο απορρίπτεται. Για να εξασφαλίσετε byte-ακριβή έλεγχο στο τι βλέπει ο αποσειριοποιητής πρέπει να:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Πρακτική ροή εργασίας για patching/fuzzing περιεχομένου RFA:

1) Εξάγετε το OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργασία Global\Latest με gzip/ECC πειθαρχία

- Αποσύνθεσε το `Global/Latest`: διατήρησε την κεφαλίδα, κάνε gunzip στο payload, αλλοίωσε bytes, και στη συνέχεια κάνε gzip πίσω χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατήρησε το zero-padding και επανυπολόγισε το ECC trailer ώστε τα νέα bytes να γίνονται αποδεκτά από το Revit.
- Εάν χρειάζεσαι deterministic byte-for-byte αναπαραγωγή, φτιάξε ένα ελάχιστο wrapper γύρω από τα DLLs του Revit για να καλείς τις διαδρομές του gzip/gunzip και τον υπολογισμό ECC (όπως επιδεικνύεται στην έρευνα), ή επαν-χρησιμοποίησε οποιονδήποτε διαθέσιμο helper που αναπαράγει αυτές τις σημασιολογίες.

3) Ανακατασκεύασε το OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:

- Το CompoundFileTool γράφει storages/streams στο σύστημα αρχείων με escaping για χαρακτήρες μη έγκυρους σε ονόματα NTFS· το stream path που θέλετε είναι ακριβώς `Global/Latest` στο δέντρο εξόδου.
- Όταν παραδίδετε μαζικές επιθέσεις μέσω plugins του οικοσυστήματος που ανακτούν RFAs από cloud storage, βεβαιωθείτε ότι το patched RFA περνάει πρώτα τους τοπικούς ελέγχους ακεραιότητας του Revit (gzip/ECC σωστά) πριν επιχειρήσετε δικτυακή έγχυση.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Ο Revit deserializer διαβάζει έναν 16-bit δείκτη κλάσης και κατασκευάζει ένα αντικείμενο. Ορισμένοι τύποι είναι μη‑πολυμορφικοί και στερούνται vtables· η κατάχρηση του χειρισμού του destructor οδηγεί σε ένα type confusion όπου ο engine εκτελεί ένα indirect call μέσω attacker-controlled pointer.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν attacker-controlled heap pointer στη μετατόπιση αντικειμένου 0. Κατά το loop του destructor, το Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια αντικείμενα στο σειριακό γράφο ώστε κάθε επανάληψη του destructor loop να εκτελεί ένα gadget (“weird machine”), και οργανώστε ένα stack pivot σε μια συμβατική x64 ROP chain.

Δείτε τις λεπτομέρειες για Windows x64 pivot/gadget εδώ:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

και γενικές οδηγίες ROP εδώ:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:

- CompoundFileTool (OSS) για την επέκταση/ανακατασκευή OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD για reverse/taint; απενεργοποιήστε το page heap με TTD για να διατηρήσετε τα traces συμπαγή.
- Ένας τοπικός proxy (π.χ. Fiddler) μπορεί να προσομοιώσει την παράδοση supply-chain ανταλλάσσοντας RFAs στην κίνηση plugin για δοκιμές.

## Αναφορές

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
