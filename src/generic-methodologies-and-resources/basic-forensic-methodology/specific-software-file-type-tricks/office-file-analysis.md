# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}


Για περισσότερες πληροφορίες δείτε [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Αυτό είναι απλώς μια περίληψη:

Η Microsoft έχει δημιουργήσει πολλές μορφές εγγράφων, με δύο κύριους τύπους να είναι **OLE formats** (όπως RTF, DOC, XLS, PPT) και **Office Open XML (OOXML) formats** (όπως DOCX, XLSX, PPTX). Αυτές οι μορφές μπορούν να περιέχουν macros, καθιστώντας τες στόχους για phishing και malware. Τα OOXML αρχεία είναι δομημένα ως zip containers, επιτρέποντας την επιθεώρηση μέσω unzipping, αποκαλύπτοντας την ιεραρχία αρχείων/φακέλων και το περιεχόμενο των XML αρχείων.

Για να εξερευνήσετε τη δομή των OOXML αρχείων, δίνεται η εντολή για unzip ενός εγγράφου και η δομή εξόδου. Τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία έχουν τεκμηριωθεί, υποδεικνύοντας συνεχή καινοτομία στην απόκρυψη δεδομένων μέσα σε CTF challenges.

Για ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα toolsets για την εξέταση τόσο OLE όσο και OOXML εγγράφων. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, που συχνά λειτουργούν ως φορείς για παράδοση malware, συνήθως κατεβάζοντας και εκτελώντας επιπλέον κακόβουλα payloads. Η ανάλυση των VBA macros μπορεί να γίνει χωρίς Microsoft Office χρησιμοποιώντας Libre Office, που επιτρέπει debugging με breakpoints και watch variables.

Η εγκατάσταση και η χρήση των **oletools** είναι απλές, με εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Η αυτόματη εκτέλεση των macros ενεργοποιείται από συναρτήσεις όπως `AutoOpen`, `AutoExec`, ή `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File Εκμετάλλευση: Autodesk Revit RFA – επανυπολογισμός ECC και ελεγχόμενο gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως ένα [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Το σειριοποιημένο μοντέλο βρίσκεται κάτω από storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (παρατηρήθηκε στο Revit 2025):

- Header
- GZIP-compressed payload (το πραγματικό σειριοποιημένο γράφημα αντικειμένων)
- Zero padding
- Error-Correcting Code (ECC) trailer

Το Revit θα αυτοεπιδιορθώσει μικρές παρεκκλίσεις στο stream χρησιμοποιώντας το ECC trailer και θα απορρίψει streams που δεν ταιριάζουν με το ECC. Επομένως, η πρόχειρη επεξεργασία των συμπιεσμένων bytes δεν θα διατηρηθεί: οι αλλαγές σας είτε θα αναιρεθούν είτε το αρχείο θα απορριφθεί. Για να εξασφαλίσετε byte-ακριβή έλεγχο πάνω σε αυτά που βλέπει ο deserializer, πρέπει:

- Να επανασυμπιέσετε με μια Revit-compatible gzip υλοποίηση (ώστε τα συμπιεσμένα bytes που παράγει/αποδέχεται το Revit να ταιριάζουν με αυτά που περιμένει).
- Να επανυπολογίσετε το ECC trailer πάνω στο padded stream ώστε το Revit να αποδεχτεί το τροποποιημένο stream χωρίς να το αυτοεπιδιορθώσει.

Πρακτικό workflow για την επεξεργασία/fuzzing του περιεχομένου RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Επεξεργαστείτε το Global\Latest με gzip/ECC πρακτική

- Αποδομήστε το `Global/Latest`: διατηρήστε την κεφαλίδα, κάντε gunzip στο payload, μεταβάλλετε bytes, και έπειτα κάντε gzip ξανά χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατηρήστε το zero-padding και επαναυπολογίστε το ECC trailer ώστε τα νέα bytes να γίνουν αποδεκτά από το Revit.
- Εάν χρειάζεστε ντετερμινιστική αναπαραγωγή byte-for-byte, δημιουργήστε ένα ελάχιστο περίβλημα γύρω από τα DLLs του Revit για να καλέσετε τις gzip/gunzip διαδρομές και τον υπολογισμό του ECC (όπως επιδείχθηκε στην έρευνα), ή επαναχρησιμοποιήστε οποιοδήποτε διαθέσιμο βοηθητικό εργαλείο που αναπαράγει αυτές τις συμπεριφορές.

3) Επαναδημιουργήστε το σύνθετο έγγραφο OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Σημειώσεις:

- Το CompoundFileTool γράφει storages/streams στο σύστημα αρχείων με escaping για χαρακτήρες άκυρους σε ονόματα NTFS· το stream path που θέλετε είναι ακριβώς `Global/Latest` στο δέντρο εξόδου.
- Όταν διανέμετε μαζικές επιθέσεις μέσω ecosystem plugins που ανακτούν RFAs από cloud storage, βεβαιωθείτε ότι το patched RFA περνάει τοπικά τους ελέγχους ακεραιότητας του Revit πρώτα (gzip/ECC σωστό) πριν επιχειρήσετε network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Ο Revit deserializer διαβάζει έναν 16-bit class index και κατασκευάζει ένα object. Ορισμένοι τύποι είναι non‑polymorphic και δεν έχουν vtables· η κατάχρηση της διαχείρισης destructor οδηγεί σε type confusion όπου η engine εκτελεί μια indirect call μέσω ενός attacker-controlled pointer.
- Η επιλογή του `AString` (class index `0x1F`) τοποθετεί έναν attacker-controlled heap pointer στη θέση offset 0 του object. Κατά τον destructor loop, ο Revit ουσιαστικά εκτελεί:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Τοποθετήστε πολλαπλά τέτοια αντικείμενα στον σειριοποιημένο γράφο ώστε κάθε επανάληψη του destructor loop να εκτελεί ένα gadget (“weird machine”), και κανονίστε ένα stack pivot σε συμβατική x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:

- CompoundFileTool (OSS) για επέκταση/αναδημιουργία OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD για reverse/taint; απενεργοποιήστε το page heap με TTD για να διατηρείτε τα traces συμπαγή.
- Ένας τοπικός proxy (π.χ. Fiddler) μπορεί να προσομοιώσει supply-chain delivery ανταλλάσσοντας RFAs στην κίνηση του plugin για δοκιμές.

## Αναφορές

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
