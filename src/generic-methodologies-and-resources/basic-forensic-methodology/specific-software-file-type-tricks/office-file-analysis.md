# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}

Για περισσότερες πληροφορίες, δείτε το [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ακολουθεί μια σύντομη σύνοψη:<sup>[[4]](#references)</sup>

Τα έγγραφα Microsoft Office εμφανίζονται συχνά σε παλαιότερες μορφές, όπως RTF και DOC, XLS και PPT που βασίζονται σε OLE/CFBF, ή σε νεότερες μορφές **Office Open XML (OOXML)**, όπως DOCX, XLSX και PPTX. Τα έγγραφα Office μπορεί να περιέχουν ενεργό περιεχόμενο, όπως macros, γεγονός που τα καθιστά συνηθισμένα μέσα για phishing και malware. Τα αρχεία OOXML είναι αρχεία ZIP, των οποίων η ιεραρχία αρχείων και τα περιεχόμενα XML μπορούν να εξεταστούν με αποσυμπίεση.<sup>[[3]](#references)[[4]](#references)</sup>

Για την εξερεύνηση των δομών αρχείων OOXML, δίνονται η εντολή αποσυμπίεσης ενός εγγράφου και η δομή εξόδου. Έχουν καταγραφεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, γεγονός που δείχνει ότι οι τεχνικές απόκρυψης δεδομένων σε προκλήσεις CTF συνεχίζουν να εξελίσσονται.<sup>[[4]](#references)</sup>

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένα σύνολα εργαλείων για την εξέταση εγγράφων OLE και OOXML. Τα εργαλεία αυτά βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων macros, τα οποία συχνά χρησιμοποιούνται για τη διανομή malware και συνήθως κατεβάζουν και εκτελούν πρόσθετα κακόβουλα payloads. Η ανάλυση VBA macros μπορεί να γίνει χωρίς Microsoft Office, με τη χρήση του Libre Office, το οποίο επιτρέπει τον εντοπισμό σφαλμάτων με breakpoints και μεταβλητές παρακολούθησης.<sup>[[4]](#references)</sup>

Η εγκατάσταση και χρήση του **oletools** είναι απλή, ενώ παρέχονται εντολές για εγκατάσταση μέσω pip και εξαγωγή macros από έγγραφα. Στο Word, τα αυτόματα macros περιλαμβάνουν τα `AutoExec` και `AutoOpen`, ενώ το `Document_Open` είναι μια διαδικασία συμβάντος ανοίγματος.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Για έγγραφα Office κρυπτογραφημένα με κωδικό πρόσβασης, δείτε τη [ροή εργασίας ανάκτησης εκτός σύνδεσης με καθοδήγηση γραμματικής](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Εκμετάλλευση OLE Compound File: Autodesk Revit RFA – επανυπολογισμός ECC και ελεγχόμενο gzip

Τα μοντέλα Revit RFA αποθηκεύονται ως [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (γνωστό και ως CFBF). Το σειριοποιημένο μοντέλο βρίσκεται στο storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Βασική διάταξη του `Global\Latest` (παρατηρήθηκε στο Revit 2025):

- Κεφαλίδα
- Συμπιεσμένο με GZIP payload (το πραγματικό σειριοποιημένο γράφημα αντικειμένων)
- Μηδενικό padding
- Τμήμα ελέγχου σφαλμάτων (ECC)

Το Revit επιδιορθώνει αυτόματα μικρές αλλοιώσεις στο stream χρησιμοποιώντας το τμήμα ECC και απορρίπτει streams που δεν συμφωνούν με το ECC. Επομένως, η αφελής επεξεργασία των συμπιεσμένων bytes δεν θα διατηρηθεί: οι αλλαγές σας είτε αναιρούνται είτε το αρχείο απορρίπτεται. Για να διασφαλίσετε ακριβή έλεγχο σε επίπεδο byte του τι θα δει ο deserializer, πρέπει να:<sup>[[1]](#references)</sup>

- Κάνετε ξανά συμπίεση με υλοποίηση gzip συμβατή με το Revit (ώστε τα συμπιεσμένα bytes που παράγει/αποδέχεται το Revit να συμφωνούν με αυτά που αναμένει).
- Επανυπολογίσετε το τμήμα ECC πάνω από το stream με padding, ώστε το Revit να αποδεχτεί το τροποποιημένο stream χωρίς να το επιδιορθώσει αυτόματα.

Πρακτική ροή εργασίας για την τροποποίηση/fuzzing περιεχομένων RFA:<sup>[[1]](#references)</sup>

1) Αναπτύξτε το σύνθετο έγγραφο OLE.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Επεξεργασία του Global\Latest με προσοχή στα gzip/ECC

- Αποδόμησε το `Global/Latest`: διατήρησε την κεφαλίδα, κάνε gunzip το payload, τροποποίησε τα bytes και, στη συνέχεια, κάνε ξανά gzip χρησιμοποιώντας παραμέτρους deflate συμβατές με το Revit.
- Διατήρησε το zero-padding και υπολόγισε ξανά το ECC trailer, ώστε το Revit να αποδεχτεί τα νέα bytes.
- Αν χρειάζεσαι ντετερμινιστική αναπαραγωγή byte προς byte, δημιούργησε ένα ελάχιστο wrapper γύρω από τα DLL του Revit, ώστε να καλέσεις τις διαδρομές gzip/gunzip και τον υπολογισμό ECC (όπως παρουσιάζεται στην έρευνα), ή χρησιμοποίησε ξανά κάποιο διαθέσιμο helper που αναπαράγει αυτή τη συμπεριφορά.

3) Ανακατασκευή του σύνθετου εγγράφου OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Σημειώσεις:<sup>[[1]](#references)[[2]](#references)</sup>

- Το CompoundFileTool γράφει storages/streams στο filesystem, κάνοντας escaping για χαρακτήρες που δεν είναι έγκυροι σε ονόματα NTFS· η διαδρομή του stream που θέλετε είναι ακριβώς `Global/Latest` στο δέντρο εξόδου.
- Όταν πραγματοποιείτε μαζικές επιθέσεις μέσω ecosystem plugins που λαμβάνουν RFAs από cloud storage, βεβαιωθείτε πρώτα ότι το patched RFA περνά επιτυχώς τους τοπικούς ελέγχους ακεραιότητας του Revit (σωστά gzip/ECC) πριν επιχειρήσετε network injection.

Σημείωση για το exploitation (για να καθοδηγήσει την επιλογή των bytes που θα τοποθετηθούν στο gzip payload):<sup>[[1]](#references)</sup>

- Ο deserializer του Revit διαβάζει έναν δείκτη κλάσης 16-bit και δημιουργεί ένα object. Ορισμένοι τύποι δεν είναι polymorphic και δεν έχουν vtables· η κατάχρηση του χειρισμού του destructor προκαλεί type confusion, όπου η engine εκτελεί μια έμμεση κλήση μέσω ενός pointer που ελέγχει ο attacker.
- Η επιλογή του `AString` (δείκτης κλάσης `0x1F`) τοποθετεί έναν heap pointer που ελέγχει ο attacker στο offset 0 του object. Κατά τον βρόχο του destructor, το Revit ουσιαστικά εκτελεί:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Τοποθετήστε πολλαπλά τέτοια αντικείμενα στο serialized graph, ώστε κάθε επανάληψη του destructor loop να εκτελεί ένα gadget («weird machine»), και οργανώστε ένα stack pivot προς μια συμβατική x64 ROP chain.

Δείτε εδώ λεπτομέρειες για pivot/gadget building σε Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

και εδώ γενικές οδηγίες για ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Εργαλεία:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) για την εξαγωγή και ανακατασκευή σύνθετων αρχείων OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD για reverse/taint· απενεργοποιήστε το page heap με το TTD, ώστε τα traces να παραμένουν συμπαγή.
- Ένας τοπικός proxy (π.χ., Fiddler) μπορεί να προσομοιώσει την παράδοση μέσω supply chain, αντικαθιστώντας RFAs στην κίνηση των plugins για δοκιμές.

## References

- [1] [Δημιουργία πλήρους exploit RCE από crash κατά την ανάλυση αρχείου Autodesk Revit RFA (ιστολόγιο ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Έγγραφα για το OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Οδηγός πεδίου για Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Τεκμηρίωση του olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Συμβάν Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
