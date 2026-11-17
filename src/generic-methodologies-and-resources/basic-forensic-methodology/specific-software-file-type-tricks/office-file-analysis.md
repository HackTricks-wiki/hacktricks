# Ανάλυση αρχείων Office

{{#include ../../../banners/hacktricks-training.md}}

Για περισσότερες πληροφορίες, ανατρέξτε στο [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ακολουθεί μόνο μια σύνοψη:<sup>[[2]](#references)</sup>

Τα έγγραφα Microsoft Office εμφανίζονται συνήθως σε παλαιότερες μορφές, όπως RTF και DOC, XLS και PPT που βασίζονται σε OLE/CFBF, ή σε νεότερες μορφές **Office Open XML (OOXML)**, όπως DOCX, XLSX και PPTX. Τα έγγραφα Office μπορεί να περιέχουν ενεργό περιεχόμενο, όπως μακροεντολές, γεγονός που τα καθιστά συχνά μέσα για phishing και malware. Τα αρχεία OOXML είναι αρχεία ZIP, των οποίων η ιεραρχία αρχείων και τα περιεχόμενα XML μπορούν να εξεταστούν με αποσυμπίεση.<sup>[[1]](#references)[[2]](#references)</sup>

Παρουσιάζονται η εντολή αποσυμπίεσης ενός εγγράφου και η δομή εξόδου, ώστε να εξερευνήσετε τις δομές αρχείων OOXML. Έχουν καταγραφεί τεχνικές απόκρυψης δεδομένων σε αυτά τα αρχεία, γεγονός που δείχνει τη συνεχή εξέλιξη των μεθόδων απόκρυψης δεδομένων σε προκλήσεις CTF.<sup>[[2]](#references)</sup>

Για την ανάλυση, τα **oletools** και **OfficeDissector** προσφέρουν ολοκληρωμένες εργαλειοθήκες για την εξέταση εγγράφων OLE και OOXML. Αυτά τα εργαλεία βοηθούν στον εντοπισμό και την ανάλυση ενσωματωμένων μακροεντολών, οι οποίες συχνά χρησιμοποιούνται για τη διανομή malware, συνήθως με τη λήψη και εκτέλεση πρόσθετων κακόβουλων payloads. Η ανάλυση μακροεντολών VBA μπορεί να γίνει χωρίς το Microsoft Office με τη χρήση του Libre Office, το οποίο επιτρέπει τον εντοπισμό σφαλμάτων με breakpoints και watch variables.<sup>[[2]](#references)</sup>

Η εγκατάσταση και η χρήση του **oletools** είναι απλές, ενώ παρέχονται εντολές για την εγκατάστασή του μέσω pip και την εξαγωγή μακροεντολών από έγγραφα. Στο Word, οι αυτόματες μακροεντολές περιλαμβάνουν τις `AutoExec` και `AutoOpen`, ενώ η `Document_Open` είναι μια διαδικασία συμβάντος ανοίγματος.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Ανάλυση μακροεντολών VBA: Junk Code και UserForms

## Junk Code

Οι μακροεντολές μπορεί να περιέχουν **μη προσπελάσιμο ή άσχετο κώδικα** με σκοπό να επιβραδύνουν την ανάλυση. Εντοπίστε τις σταθερές συνθήκες και ανιχνεύστε τη συμπεριφορά που είναι προσπελάσιμη πριν αφιερώσετε χρόνο στην αντίστροφη μηχανική ενός κλάδου. Το παρακάτω παράδειγμα χρησιμοποιεί μια συνθήκη `If` που δεν μπορεί ποτέ να είναι αληθής, για να αποκρύψει junk code.

![Μια μακροεντολή Word που περιέχει έναν μη προσπελάσιμο κλάδο υπό συνθήκη με junk code](<../../../images/image (369).png>)

## Φόρμες μακροεντολών

Τα VBA UserForms μπορούν να αποθηκεύουν δεδομένα σε στοιχεία ελέγχου, όπως πλαίσια κειμένου. Επειδή οι φόρμες, τα πλαίσια και οι σελίδες μπορούν να εκθέτουν το καθένα μια συλλογή `Controls`, οι αναλυτές θα πρέπει να απαριθμούν ολόκληρη την ιεραρχία των στοιχείων ελέγχου και να μην βασίζονται μόνο σε όσα εμφανίζει η φόρμα. Το παρακάτω παράδειγμα αποθηκεύει κρυφά δεδομένα σε επικαλυπτόμενα πλαίσια κειμένου.<sup>[[6]](#references)</sup>

Κατά τη δυναμική ανάλυση, η συνάρτηση `GetObject` της VBA μπορεί να ανακτήσει ένα αντικείμενο Automation από ένα αρχείο ή να συνδεθεί σε έναν ήδη εκτελούμενο διακομιστή Automation. Οι μακροεντολές μπορεί να χρησιμοποιούν αυτήν την πρόσβαση σε αντικείμενα για να αποκτήσουν πρόσβαση σε δεδομένα που δεν είναι εμφανή στο ορατό έγγραφο· εξετάστε τόσο το αντικείμενο που επιστρέφεται όσο και το δέντρο στοιχείων ελέγχου του UserForm.<sup>[[7]](#references)</sup>

![Ένα UserForm μακροεντολής με δεδομένα κρυμμένα σε επικαλυπτόμενα πλαίσια κειμένου](<../../../images/image (344).png>)

Για έγγραφα Office κρυπτογραφημένα με κωδικό πρόσβασης, δείτε τη [ροή εργασίας offline ανάκτησης με βάση τη γραμματική](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Για αρχεία Revit RFA που χρησιμοποιούν OLE/CFBF, δείτε [επανυπολογισμό ECC, ελεγχόμενο gzip και εκμετάλλευση deserializer](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md)· αυτή η ροή εργασίας εκμετάλλευσης parser είναι ξεχωριστή από την αρχική διαλογή εγγράφων Office.

## References

- [1] [Τεκμηρίωση OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Οδηγός πεδίου για Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Τεκμηρίωση olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Αυτόματες μακροεντολές (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Συμβάν Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Συλλογές, στοιχεία ελέγχου και αντικείμενα (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Συνάρτηση `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
