# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Τα Macros μπορεί να περιέχουν **μη προσπελάσιμο ή άσχετο code**, με σκοπό να επιβραδύνουν την ανάλυση. Εντοπίστε τις σταθερές συνθήκες και ανιχνεύστε τη συμπεριφορά που είναι προσβάσιμη, πριν αφιερώσετε χρόνο στην αντίστροφη ανάλυση ενός branch. Το παρακάτω παράδειγμα χρησιμοποιεί μια συνθήκη `If` που δεν μπορεί ποτέ να είναι true, ώστε να αποκρύψει junk code.

![Ένα Word macro που περιέχει ένα μη προσπελάσιμο conditional branch με junk code](<../images/image (369).png>)

## Macro Forms

Τα VBA UserForms μπορούν να αποθηκεύουν δεδομένα σε controls, όπως text boxes. Επειδή τα forms, frames και pages μπορούν να εκθέτουν το καθένα μια συλλογή `Controls`, οι analysts θα πρέπει να απαριθμούν ολόκληρη την ιεραρχία των controls, αντί να βασίζονται μόνο σε όσα εμφανίζει το form. Το παρακάτω παράδειγμα αποθηκεύει κρυφά δεδομένα σε επικαλυπτόμενα text boxes.<sup>[[1]](#references)</sup>

Κατά τη dynamic analysis, η συνάρτηση `GetObject` της VBA μπορεί να ανακτήσει ένα Automation object από ένα αρχείο ή να συνδεθεί σε έναν Automation server που εκτελείται ήδη. Τα Macros μπορούν να χρησιμοποιήσουν αυτή την πρόσβαση στο object για να φτάσουν σε δεδομένα που δεν είναι εμφανή στο ορατό document. Εξετάστε τόσο το object που επιστρέφεται όσο και το control tree του UserForm.<sup>[[2]](#references)</sup>

![Ένα macro UserForm με δεδομένα κρυμμένα σε επικαλυπτόμενα text boxes](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Συλλογές, controls και objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Συνάρτηση `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
