# Μακροεντολές Word

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Οι μακροεντολές μπορεί να περιέχουν **μη προσπελάσιμο ή άσχετο κώδικα**, με σκοπό να επιβραδύνουν την ανάλυση. Εντοπίστε τις σταθερές συνθήκες και ανιχνεύστε τη συμπεριφορά που είναι προσβάσιμη, προτού αφιερώσετε χρόνο στην αντίστροφη ανάλυση ενός κλάδου. Το παρακάτω παράδειγμα χρησιμοποιεί μια συνθήκη `If` που δεν μπορεί ποτέ να είναι αληθής, ώστε να αποκρύψει junk code.

![Μια μακροεντολή Word που περιέχει έναν μη προσπελάσιμο υπό συνθήκη κλάδο με junk code](<../images/image (369).png>)

## Macro Forms

Τα VBA UserForms μπορούν να αποθηκεύουν δεδομένα σε controls, όπως text boxes. Επειδή οι φόρμες, τα frames και οι pages μπορούν να εκθέτουν το καθένα μια συλλογή `Controls`, οι αναλυτές θα πρέπει να απαριθμούν ολόκληρη την ιεραρχία των controls, αντί να βασίζονται μόνο σε όσα εμφανίζει η φόρμα. Το παρακάτω παράδειγμα αποθηκεύει κρυφά δεδομένα σε επικαλυπτόμενα text boxes.<sup>[[1]](#references)</sup>

![Ένα macro UserForm με δεδομένα κρυμμένα σε επικαλυπτόμενα text boxes](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Συλλογές, controls και αντικείμενα (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
