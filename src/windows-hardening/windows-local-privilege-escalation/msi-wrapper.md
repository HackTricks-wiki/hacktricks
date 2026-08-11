# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

Το MSI Wrapper μπορεί να συσκευάσει ένα εκτελέσιμο αρχείο ή script ως αρχείο Windows Installer (`.msi`). Κατεβάστε και εκκινήστε τη δωρεάν έκδοση και, στη συνέχεια, επιλέξτε το εκτελέσιμο αρχείο προς συσκευασία. Για να εκτελέσετε μια ακολουθία εντολών, επιλέξτε ένα αρχείο `.bat` ως είσοδο αντί να συσκευάσετε το `cmd.exe`.<sup>[[1]](#references)</sup>

![Επιλογή του εκτελέσιμου αρχείου προέλευσης ή του batch script στο MSI Wrapper](<../../images/image (417).png>)

Διαμορφώστε προσεκτικά το execution context και τις υπόλοιπες ιδιότητες του installer:

![Διαμόρφωση του application ID και του security context στο MSI Wrapper](<../../images/image (312).png>)

![Διαμόρφωση των ιδιοτήτων του installer στο MSI Wrapper](<../../images/image (346).png>)

![Έλεγχος των ρυθμίσεων build του MSI Wrapper](<../../images/image (1072).png>)

Αυτές οι τιμές μπορούν να αλλάξουν κατά τη συσκευασία ενός custom binary.

Συνεχίστε στις υπόλοιπες σελίδες του wizard και επιλέξτε **Build** για να δημιουργήσετε τον installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Η δημιουργία ενός MSI δεν παρέχει από μόνη της elevated privileges. Το αν η εγκατάσταση θα εκτελεστεί με elevated privileges εξαρτάται από την πολιτική του Windows Installer, το package context και την εξουσιοδότηση του χρήστη. Η Microsoft προειδοποιεί ότι η ενεργοποίηση του `AlwaysInstallElevated` τόσο για τον χρήστη όσο και για τον υπολογιστή επιτρέπει σε μη διαχειριστές να εγκαθιστούν packages με system privileges.<sup>[[2]](#references)</sup>

## References

- [1] [Τεκμηρίωση του MSI Wrapper - Ξεκινώντας](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Εγκατάσταση package με elevated privileges για non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
