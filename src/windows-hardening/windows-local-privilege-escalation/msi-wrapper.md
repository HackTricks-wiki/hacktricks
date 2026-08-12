# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

Το MSI Wrapper μπορεί να συσκευάσει ένα executable ή script ως αρχείο Windows Installer (`.msi`). Κατεβάστε και εκκινήστε τη free edition και, στη συνέχεια, επιλέξτε το executable που θέλετε να συσκευάσετε.<sup>[[3]](#references)</sup> Για να εκτελέσετε μια ακολουθία εντολών, επιλέξτε ένα αρχείο `.bat` ως input αντί να συσκευάσετε το `cmd.exe`.<sup>[[1]](#references)</sup>

![Επιλογή του source executable ή batch script στο MSI Wrapper](<../../images/image (417).png>)

Διαμορφώστε προσεκτικά το execution context και τις υπόλοιπες ιδιότητες του installer:

![Διαμόρφωση του application ID και του security context στο MSI Wrapper](<../../images/image (312).png>)

![Διαμόρφωση των ιδιοτήτων του installer στο MSI Wrapper](<../../images/image (346).png>)

![Έλεγχος των ρυθμίσεων build του MSI Wrapper](<../../images/image (1072).png>)

Αυτές οι τιμές μπορούν να αλλάξουν κατά τη συσκευασία ενός custom binary.

Συνεχίστε στις υπόλοιπες σελίδες του wizard και επιλέξτε **Build** για να δημιουργήσετε τον installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Η δημιουργία ενός MSI δεν παρέχει από μόνη της elevated privileges. Το αν η εγκατάσταση θα γίνει με elevated privileges εξαρτάται από την πολιτική του Windows Installer, το package context και την εξουσιοδότηση του χρήστη. Η Microsoft προειδοποιεί ότι η ενεργοποίηση του `AlwaysInstallElevated` τόσο για τον χρήστη όσο και για τον υπολογιστή επιτρέπει σε non-administrators να εγκαθιστούν packages με system privileges.<sup>[[2]](#references)</sup>

## References

- [1] [Τεκμηρίωση του MSI Wrapper - Ξεκινώντας](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Εγκατάσταση package με elevated privileges για non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Λήψη](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
