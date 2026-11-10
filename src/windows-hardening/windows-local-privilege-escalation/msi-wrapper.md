# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

Το MSI Wrapper μπορεί να συσκευάσει ένα εκτελέσιμο αρχείο ή script ως αρχείο Windows Installer (`.msi`). Κατεβάστε και εκκινήστε τη δωρεάν έκδοση και, στη συνέχεια, επιλέξτε το εκτελέσιμο αρχείο προς συσκευασία.<sup>[[3]](#references)</sup> Για να εκτελέσετε μια ακολουθία εντολών, επιλέξτε ένα αρχείο `.bat` ως είσοδο αντί να συσκευάσετε το `cmd.exe`.<sup>[[1]](#references)</sup>

![Επιλογή του εκτελέσιμου αρχείου προέλευσης ή του batch script στο MSI Wrapper](<../../images/image (417).png>)

Ρυθμίστε προσεκτικά το πλαίσιο εκτέλεσης και τις άλλες ιδιότητες του installer:

![Ρύθμιση του application ID και του security context στο MSI Wrapper](<../../images/image (312).png>)

![Ρύθμιση των ιδιοτήτων του installer στο MSI Wrapper](<../../images/image (346).png>)

![Έλεγχος των ρυθμίσεων build του MSI Wrapper](<../../images/image (1072).png>)

Αυτές οι τιμές μπορούν να αλλάξουν κατά τη συσκευασία ενός προσαρμοσμένου binary.

Συνεχίστε στις υπόλοιπες σελίδες του wizard και επιλέξτε **Build** για να δημιουργήσετε τον installer.<sup>[[1]](#references)</sup>

## Επαλήθευση του πλαισίου εκτέλεσης της wrapped εντολής

Για ένα δοκιμαστικό πακέτο, τυλίξτε ένα αρχείο `.bat` που καταγράφει το token του, αντί να υποθέσετε ότι η ρύθμιση ανύψωσης δικαιωμάτων του MSI ισχύει και για την υποδιεργασία του.<sup>[[4]](#references)</sup> Στον wizard, επιλέξτε το security context **System** αντί για **User** και επιλέξτε εγκατάσταση ανά μηχάνημα με ανυψωμένα δικαιώματα, αν αυτός είναι ο επιθυμητός τρόπος.<sup>[[5]](#references)</sup> Η επιλογή **System** δεν παρακάμπτει την εξουσιοδότηση: ένας χρήστης που δεν είναι admin εξακολουθεί να χρειάζεται έναν τρόπο εγκατάστασης με ανυψωμένα δικαιώματα, όπως η [λανθασμένη ρύθμιση των δύο πολιτικών `AlwaysInstallElevated`](index.html#alwaysinstallelevated) ή μια προνομιούχα ροή εργασίας installer.<sup>[[2]](#references)</sup> Αν επιλέξετε **User**, η wrapped εντολή εκτελείται με το πλαίσιο του χρήστη που πραγματοποιεί την εγκατάσταση, κάτι που μπορεί να είναι απαραίτητο για πόρους που αφορούν συγκεκριμένο χρήστη ή για πόρους δικτύου.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Δημιουργήστε το MSI χρησιμοποιώντας αυτό το batch file ως είσοδο και, στη συνέχεια, εκτελέστε το στον δοκιμαστικό host και ελέγξτε την καταγεγραμμένη ταυτότητα και τα δικαιώματα.<sup>[[4]](#references)</sup> Το MSI Wrapper αντιστοιχίζει έναν μη μηδενικό κωδικό εξόδου του batch σε σφάλμα εγκατάστασης 1603, επομένως η ρητή επιστροφή μηδενικού κωδικού αποτρέπει μια εσφαλμένη αποτυχία μετά από επιτυχημένη δοκιμή.<sup>[[4]](#references)</sup> Το αρχείο εξόδου είναι ένα τεχνούργημα δοκιμής· μην συμπεραίνετε ότι εκτελέστηκε ως SYSTEM μόνο και μόνο επειδή η εκτέλεση του `msiexec` ολοκληρώθηκε επιτυχώς ή η εγκατάσταση έγινε αθόρυβα.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` αποκρύπτει το περιβάλλον εργασίας του MSI, όχι απαραίτητα το περιβάλλον εργασίας του εκτελέσιμου αρχείου που περιλαμβάνει.<sup>[[6]](#references)[[7]](#references)</sup> Για ένα πρόγραμμα εγκατάστασης που περιλαμβάνεται, ορίστε στον οδηγό τις υποστηριζόμενες παραμέτρους σιωπηλής εγκατάστασης· η δυναμική ιδιότητα `WRAPPED_ARGUMENTS` του MSI Wrapper είναι δυνατότητα PRO.<sup>[[1]](#references)[[7]](#references)</sup> Δείτε [την προσέγγιση custom-action του WiX](create-msi-with-wix.md) αν χρειάζεστε άμεσο έλεγχο της αλληλουχίας και της πλαστοπροσωπίας των custom-action.

> [!WARNING]
> Η δημιουργία ενός MSI δεν παρέχει από μόνη της αυξημένα προνόμια. Το αν η εγκατάσταση θα γίνει με αυξημένα προνόμια εξαρτάται από την πολιτική του Windows Installer, το πλαίσιο του πακέτου και την εξουσιοδότηση του χρήστη. Η Microsoft προειδοποιεί ότι η ενεργοποίηση του `AlwaysInstallElevated` τόσο για τον χρήστη όσο και για τον υπολογιστή επιτρέπει σε μη διαχειριστές να εγκαθιστούν πακέτα με προνόμια συστήματος.<sup>[[2]](#references)</sup>



## References

- [1] [Τεκμηρίωση MSI Wrapper - Ξεκινώντας](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Εγκατάσταση πακέτου με αυξημένα προνόμια για μη διαχειριστή](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Λήψη](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Δημιουργία msi από αρχείο batch](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Σελίδες οδηγού](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Επιλογές γραμμής εντολών](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Ορίσματα γραμμής εντολών](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
