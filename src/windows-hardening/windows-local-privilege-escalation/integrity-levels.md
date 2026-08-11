# Επίπεδα ακεραιότητας

{{#include ../../banners/hacktricks-training.md}}

## Επίπεδα ακεραιότητας

Στα Windows Vista και στις νεότερες εκδόσεις, τα securable objects μπορούν να φέρουν μια ετικέτα **επιπέδου ακεραιότητας**. Τα περισσότερα objects αντιμετωπίζονται ως objects με μεσαία ακεραιότητα, ενώ συγκεκριμένες τοποθεσίες που προορίζονται για εφαρμογές χαμηλής ακεραιότητας μπορούν να επισημανθούν ως χαμηλής ακεραιότητας. Οι διεργασίες που ξεκινούν από standard users εκτελούνται κανονικά με μεσαία ακεραιότητα, οι elevated εφαρμογές εκτελούνται με υψηλή ακεραιότητα και πολλές υπηρεσίες εκτελούνται με ακεραιότητα συστήματος.<sup>[[1]](#references)</sup>

Ένας βασικός κανόνας είναι ότι τα objects δεν μπορούν να τροποποιηθούν από διεργασίες με χαμηλότερο επίπεδο ακεραιότητας από αυτό του object. Τα Windows εφαρμόζουν αυτόν τον έλεγχο Mandatory Integrity Control (MIC) πριν αξιολογήσουν τη discretionary access control list (DACL) του object. Τα επίπεδα που συναντώνται συχνότερα είναι τα εξής:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Το χαμηλότερο επίπεδο, που αναπαρίσταται από το `SECURITY_MANDATORY_UNTRUSTED_RID`. Ως παράδειγμα από τον πραγματικό κόσμο, το Windows sandbox του Chromium αρχικά εκχωρεί στα sandboxed targets χαμηλή ακεραιότητα και στη συνέχεια υποβαθμίζει τα renderer targets σε Untrusted ακεραιότητα μετά την εκκίνηση.<sup>[[5]](#references)</sup>
- **Low**: Χρησιμοποιείται κυρίως για αλληλεπιδράσεις με το Internet, ειδικά στο Protected Mode του Internet Explorer, επηρεάζοντας τα συσχετισμένα αρχεία και τις διεργασίες, καθώς και ορισμένους φακέλους όπως τον **Temporary Internet Folder**. Οι διεργασίες χαμηλής ακεραιότητας υπόκεινται σε σημαντικούς περιορισμούς, όπως απουσία πρόσβασης εγγραφής στο registry και περιορισμένη πρόσβαση εγγραφής στο user profile.
- **Medium**: Το προεπιλεγμένο επίπεδο για τις περισσότερες δραστηριότητες, το οποίο εκχωρείται σε standard users και objects χωρίς συγκεκριμένα επίπεδα ακεραιότητας. Ακόμη και τα μέλη της ομάδας Administrators λειτουργούν σε αυτό το επίπεδο από προεπιλογή.
- **High**: Προορίζεται για administrators, επιτρέποντάς τους να τροποποιούν objects χαμηλότερων επιπέδων ακεραιότητας, συμπεριλαμβανομένων εκείνων που βρίσκονται στο ίδιο το επίπεδο high.
- **System**: Το υψηλότερο λειτουργικό επίπεδο για τον Windows kernel και τις βασικές υπηρεσίες, απρόσιτο ακόμη και στους administrators, διασφαλίζοντας την προστασία ζωτικών λειτουργιών του συστήματος.

Τα Windows ορίζουν επίσης μια τιμή ακεραιότητας protected-process πάνω από το System. Το **TrustedInstaller**, ωστόσο, είναι μια ταυτότητα υπηρεσίας των Windows και όχι ξεχωριστό επίπεδο MIC· η δυνατότητά του να τροποποιεί προστατευμένους πόρους του λειτουργικού συστήματος προκύπτει από τα permissions που έχουν εκχωρηθεί σε αυτή την ταυτότητα.

Μπορείτε να ανακτήσετε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το **Process Explorer** από το **Sysinternals**, ανοίγοντας τις ιδιότητες της διεργασίας και προβάλλοντας την καρτέλα **Security**:<sup>[[3]](#references)</sup>

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε να δείτε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το Process Explorer από το Sysinternals, αποκτώντας πρόσβαση στις ιδιότητες της διεργασίας και προβάλλοντας την ...](<../../images/image (824).png>)

Μπορείτε επίσης να ανακτήσετε το **τρέχον επίπεδο ακεραιότητάς σας** χρησιμοποιώντας το `whoami /groups`:

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε επίσης να δείτε το τρέχον επίπεδο ακεραιότητάς σας χρησιμοποιώντας το whoami /groups](<../../images/image (325).png>)

### Επίπεδα ακεραιότητας στο σύστημα αρχείων

Ένα object στο σύστημα αρχείων μπορεί να διαθέτει μια **ελάχιστη απαίτηση επιπέδου ακεραιότητας**. Μια διεργασία κάτω από αυτό το επίπεδο υπόκειται στην υποχρεωτική πολιτική του object, ακόμη και όταν η DACL του θα παρείχε διαφορετικά πρόσβαση. Για παράδειγμα, δημιουργήστε ένα κανονικό αρχείο από μια κονσόλα standard user και ελέγξτε τα permissions του:<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Τώρα, εκχωρήστε ένα ελάχιστο επίπεδο ακεραιότητας **High** στο αρχείο. Αυτό **πρέπει να γίνει από μια κονσόλα** που εκτελείται ως **administrator**, επειδή μια κανονική κονσόλα εκτελείται με ακεραιότητα Medium και **δεν θα επιτρέπεται** να εκχωρήσει ακεραιότητα High σε ένα αντικείμενο:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Ο χρήστης `DESKTOP-IDJHTKP\user` έχει **ΠΛΗΡΗ δικαιώματα** στο αρχείο, επειδή ο συγκεκριμένος χρήστης το δημιούργησε. Ωστόσο, η υποχρεωτική ετικέτα δεν επιτρέπει στον χρήστη να τροποποιήσει το αρχείο, εκτός εάν η διεργασία εκτελείται με επίπεδο ακεραιότητας High. Ο χρήστης μπορεί να το διαβάσει, επειδή η εμφανιζόμενη υποχρεωτική πολιτική είναι `(NW)`, δηλαδή no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Επομένως, όταν ένα αρχείο έχει ένα ελάχιστο επίπεδο ακεραιότητας, για να το τροποποιήσετε πρέπει να εκτελείστε τουλάχιστον σε αυτό το επίπεδο ακεραιότητας.**

### Επίπεδα ακεραιότητας σε Binaries

Το ακόλουθο παράδειγμα χρησιμοποιεί ένα αντίγραφο του `cmd.exe` στη θέση `C:\Windows\System32\cmd-low.exe` και του εκχωρεί ένα **Low integrity level από μια κονσόλα διαχειριστή**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Τώρα, όταν εκτελώ το `cmd-low.exe`, θα **εκτελείται σε επίπεδο χαμηλής ακεραιότητας** αντί για μεσαίο:

![Επίπεδα ακεραιότητας στο σύστημα αρχείων - Επίπεδα ακεραιότητας σε δυαδικά αρχεία: Τώρα, όταν εκτελώ το cmd-low.exe, θα εκτελείται σε επίπεδο χαμηλής ακεραιότητας αντί για μεσαίο](<../../images/image (313).png>)

Η εκχώρηση μιας ετικέτας υψηλής ακεραιότητας σε ένα δυαδικό αρχείο (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) δεν σημαίνει ότι θα εκτελείται αυτόματα σε υψηλή ακεραιότητα. Αν εκκινηθεί από μια διεργασία μεσαίας ακεραιότητας, εκτελείται σε μεσαία ακεραιότητα, επειδή μια νέα διεργασία λαμβάνει το χαμηλότερο από τα επίπεδα ακεραιότητας του εκτελέσιμου αρχείου και της διεργασίας που την καλεί.<sup>[[1]](#references)</sup>

### Επίπεδα ακεραιότητας σε διεργασίες

Δεν έχουν όλα τα αρχεία και οι φάκελοι μια explicit ελάχιστη ετικέτα ακεραιότητας, **όμως κάθε διεργασία εκτελείται σε ένα επίπεδο ακεραιότητας**. Όπως και με τα αντικείμενα του συστήματος αρχείων, **μια διεργασία που θέλει πρόσβαση εγγραφής σε μια άλλη διεργασία πρέπει να έχει τουλάχιστον το ίδιο επίπεδο ακεραιότητας**. Επομένως, μια διεργασία χαμηλής ακεραιότητας δεν μπορεί να ανοίξει μια διεργασία μεσαίας ακεραιότητας με πλήρη πρόσβαση.<sup>[[1]](#references)</sup>

Λόγω αυτών των περιορισμών, η ασφαλέστερη προσέγγιση είναι να **εκτελείται κάθε διεργασία στο χαμηλότερο επίπεδο ακεραιότητας που εξακολουθεί να της επιτρέπει να εκτελεί την προβλεπόμενη εργασία της**.

## References

- [1] [Microsoft Learn – Υποχρεωτικός έλεγχος ακεραιότητας](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – απαρίθμηση MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Πηγαίος κώδικας Chromium – Προεπιλεγμένη πολιτική sandbox των Windows ως προς την ακεραιότητα](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
