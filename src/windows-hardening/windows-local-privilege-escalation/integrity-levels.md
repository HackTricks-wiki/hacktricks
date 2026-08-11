# Επίπεδα ακεραιότητας

{{#include ../../banners/hacktricks-training.md}}

## Επίπεδα ακεραιότητας

Στα Windows Vista και σε νεότερες εκδόσεις, τα αντικείμενα που μπορούν να προστατευτούν ενδέχεται να φέρουν ετικέτα **επιπέδου ακεραιότητας**. Τα περισσότερα αντικείμενα αντιμετωπίζονται ως μέσης ακεραιότητας, ενώ συγκεκριμένες τοποθεσίες που προορίζονται για εφαρμογές χαμηλής ακεραιότητας μπορούν να επισημανθούν ως χαμηλής. Οι διεργασίες που εκκινούνται από τυπικούς χρήστες εκτελούνται κανονικά με μέση ακεραιότητα, οι εφαρμογές με αυξημένα δικαιώματα εκτελούνται με υψηλή ακεραιότητα και πολλές υπηρεσίες εκτελούνται με ακεραιότητα συστήματος.<sup>[[1]](#references)</sup>

Ένας βασικός κανόνας είναι ότι τα αντικείμενα δεν μπορούν να τροποποιηθούν από διεργασίες με χαμηλότερο επίπεδο ακεραιότητας από το επίπεδο του αντικειμένου. Τα Windows εφαρμόζουν αυτόν τον έλεγχο Mandatory Integrity Control (MIC) πριν αξιολογήσουν τη discretionary access control list (DACL) του αντικειμένου. Τα επίπεδα που συναντώνται συχνότερα είναι τα εξής:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Το χαμηλότερο επίπεδο, που αναπαρίσταται από το `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Χρησιμοποιείται κυρίως για αλληλεπιδράσεις στο διαδίκτυο, ειδικά στο Protected Mode του Internet Explorer, επηρεάζοντας τα συσχετιζόμενα αρχεία και τις διεργασίες, καθώς και συγκεκριμένους φακέλους όπως τον **Temporary Internet Folder**. Οι διεργασίες χαμηλής ακεραιότητας αντιμετωπίζουν σημαντικούς περιορισμούς, όπως απουσία πρόσβασης εγγραφής στο registry και περιορισμένη πρόσβαση εγγραφής στο προφίλ χρήστη.
- **Medium**: Το προεπιλεγμένο επίπεδο για τις περισσότερες δραστηριότητες, το οποίο εκχωρείται σε τυπικούς χρήστες και αντικείμενα χωρίς συγκεκριμένα επίπεδα ακεραιότητας. Ακόμη και τα μέλη της ομάδας Administrators λειτουργούν από προεπιλογή σε αυτό το επίπεδο.
- **High**: Προορίζεται για administrators, επιτρέποντάς τους να τροποποιούν αντικείμενα χαμηλότερων επιπέδων ακεραιότητας, συμπεριλαμβανομένων και εκείνων που βρίσκονται στο ίδιο το επίπεδο high.
- **System**: Το υψηλότερο λειτουργικό επίπεδο για τον πυρήνα των Windows και τις βασικές υπηρεσίες, απρόσιτο ακόμη και στους administrators, εξασφαλίζοντας την προστασία ζωτικών λειτουργιών του συστήματος.

Τα Windows ορίζουν επίσης μια τιμή ακεραιότητας protected-process πάνω από το System. Το **TrustedInstaller**, ωστόσο, είναι μια ταυτότητα υπηρεσίας των Windows και όχι ξεχωριστό επίπεδο MIC· η δυνατότητά του να τροποποιεί προστατευμένους πόρους του λειτουργικού συστήματος προέρχεται από τα δικαιώματα που έχουν εκχωρηθεί σε αυτήν την ταυτότητα.

Μπορείτε να λάβετε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το **Process Explorer** από το **Sysinternals**, ανοίγοντας τις ιδιότητες της διεργασίας και προβάλλοντας την καρτέλα **Security**:<sup>[[3]](#references)</sup>

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε να λάβετε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το Process Explorer από το Sysinternals, αποκτώντας πρόσβαση στις ιδιότητες της διεργασίας και προβάλλοντας την ...](<../../images/image (824).png>)

Μπορείτε επίσης να λάβετε το **τρέχον επίπεδο ακεραιότητάς** σας χρησιμοποιώντας το `whoami /groups`:

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε επίσης να λάβετε το τρέχον επίπεδο ακεραιότητάς σας χρησιμοποιώντας το whoami /groups](<../../images/image (325).png>)

### Επίπεδα ακεραιότητας στο σύστημα αρχείων

Ένα αντικείμενο στο σύστημα αρχείων μπορεί να διαθέτει **ελάχιστη απαίτηση επιπέδου ακεραιότητας**. Μια διεργασία κάτω από αυτό το επίπεδο υπόκειται στην mandatory policy του αντικειμένου, ακόμη και όταν η DACL του θα επέτρεπε διαφορετικά την πρόσβαση. Για παράδειγμα, δημιουργήστε ένα κανονικό αρχείο από μια κονσόλα τυπικού χρήστη και ελέγξτε τα δικαιώματά του:<sup>[[1]](#references)[[4]](#references)</sup>
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
Τώρα, εκχωρήστε ένα ελάχιστο επίπεδο ακεραιότητας **High** στο αρχείο. Αυτό **πρέπει να γίνει από μια κονσόλα** που εκτελείται ως **administrator**, επειδή μια κανονική κονσόλα εκτελείται με επίπεδο ακεραιότητας Medium και **δεν θα έχει δικαίωμα** να εκχωρήσει επίπεδο ακεραιότητας High σε ένα αντικείμενο:
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
Ο χρήστης `DESKTOP-IDJHTKP\user` έχει **FULL privileges** στο αρχείο, επειδή το δημιούργησε. Ωστόσο, η υποχρεωτική ετικέτα εμποδίζει τον χρήστη να τροποποιήσει το αρχείο, εκτός εάν η διεργασία εκτελείται σε High integrity. Ο χρήστης μπορεί να το διαβάσει, επειδή η εμφανιζόμενη υποχρεωτική πολιτική είναι `(NW)`, ή no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Επομένως, όταν ένα file έχει ένα ελάχιστο integrity level, για να το τροποποιήσετε πρέπει να εκτελείστε τουλάχιστον σε αυτό το integrity level.**

### Integrity Levels σε Binaries

Το ακόλουθο παράδειγμα χρησιμοποιεί ένα αντίγραφο του `cmd.exe` στη διαδρομή `C:\Windows\System32\cmd-low.exe` και του εκχωρεί ένα **Low integrity level από μια κονσόλα διαχειριστή**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Τώρα, όταν εκτελώ το `cmd-low.exe`, θα **εκτελείται σε low-integrity level** αντί για medium:

![Integrity Levels in File-system - Integrity Levels in Binaries: Τώρα, όταν εκτελώ το cmd-low.exe, θα εκτελείται σε low-integrity level αντί για medium](<../../images/image (313).png>)

Η εκχώρηση μιας ετικέτας High integrity σε ένα binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) δεν σημαίνει ότι θα εκτελείται αυτόματα με High integrity. Αν κληθεί από μια διεργασία Medium-integrity, εκτελείται με Medium integrity, επειδή μια νέα διεργασία λαμβάνει το χαμηλότερο από τα επίπεδα ακεραιότητας του εκτελέσιμου αρχείου και της διεργασίας που την καλεί.<sup>[[1]](#references)</sup>

### Επίπεδα ακεραιότητας σε διεργασίες

Δεν έχουν όλα τα αρχεία και οι φάκελοι μια ρητή ελάχιστη ετικέτα ακεραιότητας, **αλλά κάθε διεργασία εκτελείται σε ένα επίπεδο ακεραιότητας**. Όπως και στα αντικείμενα του file-system, **μια διεργασία που θέλει πρόσβαση εγγραφής σε μια άλλη διεργασία πρέπει να έχει τουλάχιστον το ίδιο επίπεδο ακεραιότητας**. Επομένως, μια διεργασία Low-integrity δεν μπορεί να ανοίξει μια διεργασία Medium-integrity με πλήρη πρόσβαση.<sup>[[1]](#references)</sup>

Λόγω αυτών των περιορισμών, η ασφαλέστερη προσέγγιση είναι να **εκτελείται κάθε διεργασία στο χαμηλότερο επίπεδο ακεραιότητας που εξακολουθεί να της επιτρέπει να εκτελεί την προβλεπόμενη εργασία της**.

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – απαρίθμηση MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
