# Επίπεδα ακεραιότητας

{{#include ../../banners/hacktricks-training.md}}

## Επίπεδα ακεραιότητας

Στα Windows Vista και σε νεότερες εκδόσεις, τα securable objects μπορούν να φέρουν μια ετικέτα **επιπέδου ακεραιότητας**. Τα περισσότερα objects αντιμετωπίζονται ως medium integrity, ενώ συγκεκριμένες τοποθεσίες που προορίζονται για εφαρμογές low-integrity μπορούν να επισημανθούν ως low. Οι διεργασίες που εκκινούνται από standard users εκτελούνται συνήθως σε medium integrity, οι elevated εφαρμογές εκτελούνται σε high integrity και πολλές υπηρεσίες εκτελούνται σε system integrity.<sup>[[1]](#references)</sup>

Ένας βασικός κανόνας είναι ότι τα objects δεν μπορούν να τροποποιηθούν από διεργασίες με χαμηλότερο επίπεδο ακεραιότητας από αυτό του object. Τα Windows εφαρμόζουν αυτόν τον έλεγχο Mandatory Integrity Control (MIC) πριν αξιολογήσουν τη discretionary access control list (DACL) του object. Τα επίπεδα που συναντώνται συχνότερα είναι τα εξής:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Το χαμηλότερο επίπεδο, που αντιπροσωπεύεται από το `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Μην συγχέετε αυτήν την ετικέτα ακεραιότητας με την ταυτότητα **Anonymous Logon** (`S-1-5-7`): οι ταυτότητες authentication και οι ετικέτες MIC ανήκουν σε ξεχωριστά SID namespaces. Ως πραγματικό παράδειγμα, το sandbox του Chromium στα Windows εκχωρεί αρχικά στα sandboxed targets Low integrity και στη συνέχεια υποβιβάζει τα renderer targets σε Untrusted integrity μετά την εκκίνηση.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Χρησιμοποιείται κυρίως για αλληλεπιδράσεις με το internet, ειδικά στο Protected Mode του Internet Explorer, επηρεάζοντας τα σχετιζόμενα αρχεία και τις διεργασίες, καθώς και ορισμένους φακέλους, όπως τον **Temporary Internet Folder**. Οι διεργασίες low integrity αντιμετωπίζουν σημαντικούς περιορισμούς, όπως απουσία πρόσβασης εγγραφής στο registry και περιορισμένη δυνατότητα εγγραφής στο user profile.
- **Medium**: Το προεπιλεγμένο επίπεδο για τις περισσότερες δραστηριότητες, το οποίο εκχωρείται σε standard users και objects χωρίς συγκεκριμένα επίπεδα ακεραιότητας. Ακόμη και τα μέλη της ομάδας Administrators λειτουργούν από προεπιλογή σε αυτό το επίπεδο.
- **High**: Προορίζεται για administrators και τους επιτρέπει να τροποποιούν objects σε χαμηλότερα επίπεδα ακεραιότητας, συμπεριλαμβανομένων και εκείνων που βρίσκονται στο ίδιο το high level.
- **System**: Το υψηλότερο operational level για τον kernel των Windows και τις core services, απρόσιτο ακόμη και στους administrators, εξασφαλίζοντας την προστασία ζωτικών λειτουργιών του συστήματος.

Τα Windows ορίζουν επίσης μια τιμή protected-process integrity πάνω από το System. Το **TrustedInstaller**, ωστόσο, είναι μια ταυτότητα υπηρεσίας των Windows και όχι ξεχωριστό MIC level. Η δυνατότητά του να τροποποιεί προστατευμένους πόρους του operating system προέρχεται από τα permissions που έχουν εκχωρηθεί σε αυτήν την ταυτότητα.

Μην θεωρείτε δεδομένο ότι μια τοποθεσία, όπως η ρίζα ενός system drive, έχει πάντα μια σταθερή ετικέτα High integrity. Ελέγξτε την effective DACL και οποιαδήποτε explicit mandatory label με το `icacls`. Ένα object χωρίς ετικέτα αντιμετωπίζεται ως Medium από το MIC, ενώ η DACL και η ιδιοκτησία του μπορούν ανεξάρτητα να περιορίζουν την πρόσβαση.<sup>[[1]](#references)[[4]](#references)</sup>

Μπορείτε να λάβετε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το **Process Explorer** από το **Sysinternals**, ανοίγοντας τις ιδιότητες της διεργασίας και προβάλλοντας την καρτέλα **Security**:<sup>[[3]](#references)</sup>

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε να λάβετε το επίπεδο ακεραιότητας μιας διεργασίας χρησιμοποιώντας το Process Explorer από το Sysinternals, αποκτώντας πρόσβαση στις ιδιότητες της διεργασίας και προβάλλοντας την "...](<../../images/image (824).png>)

Μπορείτε επίσης να λάβετε το **τρέχον επίπεδο ακεραιότητάς** σας χρησιμοποιώντας το `whoami /groups`:

![Επίπεδα ακεραιότητας - Επίπεδα ακεραιότητας: Μπορείτε επίσης να λάβετε το τρέχον επίπεδο ακεραιότητάς σας χρησιμοποιώντας το whoami /groups](<../../images/image (325).png>)

### Επίπεδα ακεραιότητας στο File System

Ένα object στο file system μπορεί να έχει μια **ελάχιστη απαίτηση επιπέδου ακεραιότητας**. Μια διεργασία κάτω από αυτό το επίπεδο υπόκειται στην mandatory policy του object, ακόμη και όταν η DACL του θα παρείχε διαφορετικά πρόσβαση. Για παράδειγμα, δημιουργήστε ένα κανονικό αρχείο από μια κονσόλα standard-user και ελέγξτε τα permissions του:<sup>[[1]](#references)[[4]](#references)</sup>
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
Τώρα, εκχωρήστε ένα ελάχιστο επίπεδο ακεραιότητας **High** στο αρχείο. Αυτό **πρέπει να γίνει από μια κονσόλα** που εκτελείται ως **administrator**, επειδή μια κανονική κονσόλα εκτελείται με επίπεδο ακεραιότητας Medium και **δεν θα έχει άδεια** να εκχωρήσει επίπεδο ακεραιότητας High σε ένα αντικείμενο:
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
Ο χρήστης `DESKTOP-IDJHTKP\user` έχει **FULL privileges** στο αρχείο, επειδή το δημιούργησε. Ωστόσο, η mandatory label αποτρέπει τον χρήστη από την τροποποίηση του αρχείου, εκτός εάν η διεργασία εκτελείται σε High integrity. Ο χρήστης μπορεί ακόμα να το διαβάσει, επειδή η εμφανιζόμενη mandatory policy είναι `(NW)`, δηλαδή no-write-up:
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

Το ακόλουθο παράδειγμα χρησιμοποιεί ένα αντίγραφο του `cmd.exe` στη διαδρομή `C:\Windows\System32\cmd-low.exe` και του εκχωρεί ένα **Low επίπεδο ακεραιότητας από μια κονσόλα διαχειριστή**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Τώρα, όταν εκτελώ το `cmd-low.exe`, θα **εκτελείται σε επίπεδο χαμηλής ακεραιότητας** αντί για επίπεδο μεσαίας ακεραιότητας:

![Επίπεδα ακεραιότητας στο σύστημα αρχείων - Επίπεδα ακεραιότητας σε binaries: Τώρα, όταν εκτελώ το cmd-low.exe, θα εκτελείται σε επίπεδο χαμηλής ακεραιότητας αντί για επίπεδο μεσαίας ακεραιότητας](<../../images/image (313).png>)

Η εκχώρηση μιας ετικέτας υψηλής ακεραιότητας σε ένα binary (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) δεν το κάνει να εκτελείται αυτόματα με υψηλή ακεραιότητα. Αν κληθεί από μια διεργασία μεσαίας ακεραιότητας, εκτελείται με μεσαία ακεραιότητα, επειδή μια νέα διεργασία λαμβάνει το χαμηλότερο από τα επίπεδα ακεραιότητας του εκτελέσιμου αρχείου και της διεργασίας που την καλεί.<sup>[[1]](#references)</sup>

### Επίπεδα ακεραιότητας σε διεργασίες

Δεν έχουν όλα τα αρχεία και οι φάκελοι μια ρητή ελάχιστη ετικέτα ακεραιότητας, **όμως κάθε διεργασία εκτελείται σε ένα επίπεδο ακεραιότητας**. Όπως και με τα αντικείμενα του συστήματος αρχείων, **μια διεργασία που θέλει πρόσβαση εγγραφής σε μια άλλη διεργασία πρέπει να έχει τουλάχιστον το ίδιο επίπεδο ακεραιότητας**. Επομένως, μια διεργασία χαμηλής ακεραιότητας δεν μπορεί να ανοίξει μια διεργασία μεσαίας ακεραιότητας με πλήρη πρόσβαση.<sup>[[1]](#references)</sup>

Λόγω αυτών των περιορισμών, η ασφαλέστερη προσέγγιση είναι να **εκτελείται κάθε διεργασία στο χαμηλότερο επίπεδο ακεραιότητας που εξακολουθεί να της επιτρέπει να εκτελεί την προβλεπόμενη εργασία της**.

## References

- [1] [Microsoft Learn – Υποχρεωτικός έλεγχος ακεραιότητας](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Απαρίθμηση MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Πηγαίος κώδικας του Chromium – Προεπιλεγμένη πολιτική sandbox ακεραιότητας των Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Γνωστά SID](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
