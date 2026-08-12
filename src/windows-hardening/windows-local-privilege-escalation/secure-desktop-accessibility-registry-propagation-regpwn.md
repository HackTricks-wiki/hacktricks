# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι δυνατότητες Windows Accessibility αποθηκεύουν τη διαμόρφωση του χρήστη στο HKCU και την προωθούν σε τοποθεσίες HKLM ανά session. Κατά τη μετάβαση σε **Secure Desktop** (οθόνη κλειδώματος ή προτροπή UAC), τα components του **SYSTEM** αντιγράφουν ξανά αυτές τις τιμές. Αν το **per-session HKLM key είναι εγγράψιμο από τον χρήστη**, γίνεται ένα privileged write choke point που μπορεί να ανακατευθυνθεί με **registry symbolic links**, επιτρέποντας ένα **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Η τεχνική RegPwn εκμεταλλεύεται αυτή την αλυσίδα propagation με ένα μικρό race window, το οποίο σταθεροποιείται μέσω ενός **opportunistic lock (oplock)** σε ένα αρχείο που χρησιμοποιείται από το `osk.exe`.<sup>[[1]](#references)</sup>

## Αλυσίδα Registry Propagation (Accessibility -> Secure Desktop)

Παράδειγμα feature: **On-Screen Keyboard** (`osk`). Οι σχετικές τοποθεσίες είναι:

- **Λίστα feature σε επίπεδο συστήματος**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Διαμόρφωση ανά χρήστη (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Διαμόρφωση HKLM ανά session (δημιουργείται από το `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (context SYSTEM)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Η propagation κατά τη μετάβαση σε secure desktop (απλοποιημένη):

1. Το user `atbroker.exe` αντιγράφει το `HKCU\...\ATConfig\osk` στο `HKLM\...\Session<session id>\ATConfig\osk`.
2. Το **SYSTEM** `atbroker.exe` αντιγράφει το `HKLM\...\Session<session id>\ATConfig\osk` στο `HKU\.DEFAULT\...\ATConfig\osk`.
3. Το **SYSTEM** `osk.exe` αντιγράφει το `HKU\.DEFAULT\...\ATConfig\osk` πίσω στο `HKLM\...\Session<session id>\ATConfig\osk`.

Αν το HKLM subtree του session είναι εγγράψιμο από τον χρήστη, τα βήματα 2/3 παρέχουν ένα SYSTEM write μέσω μιας τοποθεσίας που ο χρήστης μπορεί να αντικαταστήσει.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write μέσω Registry Links

Αντικαταστήστε το user-writable per-session key με ένα **registry symbolic link** που δείχνει σε έναν προορισμό της επιλογής του attacker. Όταν πραγματοποιηθεί το SYSTEM copy, ακολουθεί το link και γράφει τιμές που ελέγχει ο attacker στο arbitrary target key.

Βασική ιδέα:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Ο attacker αντικαθιστά αυτό το key με ένα **registry link** προς οποιοδήποτε άλλο key.
- Το **SYSTEM** εκτελεί το copy και γράφει στο key της επιλογής του attacker με SYSTEM permissions.

Αυτό παρέχει ένα **arbitrary SYSTEM registry write** primitive.<sup>[[1]](#references)</sup>

## Κερδίζοντας το Race Window με Oplocks

Υπάρχει ένα σύντομο timing window μεταξύ της εκκίνησης του **SYSTEM `osk.exe`** και της εγγραφής του per-session key. Για να γίνει αξιόπιστο, το exploit τοποθετεί ένα **oplock** σε:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Όταν ενεργοποιείται το oplock, ο attacker αντικαθιστά το per-session κλειδί HKLM με ένα registry link, αφήνει την εγγραφή από το SYSTEM να ολοκληρωθεί και στη συνέχεια αφαιρεί το link.<sup>[[1]](#references)</sup>

## Παράδειγμα Ροής Exploitation (Υψηλού Επιπέδου)

1. Λάβετε το τρέχον **session ID** από το access token.
2. Εκκινήστε ένα κρυφό instance του `osk.exe` και περιμένετε για λίγο (ώστε να ενεργοποιηθεί το oplock).
3. Γράψτε τιμές που ελέγχει ο attacker στο:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Ορίστε ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Ενεργοποιήστε το **Secure Desktop** (`LockWorkstation()`), προκαλώντας την εκκίνηση των SYSTEM `atbroker.exe` / `osk.exe`.
6. Κατά την ενεργοποίηση του oplock, αντικαταστήστε το `HKLM\...\Session<session id>\ATConfig\osk` με ένα **registry link** προς έναν αυθαίρετο στόχο.
7. Περιμένετε για λίγο ώστε να ολοκληρωθεί το SYSTEM copy και στη συνέχεια αφαιρέστε το link.<sup>[[1]](#references)</sup>

## Μετατροπή του Primitive σε Εκτέλεση ως SYSTEM

Μια απλή αλυσίδα είναι η αντικατάσταση μιας τιμής **service configuration** (π.χ. `ImagePath`) και στη συνέχεια η εκκίνηση του service. Το RegPwn PoC αντικαθιστά το `ImagePath` του **`msiserver`** και το ενεργοποιεί με τη δημιουργία του **MSI COM object**, με αποτέλεσμα την εκτέλεση κώδικα ως **SYSTEM**.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

## Σχετικά

Για άλλες συμπεριφορές του Secure Desktop / UIAccess, δείτε:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)
{{#include ../../banners/hacktricks-training.md}}
