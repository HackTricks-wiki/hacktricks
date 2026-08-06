# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι λειτουργίες Accessibility των Windows διατηρούν τη ρύθμιση του χρήστη στο HKCU και τη μεταδίδουν σε τοποθεσίες HKLM ανά session. Κατά τη μετάβαση σε **Secure Desktop** (οθόνη κλειδώματος ή προτροπή UAC), στοιχεία του **SYSTEM** αντιγράφουν ξανά αυτές τις τιμές. Αν το **per-session HKLM key είναι εγγράψιμο από τον χρήστη**, γίνεται ένα privileged write choke point που μπορεί να ανακατευθυνθεί με **registry symbolic links**, επιτρέποντας ένα **arbitrary SYSTEM registry write**.<sup>[[1]](#references)</sup>

Η τεχνική RegPwn κάνει abuse σε αυτή την αλυσίδα propagation με ένα μικρό race window, το οποίο σταθεροποιείται μέσω ενός **opportunistic lock (oplock)** σε ένα αρχείο που χρησιμοποιείται από το `osk.exe`.<sup>[[1]](#references)</sup>

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Παράδειγμα feature: **On-Screen Keyboard** (`osk`). Οι σχετικές τοποθεσίες είναι:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Propagation κατά τη διάρκεια μιας μετάβασης σε secure desktop (απλοποιημένα):

1. Το user `atbroker.exe` αντιγράφει το `HKCU\...\ATConfig\osk` στο `HKLM\...\Session<session id>\ATConfig\osk`.
2. Το **SYSTEM** `atbroker.exe` αντιγράφει το `HKLM\...\Session<session id>\ATConfig\osk` στο `HKU\.DEFAULT\...\ATConfig\osk`.
3. Το **SYSTEM** `osk.exe` αντιγράφει το `HKU\.DEFAULT\...\ATConfig\osk` πίσω στο `HKLM\...\Session<session id>\ATConfig\osk`.

Αν το session HKLM subtree είναι εγγράψιμο από τον χρήστη, τα βήματα 2/3 παρέχουν ένα SYSTEM write μέσω μιας τοποθεσίας που μπορεί να αντικαταστήσει ο χρήστης.<sup>[[1]](#references)</sup>

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Αντικαταστήστε το user-writable per-session key με ένα **registry symbolic link** που δείχνει σε έναν destination που επιλέγει ο attacker. Όταν πραγματοποιηθεί το SYSTEM copy, ακολουθεί το link και γράφει τιμές που ελέγχει ο attacker στο arbitrary target key.

Βασική ιδέα:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Ο attacker αντικαθιστά αυτό το key με ένα **registry link** προς οποιοδήποτε άλλο key.
- Το SYSTEM εκτελεί το copy και γράφει στο key που επέλεξε ο attacker με SYSTEM permissions.

Αυτό παρέχει ένα **arbitrary SYSTEM registry write** primitive.<sup>[[1]](#references)</sup>

## Winning the Race Window with Oplocks

Υπάρχει ένα σύντομο timing window μεταξύ της εκκίνησης του **SYSTEM `osk.exe`** και της εγγραφής του per-session key. Για να γίνει αξιόπιστο, το exploit τοποθετεί ένα **oplock** στο:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Όταν ενεργοποιείται το oplock, ο attacker αντικαθιστά το HKLM key ανά session με ένα registry link, αφήνει την εγγραφή του SYSTEM να ολοκληρωθεί και στη συνέχεια αφαιρεί το link.<sup>[[1]](#references)</sup>

## Παράδειγμα ροής Exploitation (Υψηλού επιπέδου)

1. Λάβετε το τρέχον **session ID** από το access token.
2. Εκκινήστε ένα hidden instance του `osk.exe` και περιμένετε λίγο (ώστε να διασφαλίσετε ότι θα ενεργοποιηθεί το oplock).
3. Εγγράψτε τιμές ελεγχόμενες από τον attacker στο:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Ορίστε ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Ενεργοποιήστε το **Secure Desktop** (`LockWorkstation()`), προκαλώντας την εκκίνηση των `atbroker.exe` / `osk.exe` ως SYSTEM.
6. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το `HKLM\...\Session<session id>\ATConfig\osk` με ένα **registry link** προς έναν αυθαίρετο προορισμό.
7. Περιμένετε λίγο ώστε να ολοκληρωθεί η αντιγραφή του SYSTEM και, στη συνέχεια, αφαιρέστε το link.<sup>[[1]](#references)</sup>

## Μετατροπή του Primitive σε Εκτέλεση SYSTEM

Μία απλή chain είναι η αντικατάσταση μιας τιμής **service configuration** (π.χ. `ImagePath`) και, στη συνέχεια, η εκκίνηση του service. Το RegPwn PoC αντικαθιστά το `ImagePath` του **`msiserver`** και το ενεργοποιεί μέσω instantiation του **MSI COM object**, με αποτέλεσμα την εκτέλεση κώδικα ως **SYSTEM**.<sup>[[1]](#references)[[2]](#references)</sup>

## Σχετικά

Για άλλες συμπεριφορές του Secure Desktop / UIAccess, δείτε:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Αναφορές

- [1] [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [2] [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
