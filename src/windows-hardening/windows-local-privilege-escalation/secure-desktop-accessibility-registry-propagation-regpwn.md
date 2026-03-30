# Secure Desktop Accessibility Registry Propagation LPE (RegPwn)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Windows Accessibility features αποθηκεύουν τις ρυθμίσεις χρήστη υπό HKCU και τις διαδίδουν σε ανά-συνεδρία τοποθεσίες HKLM. Κατά τη διάρκεια μιας μετάβασης στο **Secure Desktop** (lock screen ή UAC prompt), τα συστατικά του **SYSTEM** ξανα-αντιγράφουν αυτές τις τιμές. Εάν το **per-session HKLM key είναι εγγράψιμο από τον χρήστη**, γίνεται ένας privileged write choke point που μπορεί να ανακατευθυνθεί με **registry symbolic links**, οδηγώντας σε **arbitrary SYSTEM registry write**.

Η τεχνική RegPwn καταχράται αυτήν την αλυσίδα διάδοσης με ένα μικρό race window που σταθεροποιείται μέσω ενός **opportunistic lock (oplock)** σε ένα αρχείο που χρησιμοποιεί το `osk.exe`.

## Registry Propagation Chain (Accessibility -> Secure Desktop)

Παράδειγμα λειτουργίας: **On-Screen Keyboard** (`osk`). Οι σχετικοί χώροι είναι:

- **System-wide feature list**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs`
- **Per-user configuration (user-writable)**:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
- **Per-session HKLM config (created by `winlogon.exe`, user-writable)**:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- **Secure desktop/default user hive (SYSTEM context)**:
- `HKU\.DEFAULT\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`

Διάδοση κατά τη μετάβαση σε secure desktop (απλοποιημένα):

1. Η διεργασία χρήστη `atbroker.exe` αντιγράφει `HKCU\...\ATConfig\osk` στο `HKLM\...\Session<session id>\ATConfig\osk`.
2. Η διεργασία του **SYSTEM** `atbroker.exe` αντιγράφει `HKLM\...\Session<session id>\ATConfig\osk` στο `HKU\.DEFAULT\...\ATConfig\osk`.
3. Η διεργασία του **SYSTEM** `osk.exe` αντιγράφει `HKU\.DEFAULT\...\ATConfig\osk` πίσω στο `HKLM\...\Session<session id>\ATConfig\osk`.

Εάν το subtree του session στο HKLM είναι εγγράψιμο από τον χρήστη, τα βήματα 2/3 παρέχουν μια SYSTEM εγγραφή μέσω μιας τοποθεσίας που ο χρήστης μπορεί να αντικαταστήσει.

## Primitive: Arbitrary SYSTEM Registry Write via Registry Links

Αντικαταστήστε το user-writable per-session key με ένα **registry symbolic link** που δείχνει σε ένα προορισμό της επιλογής του επιτιθέμενου. Όταν γίνει η αντιγραφή από τον **SYSTEM**, ακολουθεί το link και γράφει τιμές υπό έλεγχο του επιτιθέμενου στο αυθαίρετο κλειδί-στόχο.

Κύρια ιδέα:

- Victim write target (user-writable):
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\osk`
- Ο επιτιθέμενος αντικαθιστά αυτό το κλειδί με ένα **registry link** προς οποιοδήποτε άλλο κλειδί.
- Ο **SYSTEM** εκτελεί την αντιγραφή και γράφει στο επιλεγμένο από τον επιτιθέμενο κλειδί με δικαιώματα SYSTEM.

Αυτό οδηγεί σε ένα **arbitrary SYSTEM registry write** primitive.

## Winning the Race Window with Oplocks

Υπάρχει ένα μικρό χρονικό παράθυρο μεταξύ της εκκίνησης του **SYSTEM `osk.exe`** και της εγγραφής στο per-session key. Για να γίνει αξιόπιστο, το exploit τοποθετεί ένα **oplock** σε:
```
C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml
```
Όταν ενεργοποιηθεί το oplock, ο επιτιθέμενος αντικαθιστά το per-session HKLM key με ένα registry link, επιτρέπει στο SYSTEM να γράψει εκεί, και στη συνέχεια αφαιρεί το link.

## Example Exploitation Flow (High Level)

1. Ανάκτησε το τρέχον **session ID** από το access token.
2. Ξεκίνα μια κρυφή `osk.exe` διεργασία και περίμενε λίγο (βεβαιώσου ότι το oplock θα ενεργοποιηθεί).
3. Γράψε τιμές υπό έλεγχο του επιτιθέμενου στο:
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\osk`
4. Θέσε ένα **oplock** πάνω στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`.
5. Προκάλεσε το **Secure Desktop** (`LockWorkstation()`), με αποτέλεσμα το SYSTEM `atbroker.exe` / `osk.exe` να ξεκινήσει.
6. Όταν ενεργοποιηθεί το oplock, αντικατάστησε το `HKLM\...\Session<session id>\ATConfig\osk` με ένα **registry link** προς τυχαίο στόχο.
7. Περίμενε λίγο για να ολοκληρωθεί η αντιγραφή από το SYSTEM, και μετά αφαίρεσε το link.

## Converting the Primitive to SYSTEM Execution

Μια απλή αλυσίδα είναι να αντικαταστήσεις μια τιμή **service configuration** (π.χ. `ImagePath`) και μετά να ξεκινήσεις την υπηρεσία. Το RegPwn PoC αντικαθιστά το `ImagePath` του **`msiserver`** και το ενεργοποιεί με την στιγμιοποίηση του **MSI COM object**, οδηγώντας σε εκτέλεση κώδικα ως **SYSTEM**.

## Related

Για άλλες συμπεριφορές του Secure Desktop / UIAccess, δείτε:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## References

- [RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn PoC](https://github.com/mdsecactivebreach/RegPwn)

{{#include ../../banners/hacktricks-training.md}}
