# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν **SMB client support για εναλλακτικές TCP ports**. Αυτή η δυνατότητα μπορεί να γίνει αντικείμενο κατάχρησης, ώστε η **local NTLM authentication** να μετατραπεί σε **SYSTEM local privilege escalation**, όταν ο attacker μπορεί:<sup>[[1]](#references)</sup>

1. Να ανοίξει μια SMB connection σε listener που ελέγχει ο attacker, σε **non-445 port**
2. Να διατηρήσει ενεργή αυτή την TCP connection
3. Να εξαναγκάσει έναν **privileged local client** να προσπελάσει το **ίδιο SMB share path**
4. Να κάνει relay την resulting **local NTLM authentication** πίσω στην πραγματική SMB service του μηχανήματος

Αυτό είναι το primitive πίσω από το **CVE-2026-24294**, το οποίο διορθώθηκε τον **March 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Γιατί λειτουργεί

Το παλαιότερο CMTI / serialized-SPN reflection trick καλύπτεται εδώ:

{{#ref}}
../ntlm/README.md
{{#endref}}

Αυτή η νεότερη variant **δεν** χρειάζεται marshalled hostname. Αντίθετα, κάνει abuse δύο συμπεριφορών του SMB client:<sup>[[1]](#references)</sup>

- **Alternative port support** στα **Windows 11 24H2** και **Windows Server 2025**, διαθέσιμο στους users με `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, όπου πολλαπλές authenticated sessions μπορούν να χρησιμοποιούν την ίδια TCP connection

Αυτό σημαίνει ότι ένας low-privileged user μπορεί πρώτα να δημιουργήσει μια TCP connection από τον SMB client σε έναν attacker SMB server σε high port και στη συνέχεια να εξαναγκάσει μια privileged service να προσπελάσει το **ακριβώς ίδιο UNC path**. Αν τα Windows αποφασίσουν να επαναχρησιμοποιήσουν την υπάρχουσα TCP connection, το privileged NTLM exchange αποστέλλεται μέσω του attacker-controlled transport και μπορεί να γίνει relay στον local SMB server.<sup>[[1]](#references)</sup>

## Προαπαιτούμενα

- Το target υποστηρίζει SMB alternative ports:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** ή νεότερο
- **Windows Server 2025** ή νεότερο
- Ο attacker μπορεί να εκτελέσει έναν local ή remote SMB server σε επιλεγμένο high port
- Ο attacker μπορεί να εξαναγκάσει μια privileged service να προσπελάσει ένα UNC path
- Η privileged authentication πρέπει να είναι **NTLM local authentication**
- Το target πρέπει να είναι relayable:<sup>[[1]](#references)</sup>
- Η Synacktiv ανέφερε ότι λειτουργούσε by default σε **Windows Server 2025**
- Το chain τους **δεν** λειτουργούσε σε **Windows 11 24H2**, επειδή το outbound SMB signing επιβάλλεται εκεί by default

## Userland και internals

Από τη γραμμή εντολών, η δυνατότητα φαίνεται απλή:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Προγραμματιστικά, ο client χρησιμοποιεί το `WNetAddConnection4W` με undocumented δεδομένα `lpUseOptions`. Η σχετική επιλογή είναι το `TraP` (transport parameters), το οποίο τελικά φτάνει στον kernel SMB client μέσω ενός FSCTL και αναλύεται από το `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Σημαντικές πρακτικές σημειώσεις:<sup>[[1]](#references)</sup>

- **Η σύνταξη UNC εξακολουθεί να μην έχει πεδίο port**
- Το **`net use` είναι ανά logon session**
- Το bypass εξακολουθεί να λειτουργεί επειδή **η TCP connection και το SMB session είναι ξεχωριστά objects**
- Η επαναχρησιμοποίηση του **ίδιου share path** είναι υποχρεωτική, εάν το exploit βασίζεται στην επαναχρησιμοποίηση της TCP connection που δημιουργήθηκε προηγουμένως από τον SMB client

## Ροή exploitation

### 1. Δημιουργία του SMB transport που ελέγχεται από τον attacker

Εκτελέστε έναν SMB server σε μια υψηλή port και κάντε τα Windows να συνδεθούν σε αυτόν:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Ο διακομιστής μπορεί να αποδεχτεί οποιοδήποτε ζεύγος διαπιστευτηρίων ελέγχετε, για παράδειγμα `user:user`. Ο στόχος αυτού του βήματος δεν είναι ακόμη το privilege escalation, αλλά μόνο να κάνετε τον Windows SMB client να ανοίξει και να διατηρήσει μια επαναχρησιμοποιήσιμη TCP connection προς το listener σας.<sup>[[1]](#references)</sup>

### 2. Εξαναγκάστε μια privileged service στο ίδιο UNC path

Χρησιμοποιήστε ένα coercion primitive, όπως το **PetitPotam**, στο **ίδιο** path `\\192.168.56.3\share`. Αν ο coerced client έχει privileges και το target name είναι local (`localhost` ή local IP/host), τα Windows εκτελούν **NTLM local authentication**.

Επειδή η TCP connection επαναχρησιμοποιείται, αυτό το privileged NTLM exchange μεταφέρεται στην SMB service του attacker αντί απευθείας στον πραγματικό local SMB server.<sup>[[1]](#references)</sup>

### 3. Κάντε relay το privileged authentication πίσω στο local SMB

Η SMB service που ελέγχεται από τον attacker προωθεί το privileged NTLM exchange στο `ntlmrelayx.py`, το οποίο κάνει relay στο πραγματικό SMB listener του μηχανήματος και αποκτά session ως `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Typical tooling από το public writeup:<sup>[[1]](#references)</sup>

- `smbserver.py` σε custom port για να λάβει το privileged auth μέσω της επαναχρησιμοποιούμενης TCP connection
- `ntlmrelayx.py` για να κάνει relay το captured NTLM στο local SMB
- `PetitPotam.exe` ή άλλο coercion primitive για να εξαναγκάσει το privileged authentication

## Σημειώσεις για τον operator

- Αυτή είναι τεχνική **local privilege escalation**, όχι generic remote relay trick<sup>[[1]](#references)</sup>
- Η SMB service που ελέγχεται από τον attacker πρέπει να χειριστεί το privileged authentication στην **ίδια TCP connection** που χρησιμοποιήθηκε αρχικά για το share mount<sup>[[1]](#references)</sup>
- Αν το coerced access φτάσει σε **διαφορετικό share path**, τα Windows ενδέχεται να δημιουργήσουν διαφορετική connection και η αλυσίδα να διακοπεί<sup>[[1]](#references)</sup>
- Οι απαιτήσεις για SMB signing μπορούν να ακυρώσουν το relay, ακόμη και όταν το arbitrary-port step λειτουργεί<sup>[[1]](#references)</sup>
- Αν διαθέτετε μόνο Kerberos material ή δεν μπορείτε να εξαναγκάσετε local NTLM, αυτή η συγκεκριμένη variant δεν επαρκεί<sup>[[1]](#references)</sup>

## Detection και hardening

- Εγκαταστήστε το patch για το **CVE-2026-24294** από το **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Παρακολουθείτε χρήσεις των `net use` ή `New-SmbMapping` με **non-default SMB ports**<sup>[[1]](#references)</sup>
- Δημιουργήστε alert για ασυνήθιστο outbound SMB από workstations ή servers προς **high TCP ports**<sup>[[1]](#references)</sup>
- Ελέγξτε coercion opportunities, όπως triggers τύπου **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Επιβάλετε SMB signing όπου είναι δυνατό· η Synacktiv σημειώνει συγκεκριμένα ότι αυτό μπλόκαρε το relay τους στα Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
