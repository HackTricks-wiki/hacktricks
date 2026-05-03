# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Recent Windows builds introduced **SMB client support for alternative TCP ports**. That feature can be abused to turn **local NTLM authentication** into a **SYSTEM local privilege escalation** when the attacker can:

1. Open an SMB connection to an attacker-controlled listener on a **non-445 port**
2. Keep that TCP connection alive
3. Coerce a **privileged local client** to access the **same SMB share path**
4. Relay the resulting **local NTLM authentication** back to the machine's real SMB service

Αυτό είναι το primitive πίσω από το **CVE-2026-24294**, patched in **March 2026**.

## Why it works

The older CMTI / serialized-SPN reflection trick is covered here:

{{#ref}}
../ntlm/README.md
{{#endref}}

Αυτή η νεότερη παραλλαγή δεν χρειάζεται marshalled hostname. Αντίθετα, εκμεταλλεύεται δύο SMB client behaviours:

- **Alternative port support** on **Windows 11 24H2** and **Windows Server 2025**, exposed to users with `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, where multiple authenticated sessions can ride the same TCP connection

Αυτό σημαίνει ότι ένας low-privileged user μπορεί πρώτα να δημιουργήσει μια TCP connection από τον SMB client προς έναν attacker SMB server σε υψηλή πόρτα, και μετά να coerce ένα privileged service να προσπελάσει το **exact same UNC path**. Αν το Windows αποφασίσει να επαναχρησιμοποιήσει την υπάρχουσα TCP connection, το privileged NTLM exchange αποστέλλεται μέσω του attacker-controlled transport και μπορεί να relayed στο local SMB server.

## Preconditions

- Target supports SMB alternative ports:
- **Windows 11 24H2** or later
- **Windows Server 2025** or later
- Ο attacker μπορεί να τρέξει έναν local ή remote SMB server σε επιλεγμένη high port
- Ο attacker μπορεί να coerce ένα privileged service να προσπελάσει ένα UNC path
- Η privileged authentication πρέπει να είναι **NTLM local authentication**
- Το target πρέπει να είναι relayable:
- Synacktiv reported it worked by default on **Windows Server 2025**
- Their chain did **not** work on **Windows 11 24H2** because outbound SMB signing is enforced there by default

## Userland and internals

From the command line the feature looks simple:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Προγραμματιστικά, ο client χρησιμοποιεί το `WNetAddConnection4W` με undocumented `lpUseOptions` data. Η σχετική option είναι το `TraP` (transport parameters), το οποίο τελικά φτάνει στον kernel SMB client μέσω ενός FSCTL και γίνεται parsed από το `mrxsmb`.

Σημαντικές πρακτικές σημειώσεις:

- **Η σύνταξη UNC εξακολουθεί να μην έχει port field**
- **Το `net use` είναι ανά logon session**
- Το bypass εξακολουθεί να λειτουργεί επειδή **η TCP connection και η SMB session είναι separate objects**
- Η επαναχρησιμοποίηση του **ίδιου share path** είναι υποχρεωτική αν το exploit εξαρτάται από το ότι ο SMB client θα επαναχρησιμοποιήσει την προηγουμένως δημιουργημένη TCP connection

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Ο server μπορεί να δεχτεί οποιοδήποτε credential pair ελέγχεις, για παράδειγμα `user:user`. Ο στόχος αυτού του βήματος δεν είναι ακόμη το privilege escalation, αλλά μόνο να κάνεις τον Windows SMB client να ανοίξει και να διατηρήσει μια επαναχρησιμοποιήσιμη TCP connection προς τον listener σου.

### 2. Coerce μια privileged service στο ίδιο UNC path

Χρησιμοποίησε ένα coercion primitive όπως το **PetitPotam** απέναντι στο **ίδιο** `\\192.168.56.3\share` path. Αν ο coerced client είναι privileged και το target name είναι local (`localhost` ή local IP/host), τα Windows πραγματοποιούν **NTLM local authentication**.

Επειδή η TCP connection επαναχρησιμοποιείται, αυτό το privileged NTLM exchange μεταφέρεται στο attacker SMB service αντί να πάει απευθείας στον πραγματικό local SMB server.

### 3. Relay το privileged authentication πίσω στο local SMB

Το attacker-controlled SMB service προωθεί το privileged NTLM exchange στο `ntlmrelayx.py`, το οποίο το relays στο πραγματικό SMB listener του μηχανήματος και αποκτά session ως `NT AUTHORITY\SYSTEM`.

Τυπικά εργαλεία από το δημόσιο writeup:

- `smbserver.py` σε custom port για να λάβει το privileged auth μέσω της επαναχρησιμοποιούμενης TCP connection
- `ntlmrelayx.py` για να relay το captured NTLM στο local SMB
- `PetitPotam.exe` ή άλλο coercion primitive για να εξαναγκάσει το privileged authentication

## Σημειώσεις operator

- Αυτή είναι μια **local privilege escalation** τεχνική, όχι ένα γενικό remote relay trick
- Το attacker-controlled SMB service πρέπει να χειριστεί το privileged authentication στην **ίδια TCP connection** που χρησιμοποιήθηκε αρχικά για το share mount
- Αν η coerced πρόσβαση χτυπήσει **διαφορετικό share path**, τα Windows μπορεί να δημιουργήσουν διαφορετική connection και η αλυσίδα σπάει
- Οι απαιτήσεις του SMB signing μπορούν να σκοτώσουν το relay ακόμα κι όταν το arbitrary-port βήμα δουλεύει
- Αν έχεις μόνο Kerberos material ή δεν μπορείς να εξαναγκάσεις local NTLM, αυτή η ακριβής παραλλαγή δεν αρκεί

## Detection and hardening

- Κάνε patch το **CVE-2026-24294** από το **March 2026 Patch Tuesday**
- Παρακολούθησε για `net use` ή `New-SmbMapping` που χρησιμοποιούν **non-default SMB ports**
- Ειδοποίησε για ασυνήθιστο outbound SMB από workstations ή servers προς **high TCP ports**
- Έλεγξε opportunies coercion όπως **EFSRPC / PetitPotam-style** triggers
- Εφάρμοσε SMB signing όπου είναι δυνατόν· το Synacktiv σημειώνει συγκεκριμένα ότι αυτό μπλόκαρε το relay τους σε Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
