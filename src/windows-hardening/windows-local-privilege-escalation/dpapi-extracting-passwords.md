# DPAPI - Εξαγωγή Κωδικών

{{#include ../../banners/hacktricks-training.md}}



## Τι είναι το DPAPI

Η API Προστασίας Δεδομένων (DPAPI) χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για την **συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών**, εκμεταλλευόμενη είτε μυστικά χρήστη είτε μυστικά συστήματος ως σημαντική πηγή εντροπίας. Αυτή η προσέγγιση απλοποιεί την κρυπτογράφηση για τους προγραμματιστές, επιτρέποντάς τους να κρυπτογραφούν δεδομένα χρησιμοποιώντας ένα κλειδί που προέρχεται από τα μυστικά σύνδεσης του χρήστη ή, για την κρυπτογράφηση του συστήματος, τα μυστικά αυθεντικοποίησης του τομέα του συστήματος, αποφεύγοντας έτσι την ανάγκη οι προγραμματιστές να διαχειρίζονται την προστασία του κλειδιού κρυπτογράφησης οι ίδιοι.

### Προστατευμένα Δεδομένα από το DPAPI

Μεταξύ των προσωπικών δεδομένων που προστατεύονται από το DPAPI είναι:

- Κωδικοί πρόσβασης και δεδομένα αυτόματης συμπλήρωσης του Internet Explorer και του Google Chrome
- Κωδικοί πρόσβασης για λογαριασμούς ηλεκτρονικού ταχυδρομείου και εσωτερικούς λογαριασμούς FTP για εφαρμογές όπως το Outlook και το Windows Mail
- Κωδικοί πρόσβασης για κοινόχρηστους φακέλους, πόρους, ασύρματα δίκτυα και Windows Vault, συμπεριλαμβανομένων των κλειδιών κρυπτογράφησης
- Κωδικοί πρόσβασης για απομακρυσμένες συνδέσεις επιφάνειας εργασίας, .NET Passport και ιδιωτικά κλειδιά για διάφορους σκοπούς κρυπτογράφησης και αυθεντικοποίησης
- Κωδικοί πρόσβασης δικτύου που διαχειρίζεται ο Credential Manager και προσωπικά δεδομένα σε εφαρμογές που χρησιμοποιούν το CryptProtectData, όπως το Skype, το MSN messenger και άλλα

## Λίστα Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Credential Files

Τα **αρχεία διαπιστευτηρίων που προστατεύονται** θα μπορούσαν να βρίσκονται σε:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Αποκτήστε πληροφορίες πιστοποίησης χρησιμοποιώντας το mimikatz `dpapi::cred`, στην απάντηση μπορείτε να βρείτε ενδιαφέρουσες πληροφορίες όπως τα κρυπτογραφημένα δεδομένα και το guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Οι κλειδιά DPAPI που χρησιμοποιούνται για την κρυπτογράφηση των RSA κλειδιών του χρήστη αποθηκεύονται στον φάκελο `%APPDATA%\Microsoft\Protect\{SID}`, όπου {SID} είναι ο [**Security Identifier**](https://en.wikipedia.org/wiki/Security_Identifier) **αυτού του χρήστη**. **Το κλειδί DPAPI αποθηκεύεται στο ίδιο αρχείο με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά των χρηστών**. Συνήθως είναι 64 bytes τυχαίων δεδομένων. (Σημειώστε ότι αυτός ο φάκελος είναι προστατευμένος, οπότε δεν μπορείτε να τον καταχωρήσετε χρησιμοποιώντας `dir` από το cmd, αλλά μπορείτε να τον καταχωρήσετε από το PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Αυτό είναι πώς θα φαίνονται μια σειρά από Master Keys ενός χρήστη:

![](<../../images/image (1121).png>)

Συνήθως **κάθε master key είναι ένα κρυπτογραφημένο συμμετρικό κλειδί που μπορεί να αποκρυπτογραφήσει άλλο περιεχόμενο**. Επομένως, **η εξαγωγή** του **κρυπτογραφημένου Master Key** είναι ενδιαφέρουσα προκειμένου να **αποκρυπτογραφήσουμε** αργότερα εκείνο το **άλλο περιεχόμενο** που έχει κρυπτογραφηθεί με αυτό.

### Εξαγωγή master key & αποκρυπτογράφηση

Ελέγξτε την ανάρτηση [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) για ένα παράδειγμα σχετικά με το πώς να εξαγάγετε το master key και να το αποκρυπτογραφήσετε.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) είναι μια C# έκδοση κάποιων λειτουργιών DPAPI από το [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) έργο.

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) είναι ένα εργαλείο που αυτοματοποιεί την εξαγωγή όλων των χρηστών και υπολογιστών από τον κατάλογο LDAP και την εξαγωγή του κλειδιού αντιγράφου ασφαλείας του ελεγκτή τομέα μέσω RPC. Το σενάριο θα επιλύσει στη συνέχεια τη διεύθυνση IP όλων των υπολογιστών και θα εκτελέσει ένα smbclient σε όλους τους υπολογιστές για να ανακτήσει όλα τα DPAPI blobs όλων των χρηστών και να αποκρυπτογραφήσει τα πάντα με το κλειδί αντιγράφου ασφαλείας του τομέα.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Με τη λίστα υπολογιστών που εξήχθη από το LDAP μπορείτε να βρείτε κάθε υποδίκτυο ακόμη και αν δεν τα γνωρίζατε!

"Επειδή τα δικαιώματα Domain Admin δεν είναι αρκετά. Χακάρετε τα όλα."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) μπορεί να εξάγει μυστικά που προστατεύονται από DPAPI αυτόματα.

## Αναφορές

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}
