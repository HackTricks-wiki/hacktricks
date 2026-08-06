# Κλοπή πιστοποιητικών AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύντομη περίληψη των κεφαλαίων σχετικά με την κλοπή από την εξαιρετική έρευνα στο [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Τι μπορώ να κάνω με ένα πιστοποιητικό

Πριν εξετάσουμε πώς να κλέψουμε τα πιστοποιητικά, ακολουθούν ορισμένες πληροφορίες σχετικά με το πώς να βρείτε σε τι είναι χρήσιμο το πιστοποιητικό:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Εξαγωγή πιστοποιητικών με χρήση των Crypto APIs – THEFT1

Σε μια **διαδραστική συνεδρία επιφάνειας εργασίας**, η εξαγωγή ενός πιστοποιητικού χρήστη ή μηχανήματος, μαζί με το ιδιωτικό κλειδί, μπορεί να γίνει εύκολα, ιδιαίτερα αν το **ιδιωτικό κλειδί είναι δυνατό να εξαχθεί**. Αυτό μπορεί να επιτευχθεί μεταβαίνοντας στο πιστοποιητικό στο `certmgr.msc`, κάνοντας δεξί κλικ πάνω του και επιλέγοντας `All Tasks → Export`, ώστε να δημιουργηθεί ένα προστατευμένο με κωδικό πρόσβασης αρχείο .pfx.<sup>[[1]](#references)</sup>

Για μια **προγραμματιστική προσέγγιση**, είναι διαθέσιμα εργαλεία όπως το PowerShell cmdlet `ExportPfxCertificate` ή projects όπως το [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Αυτά χρησιμοποιούν το **Microsoft CryptoAPI** (CAPI) ή το Cryptography API: Next Generation (CNG) για να αλληλεπιδρούν με το certificate store. Αυτά τα APIs παρέχουν ένα εύρος κρυπτογραφικών υπηρεσιών, συμπεριλαμβανομένων όσων απαιτούνται για την αποθήκευση πιστοποιητικών και το authentication.

Ωστόσο, αν ένα ιδιωτικό κλειδί έχει οριστεί ως μη εξαγώγιμο, τόσο το CAPI όσο και το CNG κανονικά θα αποκλείσουν την εξαγωγή τέτοιων πιστοποιητικών. Για την παράκαμψη αυτού του περιορισμού, μπορούν να χρησιμοποιηθούν εργαλεία όπως το **Mimikatz**. Το Mimikatz προσφέρει τις εντολές `crypto::capi` και `crypto::cng` για την τροποποίηση των αντίστοιχων APIs, επιτρέποντας την εξαγωγή ιδιωτικών κλειδιών. Συγκεκριμένα, το `crypto::capi` τροποποιεί το CAPI μέσα στην τρέχουσα διεργασία, ενώ το `crypto::cng` στοχεύει τη μνήμη του **lsass.exe** για τροποποίηση.

## Κλοπή πιστοποιητικών χρήστη μέσω DPAPI – THEFT2

Περισσότερες πληροφορίες σχετικά με το DPAPI:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

Στα Windows, τα **ιδιωτικά κλειδιά των πιστοποιητικών προστατεύονται από το DPAPI**. Είναι σημαντικό να αναγνωριστεί ότι οι **τοποθεσίες αποθήκευσης για τα ιδιωτικά κλειδιά χρηστών και μηχανημάτων** διαφέρουν και ότι οι δομές των αρχείων ποικίλλουν ανάλογα με το cryptographic API που χρησιμοποιείται από το λειτουργικό σύστημα. Το **SharpDPAPI** είναι ένα εργαλείο που μπορεί να χειριστεί αυτόματα αυτές τις διαφορές κατά την αποκρυπτογράφηση των DPAPI blobs.<sup>[[1]](#references)</sup>

Τα **πιστοποιητικά χρήστη** αποθηκεύονται κυρίως στο registry, στη θέση `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, αλλά ορισμένα μπορούν επίσης να βρεθούν στον κατάλογο `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Τα αντίστοιχα **ιδιωτικά κλειδιά** αυτών των πιστοποιητικών αποθηκεύονται συνήθως στη θέση `%APPDATA%\Microsoft\Crypto\RSA\User SID\` για κλειδιά **CAPI** και στη θέση `%APPDATA%\Microsoft\Crypto\Keys\` για κλειδιά **CNG**.

Για την **εξαγωγή ενός πιστοποιητικού και του σχετιζόμενου ιδιωτικού κλειδιού**, η διαδικασία περιλαμβάνει:

1. **Επιλογή του πιστοποιητικού-στόχου** από το store του χρήστη και ανάκτηση του ονόματος του key store.
2. **Εντοπισμό του απαιτούμενου DPAPI masterkey** για την αποκρυπτογράφηση του αντίστοιχου ιδιωτικού κλειδιού.
3. **Αποκρυπτογράφηση του ιδιωτικού κλειδιού** με τη χρήση του plaintext DPAPI masterkey.

Για την **απόκτηση του plaintext DPAPI masterkey**, μπορούν να χρησιμοποιηθούν οι ακόλουθες προσεγγίσεις:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Για την απλοποίηση της αποκρυπτογράφησης αρχείων masterkey και αρχείων ιδιωτικών κλειδιών, η εντολή `certificates` από το [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) είναι χρήσιμη. Δέχεται τα `/pvk`, `/mkfile`, `/password` ή `{GUID}:KEY` ως ορίσματα για την αποκρυπτογράφηση των ιδιωτικών κλειδιών και των συνδεδεμένων πιστοποιητικών, δημιουργώντας στη συνέχεια ένα αρχείο `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Κλοπή Πιστοποιητικών Μηχανήματος μέσω DPAPI – THEFT3

Τα πιστοποιητικά μηχανήματος που αποθηκεύονται από τα Windows στο registry στη διαδρομή `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` και τα αντίστοιχα private keys που βρίσκονται στις `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (για CAPI) και `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (για CNG) είναι κρυπτογραφημένα με τη χρήση των DPAPI master keys του μηχανήματος. Αυτά τα keys δεν μπορούν να αποκρυπτογραφηθούν με το DPAPI backup key του domain. Αντίθετα, απαιτείται το **DPAPI_SYSTEM LSA secret**, στο οποίο έχει πρόσβαση μόνο ο χρήστης SYSTEM.<sup>[[1]](#references)</sup>

Η χειροκίνητη αποκρυπτογράφηση μπορεί να επιτευχθεί με την εκτέλεση της εντολής `lsadump::secrets` στο **Mimikatz**, ώστε να εξαχθεί το DPAPI_SYSTEM LSA secret, και στη συνέχεια με τη χρήση αυτού του key για την αποκρυπτογράφηση των machine masterkeys. Εναλλακτικά, μπορεί να χρησιμοποιηθεί η εντολή `crypto::certificates /export /systemstore:LOCAL_MACHINE` του Mimikatz μετά το patching των CAPI/CNG, όπως περιγράφηκε προηγουμένως.

Το **SharpDPAPI** προσφέρει μια πιο αυτοματοποιημένη προσέγγιση μέσω της εντολής certificates. Όταν χρησιμοποιείται το flag `/machine` με elevated permissions, κάνει escalation σε SYSTEM, πραγματοποιεί dump του DPAPI_SYSTEM LSA secret, το χρησιμοποιεί για να αποκρυπτογραφήσει τα machine DPAPI masterkeys και, στη συνέχεια, χρησιμοποιεί αυτά τα plaintext keys ως lookup table για να αποκρυπτογραφήσει οποιαδήποτε private keys πιστοποιητικών μηχανήματος.

## Εύρεση Αρχείων Πιστοποιητικών – THEFT4

Τα πιστοποιητικά εντοπίζονται μερικές φορές απευθείας στο filesystem, όπως σε file shares ή στον φάκελο Downloads. Οι πιο συνηθισμένοι τύποι αρχείων πιστοποιητικών που στοχεύουν περιβάλλοντα Windows είναι τα αρχεία `.pfx` και `.p12`. Αν και λιγότερο συχνά, εμφανίζονται επίσης αρχεία με extensions `.pkcs12` και `.pem`. Άλλα αξιοσημείωτα extensions που σχετίζονται με πιστοποιητικά περιλαμβάνουν:<sup>[[1]](#references)</sup>

- `.key` για private keys,
- `.crt`/`.cer` μόνο για πιστοποιητικά,
- `.csr` για Certificate Signing Requests, τα οποία δεν περιέχουν πιστοποιητικά ή private keys,
- `.jks`/`.keystore`/`.keys` για Java Keystores, τα οποία ενδέχεται να περιέχουν πιστοποιητικά μαζί με private keys που χρησιμοποιούνται από Java applications.

Η αναζήτηση αυτών των αρχείων μπορεί να γίνει μέσω PowerShell ή του command prompt, με αναζήτηση των προαναφερθέντων extensions.

Σε περίπτωση που εντοπιστεί ένα αρχείο πιστοποιητικού PKCS#12 και προστατεύεται με password, είναι δυνατή η εξαγωγή ενός hash μέσω του `pfx2john.py`, το οποίο είναι διαθέσιμο στο [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Στη συνέχεια, μπορεί να χρησιμοποιηθεί το JohnTheRipper για την προσπάθεια crack του password.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Κλοπή διαπιστευτηρίων NTLM μέσω PKINIT – THEFT5 (UnPAC the hash)

Το παρεχόμενο περιεχόμενο εξηγεί μια μέθοδο κλοπής διαπιστευτηρίων NTLM μέσω PKINIT, συγκεκριμένα μέσω της μεθόδου κλοπής με την ονομασία THEFT5. Ακολουθεί επαναδιατύπωση σε παθητική φωνή, με ανωνυμοποίηση και σύνοψη του περιεχομένου όπου απαιτείται:<sup>[[1]](#references)</sup>

Για την υποστήριξη του NTLM authentication `MS-NLMP` από εφαρμογές που δεν υποστηρίζουν Kerberos authentication, το KDC έχει σχεδιαστεί ώστε να επιστρέφει τη one-way function (OWF) NTLM του χρήστη μέσα στο privilege attribute certificate (PAC), συγκεκριμένα στο buffer `PAC_CREDENTIAL_INFO`, όταν χρησιμοποιείται PKCA. Κατά συνέπεια, εάν ένας λογαριασμός πραγματοποιήσει authentication και εξασφαλίσει ένα Ticket-Granting Ticket (TGT) μέσω PKINIT, παρέχεται εγγενώς ένας μηχανισμός που επιτρέπει στο τρέχον host να εξαγάγει το NTLM hash από το TGT, ώστε να υποστηρίζονται παλαιότερα authentication protocols. Η διαδικασία αυτή περιλαμβάνει την αποκρυπτογράφηση της δομής `PAC_CREDENTIAL_DATA`, η οποία αποτελεί ουσιαστικά μια NDR serialized αναπαράσταση του NTLM plaintext.

Το utility **Kekeo**, διαθέσιμο στη διεύθυνση [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), αναφέρεται ως ικανό να ζητήσει ένα TGT που περιέχει αυτά τα συγκεκριμένα δεδομένα, διευκολύνοντας έτσι την ανάκτηση του NTLM του χρήστη. Η εντολή που χρησιμοποιείται για αυτόν τον σκοπό είναι η εξής:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** μπορεί επίσης να λάβει αυτές τις πληροφορίες με την επιλογή **`asktgt [...] /getcredentials`**.

Επιπλέον, αναφέρεται ότι το Kekeo μπορεί να επεξεργαστεί certificates που προστατεύονται από smartcard, εφόσον είναι δυνατή η ανάκτηση του pin, με σχετική αναφορά στο [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Η ίδια δυνατότητα υποστηρίζεται επίσης από το **Rubeus**, το οποίο είναι διαθέσιμο στο [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Αυτή η εξήγηση συνοψίζει τη διαδικασία και τα εργαλεία που εμπλέκονται στο NTLM credential theft μέσω PKINIT, εστιάζοντας στην ανάκτηση NTLM hashes μέσω TGT που αποκτάται με τη χρήση PKINIT, καθώς και στα utilities που διευκολύνουν αυτήν τη διαδικασία.

## Αναφορές

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
