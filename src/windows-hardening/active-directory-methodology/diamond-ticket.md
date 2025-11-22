# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use. Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

There are two common techniques to detect the use of golden tickets:

- Ψάξτε για TGS-REQs που δεν έχουν αντίστοιχο AS-REQ.
- Ψάξτε για TGTs με παράλογες τιμές, όπως το προεπιλεγμένο 10ετές lifetime του Mimikatz.

A **diamond ticket** is made by **modifying the fields of a legitimate TGT that was issued by a DC**. This is achieved by **requesting** a **TGT**, **decrypting** it with the domain's krbtgt hash, **modifying** the desired fields of the ticket, then **re-encrypting it**. This **overcomes the two aforementioned shortcomings** of a golden ticket because:

- TGS-REQs will have a preceding AS-REQ.
- The TGT was issued by a DC which means it will have all the correct details from the domain's Kerberos policy. Even though these can be accurately forged in a golden ticket, it's more complex and open to mistakes.

### Requirements & workflow

- **Cryptographic material**: the krbtgt AES256 key (preferred) or NTLM hash in order to decrypt and re-sign the TGT.
- **Legitimate TGT blob**: obtained with `/tgtdeleg`, `asktgt`, `s4u`, or by exporting tickets from memory.
- **Context data**: the target user RID, group RIDs/SIDs, and (optionally) LDAP-derived PAC attributes.
- **Service keys** (only if you plan to re-cut service tickets): AES key of the service SPN to be impersonated.

1. Obtain a TGT for any controlled user via AS-REQ (Rubeus `/tgtdeleg` is convenient because it coerces the client to perform the Kerberos GSS-API dance without credentials).
2. Decrypt the returned TGT with the krbtgt key, patch PAC attributes (user, groups, logon info, SIDs, device claims, etc.).
3. Re-encrypt/sign the ticket with the same krbtgt key and inject it into the current logon session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optionally, repeat the process over a service ticket by supplying a valid TGT blob plus the target service key to stay stealthy on the wire.

### Updated Rubeus tradecraft (2024+)

Recent work by Huntress modernized the `diamond` action inside Rubeus by porting the `/ldap` and `/opsec` improvements that previously only existed for golden/silver tickets. `/ldap` now auto-populates accurate PAC attributes straight from AD (user profile, logon hours, sidHistory, domain policies), while `/opsec` makes the AS-REQ/AS-REP flow indistinguishable from a Windows client by performing the two-step pre-auth sequence and enforcing AES-only crypto. This dramatically reduces obvious indicators such as blank device IDs or unrealistic validity windows.
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
.\Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (with optional `/ldapuser` & `/ldappassword`) εκτελεί ερωτήματα σε AD και SYSVOL για να αντικατοπτρίσει τα δεδομένα πολιτικής PAC του στοχευόμενου χρήστη.
- `/opsec` επιβάλλει μια επανάληψη AS-REQ με συμπεριφορά τύπου Windows, μηδενίζοντας noisy flags και περιοριζόμενο στο AES256.
- `/tgtdeleg` σε κρατάει μακριά από το cleartext password ή το NTLM/AES key του θύματος, ενώ εξακολουθεί να επιστρέφει ένα decryptable TGT.

### Επανεπεξεργασία service-ticket

Η ίδια ανανέωση του Rubeus πρόσθεσε τη δυνατότητα να εφαρμοστεί η diamond technique σε TGS blobs. Τροφοδοτώντας το `diamond` με ένα **base64-encoded TGT** (από `asktgt`, `/tgtdeleg`, ή ένα προηγουμένως πλαστογραφημένο TGT), το **service SPN**, και το **service AES key**, μπορείτε να δημιουργήσετε ρεαλιστικά service tickets χωρίς να αγγίξετε το KDC — ουσιαστικά ένα πιο διακριτικό silver ticket.
```powershell
.\Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Αυτή η ροή εργασίας είναι ιδανική όταν έχετε ήδη τον έλεγχο ενός service account key (π.χ., εξαγόμενο με `lsadump::lsa /inject` ή `secretsdump.py`) και θέλετε να κόψετε ένα one-off TGS που ταιριάζει τέλεια με την πολιτική του AD, τις χρονοδιαγραμμίσεις και τα δεδομένα PAC χωρίς να εκδώσετε νέο AS/TGS traffic.

### OPSEC & σημειώσεις ανίχνευσης

- Οι παραδοσιακές hunter heuristics (TGS without AS, decade-long lifetimes) εξακολουθούν να ισχύουν για golden tickets, αλλά τα diamond tickets εμφανίζονται κυρίως όταν το **περιεχόμενο του PAC ή η αντιστοίχιση ομάδων φαίνεται αδύνατη**. Συμπληρώστε κάθε πεδίο PAC (logon hours, user profile paths, device IDs) ώστε οι αυτοματοποιημένες συγκρίσεις να μην σηματοδοτήσουν αμέσως την παραχάραξη.
- **Do not oversubscribe groups/RIDs**. Αν χρειάζεστε μόνο `512` (Domain Admins) και `519` (Enterprise Admins), σταματήστε εκεί και βεβαιωθείτε ότι ο στοχευόμενος λογαριασμός ανήκει λογικά σε αυτές τις ομάδες σε άλλα μέρη του AD. Υπερβολικά `ExtraSids` αποτελούν giveaway.
- Το Security Content project της Splunk διανέμει attack-range telemetry για diamond tickets καθώς και detections όπως *Windows Domain Admin Impersonation Indicator*, το οποίο συσχετίζει ασυνήθιστες ακολουθίες Event ID 4768/4769/4624 και αλλαγές σε PAC group. Η αναπαραγωγή αυτού του dataset (ή η δημιουργία του δικού σας με τις εντολές παραπάνω) βοηθά στην επαλήθευση της κάλυψης SOC για T1558.001, παρέχοντάς σας παράλληλα συγκεκριμένη λογική alert για να δοκιμάσετε την αποφυγή της.

## Αναφορές

- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)

{{#include ../../banners/hacktricks-training.md}}
