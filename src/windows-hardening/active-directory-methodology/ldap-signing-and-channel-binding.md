# LDAP Signing ve Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli

LDAP relay/MITM saldırıları, kimliği doğrulanmış bir LDAP context elde etmek için kimlik doğrulamayı bir domain controller'a iletir. [Name-resolution poisoning ve relay genel bakışı](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) daha geniş iş akışını ele alır. Birbiriyle ilişkili iki kontrol bu yolları azaltır:

- **LDAP channel binding (CBT)**, ilgili kimlik doğrulamayı LDAPS tarafından kullanılan TLS server sertifikasına/channel'a bağlayarak kanallar arası relay'i zorlaştırır.
- **LDAP signing**, SASL LDAP bind'leri için bütünlük koruması gerektirir. Gizlilik sağlamaz; LDAP içeriğinin de şifrelenmesi gerekiyorsa TLS kullanın.<sup>[[2]](#references)</sup>

**Hızlı güvenlik durumu kontrolü**: `netexec ldap <dc> -u user -p pass` gibi araçlar, gözlemlenen signing ve channel-binding politikalarını bildirir. `(signing:None)` ve `(channel binding:Never)` eksik kontrolleri gösterir; ancak relay'in başarılı olması yakalanan kimlik doğrulama türüne, EPA davranışına, hesap ayrıcalıklarına, hedef protokole ve relay korumalarına bağlıdır. Relay edilen principal gerekli haklara sahipse, KrbRelayUp gibi araçlar `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğine yazabilir, resource-based constrained delegation (RBCD) yapılandırabilir ve ayrıcalıklı bir principal'ı taklit etmek için ortaya çıkan delegation yolunu kullanabilir.<sup>[[4]](#references)</sup>

**Server 2025 DC'ler**, **LDAP server signing requirements Enforcement** adlı yeni bir GPO sunar. Bu GPO, **Not Configured** olarak bırakıldığında varsayılan olarak **Require Signing** olur. Zorunlu kılınmasını önlemek için bu politikayı açıkça **Disabled** olarak ayarlamanız gerekir.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (yalnızca LDAPS)

- **Gereksinimler**:
  - CVE-2017-8563 yaması (2017), Extended Protection for Authentication desteği ekler.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022), LDAPS CBT için “what-if” telemetrisi ekler.<sup>[[2]](#references)</sup>
- **GPO (DC'ler)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (varsayılan, CBT yok)
  - `When Supported` (kısmi zorlama: CBT destekleyen istemciler geçerli bir token sağlamalıdır; CBT desteği olmayan istemciler yine de bind olabilir ve denetim olayları oluşturulur)
  - `Always` (zorunlu: geçerli CBT olmadan yapılan LDAPS bind'lerini reddeder)<sup>[[1]](#references)</sup>
- **Denetim**: Şunları görmek için **When Supported** olarak ayarlayın:
  - **3074** – Zorlama etkin olsaydı LDAPS bind'i CBT doğrulamasında başarısız olurdu.
  - **3075** – LDAPS bind'i CBT verisi içermiyordu ve zorlama etkin olsaydı reddedilirdi.
  - (Eski derlemelerde **3039** olayı CBT hatalarını göstermeye devam eder.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Zorlama**: LDAPS istemcileri CBT gönderdiğinde **Always** olarak ayarlayın; yalnızca **LDAPS** üzerinde etkilidir (ham 389 üzerinde değil).<sup>[[1]](#references)</sup>

`When Supported` yalnızca denetim modu değildir: CBT destekleyen istemciler için CBT'yi doğrularken CBT desteği olmayan istemcilere izin verir. [Microsoft politika başvurusu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), sürüme bağlı varsayılanları açıklar. LDAP signing, LDAP/389 üzerindeki ilgili bind'ler için geçerlidir; channel binding ise TLS korumalı LDAP kimlik doğrulaması için geçerlidir.


## LDAP Signing

- **İstemci GPO'su**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows'ta varsayılan olan `Negotiate signing` yerine).<sup>[[1]](#references)</sup>
- **DC GPO'su**:
  - Eski: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan `None` değeridir).<sup>[[2]](#references)</sup>
  - **Server 2025**: Eski politikayı `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` olarak ayarlayın (`Not Configured` varsayılan olarak zorlamayı etkinleştirir; önlemek için `Disabled` olarak ayarlayın).<sup>[[1]](#references)</sup>
- **Uyumluluk**: Simple bind veya imzasız SASL bind kullanan Windows dışı cihaz ve uygulamaların envanterini çıkarın. Microsoft, desteği sürdürülen Windows sürümlerindeki desteği belgeler; eski istemcilerle uyumluluk açıklamaları, XP sürümü eşiğine indirgenmek yerine gerçek istemci yığınıyla doğrulanmalıdır.<sup>[[2]](#references)</sup>

## Relay yolları ve imzalı SASL ile yeniden kimlik doğrulama

Yalnızca **signing** zorunluysa, channel binding zorlanmadığı sürece LDAPS'e relay hâlâ çalışabilir: TLS aktarım bütünlüğü sağlar. Yalnızca **channel binding** zorunluysa, düz LDAP'te bağlanılabilecek bir TLS channel yoktur; relay, TCP 389 üzerinden kimlik doğrulayıp ardından TLS gerektiren işlemler için StartTLS kullanabilir; bunun için relay edilen kimliğin gerekli haklara sahip olması gerekir. Her ikisinin de zorunlu kılınması bu bilinen alternatifleri kapatır; ancak yamalanmamış domain controller'larda aşağıdaki açığı durdurmadı.<sup>[[5]](#references)</sup>

### Relay edilmiş bir Bind sonrasında LDAP işlemi ekleme

Etkilenen Windows Server 2016–2025 domain controller'larda, önce TCP 389 üzerinde X kimliğiyle **imzalı bir NTLM SASL LDAP bağlantısı** kurun. Bunun için session key'ini bildiğiniz kimlik bilgilerini (veya kabul edildiği durumlarda anonim bir NTLM SASL context'i) kullanın. Y'yi **SMB üzerinden** relay'e kimlik doğrulaması yapmaya zorlayın. Y'nin NTLM NEGOTIATE mesajını ve DC'nin CHALLENGE mesajını, X'in mevcut LDAP bağlantısındaki GSS-SPNEGO Bind istekleri üzerinden iletin. Windows SMB istemcisi `NTLMSSP_NEGOTIATE_SIGN` ayarını yapar; bu nedenle ortaya çıkan LDAP bind'i imzalı bir SASL katmanı gerektirir. HTTP/WebDAV kaynaklı bir alışverişte genellikle bu bayrak bulunmaz ve bu senaryoda onun yerine kullanılamaz.<sup>[[5]](#references)</sup>

Y, NTLM AUTHENTICATE gönderdiğinde **tek bir uzunluk önekli SASL kaydına iki farklı LDAP mesajı** koyun: bu yanıtı taşıyan bir BindRequest'in ardından bir ModifyRequest. Kaydın tamamını X'in bilinen anahtarıyla imzalayın. Savunmasız DC, kaydı X altında doğrular, Bind'i tamamlayıp bağlantının yetkilendirmesini Y olarak değiştirir ve ardından kalan ModifyRequest'i kaydı Y'nin anahtarıyla yeniden doğrulamadan Y olarak yürütür. Bu işlem Y'nin parolasını veya session key'ini açığa çıkarmaz; X tarafından imzalanan sonraki bir kayıt başarısız olur. `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğine RBCD yazma işlemi veya `msDS-KeyCredentialLink` özniteliğine shadow credential yazma işlemi yine de Y'nin hedef nesne üzerinde izni olmasını gerektirir. Bkz. [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) ve relay edilen bir DC makine hesabı için [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Bu, **düz LDAP** bypass'ıdır; LDAPS channel-binding bypass'ı değildir. LDAPS'te TLS bağlantıyı korur ve Windows, bu kayıt birleştirme yolu için gereken X anahtarlı NTLM SASL signing katmanını kurmaz. TCP 389 kullanılamıyorsa bu teknik doğrudan TCP 636'ya taşınamaz. Ekim 2026 güvenlik güncellemeleri, Bind bağlantı kimliğini değiştirdikten sonra kalan verileri atarak aynı kayıt içindeki işlemi engeller.<sup>[[5]](#references)</sup> KB5126646, Windows Server 2025 güncellemesidir; etkilenen diğer Server sürümlerinin KB numaraları farklıdır.<sup>[[7]](#references)</sup>

Araştırmacının [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) aracı, bu iş akışı için değiştirilmiş bir `ntlmrelayx.py` kullanır. **SMB** tabanlı bir coercion kaynağı, LDAP signing/security-context API'lerini sunan sabitlenmiş bir Impacket ağacı (PyPI Impacket 0.13.1 yetersizdir) ve ilk imzalı bind için saldırganın kontrolündeki bir hesap gerekir. RBCD yazma işlemi için kurban nesnenin DN'ini ve kontrol edilen bir delegating computer'ın SID'ini sağlayın; izin verilen başka bir yazma işlemi için `-attribute` ile birlikte `-value` veya `-value-hex` kullanın. Relay tarafındaki `FAILED` mesajını ModifyRequest'in başarısız olduğunun kanıtı saymak yerine, aracın bağımsız imzalı read-back doğrulamasını kontrol edin.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

SMB kimlik doğrulamasını ayrıca tetikleyin; bir coercion yüzeyi için [privileged NTLM authentication'ı zorlama](printers-spooler-service-abuse.md), diğerleri içinse [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) sayfasına bakın. Aracın komutu ve uygulaması deposunda belgelenmiştir.<sup>[[6]](#references)</sup>

## Denetim öncelikli dağıtım (önerilen süre ~30 gün)

1. İmzasız bind'leri günlüğe kaydetmek için her DC'de LDAP arayüz tanılamasını etkinleştirin (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. DC GPO `LDAP server channel binding token requirements` değerini kısmi CBT enforcement ve telemetri için **When Supported** olarak ayarlayın; önce eski istemcilerle uyumluluğu doğrulayın.<sup>[[1]](#references)</sup>
3. Directory Service olaylarını izleyin:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – imzasız/imzaya izin verilen bind'ler (imzalama gerekliliklerine uyumsuz).
   - **3074/3075** – başarısız olacak veya CBT'yi içermeyecek LDAPS bind'leri (2019/2022'de KB4520412 ve yukarıdaki 2. adım gerekir).
4. Ayrı değişikliklerle enforcement uygulayın:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC'lerde).
   - `LDAP client signing requirements` = **Require signing** (istemcilerde).
   - `LDAP server signing requirements` = **Require signing** (DC'lerde) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding ve LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding ve signing gereklilikleri](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay azaltma güncelleştirmesi](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing devre dışı → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signed, Sealed, and Relayed, NTLM tarzı](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo proof of concept](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server sürüm bilgileri](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
