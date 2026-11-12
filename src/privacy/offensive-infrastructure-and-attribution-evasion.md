# Saldırgan Altyapısı ve Atıfı Engelleme

{{#include ../banners/hacktricks-training.md}}

Bir operatör, tek bir proxy kullanarak nadiren anlamlı bir anonimlik elde eder. Gerçek kampanyalar bir **ayrıştırma grafiği** oluşturur: operatör bir erişim düğümüne ulaşır, geçiş düğümleri bu düğümü çıkış noktasından gizler, redirector'lar gerçek C2'yi korur ve tek kullanımlık adlar herkese açık kenar noktasına yönlendirilir.

Her yolun standartlaştırılmış avantajlar/dezavantajlar/dağıtım/tespit görünümü için [Anonim İnternet Erişimi Teknikleri Kataloğu](anonymous-internet-access-techniques.md)'nu kullanın. Bu sayfa, saldırgan altyapı bileşiminin ayrıntılarını ele alır.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Hedefin gördüğü son adres, bu nedenle klavyeyi kimin kontrol ettiğinin kanıtı değil, izlenen yolun göstergesidir. MITRE, temel bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) olarak eşleştirir.<sup>[[1]](#references)</sup>

## Altyapı sınıfları

| Sınıf | Bir aktör bunu neden kullanır | Kalıcı maruziyet | Savunmacının en iyi pivot noktası |
|---|---|---|---|
| Kiralık VPS/cloud | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden kurması kolay | Kiracı, faturalandırma, konsol, kaynak oturum açma ve image geçmişi | Hesap/control-plane olayları ve yinelenen sunucu parmak izi |
| Ticari VPN/Tor | Büyük, paylaşımlı çıkış kümesi; sunucu yönetimi gerektirmez | Sağlayıcı/gözetim görünürlüğü ve uçtan uca zamanlama | Hedef davranışı, uç nokta kanıtları ve akış korelasyonu |
| Konut tipi/mobil proxy | Tüketici ASN'si ve coğrafi açıdan makul görünüm | Aracı/müşteri kayıtları; proxyware veya ele geçirilmiş ana makine davranışı | Olanaksız seyahat, proxy protokolleri ve oturum başına adres değişimi |
| Ele geçirilmiş sunucu/yönlendirici/IoT | Kurbanın itibarını ve yargı alanını ödünç alır | Implant, yönetim akışı ve yinelenen üst akış denetleyicisi | Tek bir çıkış IP'si yerine cihaz telemetrisi ve ORB topolojisi |
| CDN/redirector | Genel edge'i arka uç C2'den ayırır | TLS/HTTP sözdizimi, sertifika, yönlendirme ve cloud-account kalıntıları | Edge-origin korelasyonu ve istek biçimi kümelendirmesi |
| Meşru web hizmeti | İzin verilen GitHub/cloud/sosyal medya trafiğine karışır | API token'ı, tenant/nesne tanımlayıcıları ve olağandışı süreç ilişkisi | Uç nokta süreci ve hizmet/API anlambilimi |
| Fiziksel/hücresel/uydu yolu | Görünürdeki fiziksel kaynağı değiştirir | RF, operatör, abone, cihaz ve konum kayıtları | Birleşik radyo/fiziksel ve ağ kanıtları |

## Operasyonel relay box ağları

Bir **ORB ağı**, ara hizmet olarak kullanılan, yönetilen bir proxy filosudur. Mandiant bunları kiralanmış sunuculardan oluşan tedarik edilmiş ağlar, ele geçirilmiş yönlendirici/IoT cihazlarından oluşan tedarik edilmemiş ağlar ve hibritler olarak sınıflandırır. Olgun bir topolojide dört mantıksal rol bulunur:<sup>[[2]](#references)</sup>

1. **Yönetim sunucusu (ACOS):** Envanteri, kimlik bilgilerini, durumu ve yönlendirme politikasını tutar.
2. **Erişim/relay düğümü:** Müşterilerin veya operatörlerin kimliğini doğrular; değişen mesh'e açılan kararlı giriş noktasıdır.
3. **Geçiş düğümleri:** Bir veya daha fazla kiralık ya da ele geçirilmiş sistem, şeffaf olmayan bağlantıları aktarır.
4. **Çıkış/evreleme düğümü:** Keşif, exploitation veya C2 hedeflerine son kaynak adresini sunar.

Mesh, çıkışları ülkeye, ASN'ye, gecikmeye veya kullanılabilirliğe göre seçebilir ve sağlıksız düğümleri değiştirebilir. Birden fazla tehdit grubu aynı ağı kiralayabilir. Mandiant, bazı ORB'lerle ilişkili bir IPv4 adresinin yalnızca 31 gün boyunca kullanıldığını gözlemledi; bu nedenle eskimiş IP listelerini engellemek yerine **ağı, zaman içinde değişen ve aktöre benzeyen bir varlık olarak** ele almayı öneriyor.<sup>[[2]](#references)</sup>

### Bunun sağladıkları ve sızdırdıkları

- Hedef, coğrafi olarak yakında ve görünüşte konut tipi olabilecek bir çıkış görür.
- Çıkış, hedefi ve bir önceki hop'u görür; operatörü görmeyebilir.
- Erişim hizmeti müşteriyi ve rota isteğini görür. Bağımsız olarak yönetilen bir mesh, müşteriyi çıkışlardan ayrı tutabilir; ancak güçlü bir karşı taraf kaydı oluşturur.
- IP'ler değişse bile yinelenen portlar, handshake sırası, sunucu başlıkları, sertifikalar, çalışma süreleri ve denetleyici ilişkileri filoyu açığa çıkarabilir.
- Ele geçirilmiş bir yönlendiricide genellikle uç nokta telemetrisi bulunmaz; ancak ISP'sinde abone ve akış verileri vardır. El koyma, implant/yapılandırma kalıntılarını ortaya çıkarır.

{% hint style="info" %}
Yetkili bir çalışma için topolojiyi kuruluşa ait VM'ler veya yönlendiricilerle yeniden oluşturun ve denetleyicinin atıf eşlemesini saklayın. Açık proxy'leri veya üçüncü taraf cihazları ağa dahil etmeyin. [Lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir aracıya zarar vermeden savunmacının görebileceği aynı hop yapısını oluşturur.
{% endhint %}

## Konut tipi ve mobil proxy ağları

Konut tipi proxy hizmetleri oturumları tüketici geniş bant adreslerine atar; mobil proxy'ler ise operatör NAT havuzları üzerinden çıkış yapar. Kaynaklar açıkça kaydolan cihazlardan, tüketici uygulamalarına eklenen SDK/proxyware'den, satıcılardan veya malware'den gelebilir. Bu kaynaklar birbirine denk değildir: bilgilendirilmiş rıza olmaması, bir gizlilik hizmetini ele geçirilmiş altyapıya dönüştürür.

Döndürme modları tespiti etkiler:

- **istek başına döndürme**, üst katman kimliği sabit kalırken IP ve ASN/coğrafya tutarsızlıklarının hızla ortaya çıkmasına neden olur;
- **yapışkan oturumlar**, bir çıkışı dakikalarca veya saatlerce koruyarak sıradan bir aboneye benzer;
- **backconnect gateway'leri**, müşteriye tek bir aracı uç noktası gösterir ve çıkışları içeride seçer;
- **mobil havuzlar**, çok sayıda gerçek aboneyi az sayıda operatör NAT adresinin arkasına yerleştirerek IP engellemesini maliyetli kılar.

Savunmacılar IP'yi kimliği doğrulanmış oturum, TLS/istemci parmak izi, HTTP sıralaması, cihaz çerezi ve davranışla ilişkilendirmelidir. Üst katman özelliklerinin tümü aynı kalırken sözde yerel bir konut tipi oturum açma işleminin ardından başka bir ülkeden oturum açılması, tek başına itibardan daha güçlü bir göstergedir. Buna karşılık adres paylaşımı ve mobil geçiş meşru değişimlere yol açar; bu nedenle konut tipi/proxy sınıflandırmasını asla tek başına hüküm olarak değerlendirmeyin.

### Proxyware control plane'leri ve satıcı örtüşmesi

Konut tipi bir havuzu düz bir çıkış listesi olarak modellemeyin. IPIDEA ekosisteminin analizi, yeniden kullanılabilir **iki katmanlı bir control plane** ortaya çıkardı: gömülü bir SDK önce cihaz/kayıt metaverisini Tier One alan adına bildirir ve Tier Two `connect`/`proxy` IP:port çiftleriyle birlikte zamanlama bilgisi alır. Düğüm, kodlanmış bir görev için Tier Two connect portunu düzenli olarak sorgular, eşleştirilmiş proxy portuna ikinci bir bağlantı açar ve sağlanan baytları istenen hedefe aktarır. Görünüşte farklı SDK'lar ve proxy markaları ayrı keşif alan adlarına sahipti; ancak ortak sahiplik ve satıcı ilişkileri nedeniyle paylaşılan Tier Two altyapısında ve örtüşen çıkış havuzlarında birleşiyordu.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Bu, residential IP bloğundan daha dayanıklı hunting pivot'leri sağlar:<sup>[[13]](#references)</sup>

- beklenmedik bir yardımcı program, VPN, oyun veya gömülü cihaz süreci sabit bir cihaz kimliği/müşteri anahtarı gönderir ve değişen bir sunucu listesi alır;
- uç nokta, alışılmadık bir porttaki doğrudan IP'yi yoklar, ardından yeni bir hedef soketi açmadan hemen önce aynı adresteki başka bir porta bağlanır;
- görünüşte farklı olan birkaç marka, Tier Two adreslerini, protokol dilbilgisini, SDK kodunu veya çıkış düğümü çakışmasını paylaşır;
- farklı Tier One alan adlarıyla iletişim kuran farklı uygulamalar, aynı Tier Two havuzundan adresler alır.

Bu çakışma, atıf yapmayı da sınırlar: Bir IP'yi tek bir vendor'ın ilan ettiği havuzda görmek, ilgili zamanda bu IP'yi hangi reseller'ın, müşterinin veya threat actor'ın kullandığını kanıtlamaz. Akış zaman damgalarını, süreç soy ağacını, Tier One yanıt gövdelerini ve Tier Two görev tanımlayıcılarını koruyun.<sup>[[13]](#references)</sup> Yetkili bir çalışmada bu hiyerarşiyi yalnızca kuruluşun sahip olduğu uç noktalarla taklit edin; tüketici cihazlarını veya üçüncü taraf proxyware'i asla ağa dahil etmeyin.

## Çok atlamalı proxy zincirleri

MITRE, external proxy'leri **multi-hop proxies (T1090.003)**'ten ayırır. Önemli olan atlama sayısı değil, bilgi ve yönetim sorumluluğunun ayrılmasıdır.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Bir taraf hem A'yı hem B'yi işletiyorsa paylaşılan loglar veya trafik zamanlaması, devreyi yeniden kurmayı mümkün kılabilir. Aynı uç nokta/hesaptan art arda ticari VPN'ler eklemek, ortak kimlik, ödeme ve zamanlama kanıtlarını ortadan kaldırmadan gecikmeyi artırabilir. Tor, bağımsız olarak seçilen relay'ler ve ortak bir istemci tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli etkileşimli bir ağ, her iki ucu da ölçen bir gözlemciye karşı dayanıklılık vaat edemez.

Yaygın hatalar arasında DNS veya IPv6 sızıntısı, uygulamaların kendi soketlerini açması, yönetim trafiğinin doğrudan relay'lere ulaşması, eşzamanlı etkinlik, yeniden kullanılan SSH anahtarları ve kimliği açığa çıkaran hesaplarda oturum açılması bulunur. Doğru doğrulama, bir arıza testidir: her relay'i sırayla durdurun ve iş yükünün şifresiz bir yola geri dönemediğini gösterin.

### Tunnel çökmesi ve upstream sızıntısı

Bir relay mimarisi, çoğu zaman arızalandığında en kolay ilişkilendirilebilir hâle gelir. Unit 42, kurbanlara dönük VPS'ler, relay VPS'leri, residential proxy'ler, Tor ve diğer proxy hizmetlerini kullanan çok katmanlı bir casusluk rotasını belgeledi; bir tunnel atlandığında veya çöktüğünde, gizli upstream altyapısı relay ve kurbanlara dönük sistemlere doğrudan bağlandı. Aynı soruşturmada, upstream altyapısında kısa süreliğine açığa çıkan bir X.509 sertifikası da katmanlar arasında pivot noktası olarak kullanıldı.<sup>[[14]](#references)</sup>

**Veri düzlemini** (`victim <-> exit`), **kontrol düzleminden** (`operator/upstream -> relay administration`) ayrı tutun. Yalnızca başarılı C2 oturumlarını değil, sahip olduğunuz her katmandaki gelen bağlantı ve kimlik doğrulama loglarını, sertifika geçmişlerini ve kısa süreli başarısız bağlantıları da saklayın. Yalnızca relay kesintileri sırasında görünen veya birden fazla kurbanlara dönük düğümü doğrudan yöneten bir kaynak, sıradan bir exit'ten daha güçlü bir upstream adayıdır; ancak ASN/jeolokasyon bilgisi hâlâ bir varsayımdır, operatörün kimliğinin kanıtı değildir.

Yetkili bir laboratuvarda iş yükü fail closed davranacak şekilde ayarlanmalıdır. Bir Linux network namespace içinde yalıtılmış iş yükünde ilk rota tunnel'ı kullanmalıdır; tunnel kaldırıldıktan sonra fiziksel uplink'e yönelmek yerine hem istek hem de rota araması başarısız olmalıdır:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS ve IPv6 için ve her relay sınırında testi tekrarlayın. Herhangi bir probe başarılı olursa, policy routing veya firewall'ı düzeltmeden önce gerçek arayüzü/kaynak adresini kaydedin; bu gözlem, bir araştırmacının göreceği attribution leak'tir.

## Redirector katmanları ve trafik şekillendirme

Bir public **redirector**, operasyona özgü bir gramerle eşleşen trafiği kabul eder ve korunan bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerik sunulabilir.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Birden fazla katman, maruziyeti sınırlar: herkese açık bir domain’i yakmak, team server’ı açığa çıkarmak zorunda değildir. CDN’ler anycast kapasitesi ve itibarlı bir dış domain sağlar; ancak CDN hesabı ve edge logları attribution noktalarına dönüşür. TLS fingerprint’leri, sertifika geçmişleri, ayırt edici yollar/header sıraları, yanıt boyutları, yönlendirme davranışı ve origin allowlist’leri, sözde ilişkisiz front’ları ilişkilendirebilir.

Tespit için normalleştirme öncesinde reverse proxy alanlarını kaydedin; SNI/Host/authority değerlerini karşılaştırın; nadir header kombinasyonlarını inceleyin; yanıt gövdelerini ve TLS fingerprint’lerini kümelendirin; yapılandırma örtüşmesi için cloud/CDN audit loglarını arayın. Yetkili red team’ler, gerçek bir markayı kopyalamaktan veya kimlik bilgisi toplamayı ilgisiz bir üçüncü tarafın arkasına yerleştirmekten kaçınmalıdır.

## Domain fronting ve domainless fronting

Klasik **domain fronting (T1090.004)** yönteminde TLS bağlantısı, SNI’da izin verilen bir front domain’i belirtirken şifrelenmiş HTTP `Host` veya HTTP/2 `:authority`, farklı bir back-end domain’i ister. İş birliği yapan bir CDN, içteki değere göre yönlendirme yapar. TLS şifre çözme imkânı olmayan bir ağ gözlemcisi front’u görür; CDN ise her iki değeri ve origin’i görür. Domainless varyantlarda SNI boş olabilirken, başka bir yönlendirme alanı hedefi seçebilir.<sup>[[4]](#references)</sup>

Bu, sihirli bir taklit yöntemi değildir: yalnızca aracı, bu uyumsuzluğa kasıtlı olarak veya yanlışlıkla izin verirse ve içteki adı nasıl yönlendireceğini biliyorsa çalışır. Büyük sağlayıcılar, hesaplar arası fronting’i kısıtlamıştır. Encrypted ClientHello (ECH), aradaki bir gözlemcinin görebileceklerini değiştirir ancak CDN, endpoint veya uygulama kayıtlarını silmez.

Tespit noktaları şunlardır:

- endpoint süreç soy ağacı ve o uygulama için beklenmeyen hedef;
- TLS incelemesinin yasal ve mümkün olduğu durumlarda SNI ile HTTP authority uyumsuzluğu;
- bir tenant/front’un başka bir authority/origin’e yönlendirme yaptığını gösteren CDN logları;
- normalde etkileşimli olan bir hizmete kurulan alışılmadık, uzun ömürlü veya periyodik oturumlar;
- değişen front domain’leri boyunca sabit kalan şifrelenmiş akış boyutları ve sıklığı.

Güvenli lab, sahip olunan bir reverse proxy üzerinde yönlendirme uyumsuzluğunu simüle eder; herkese açık bir CDN’i kötüye kullanmaz.

## Dinamik çözümleme: DDNS, DGA ve fast flux

Dinamik çözümleme, mantıksal bir hizmeti sabit altyapıdan ayırır:

- **DDNS:** Kimliği doğrulanmış bir istemci, adresi değiştikten sonra sabit bir adı günceller.
- **DGA:** Endpoint, genellikle zamana veya bir anahtara, bazen de değişebilir herkese açık içeriğe dayalı bir seed’den domain adları türetir; operatör etkin ad için DNS’i ayarlar.<sup>[[17]](#references)</sup>
- **Fast flux:** Bir ad, çoğu zaman düşük TTL’lerle, hızla değişen ele geçirilmiş/proxy adresleri kümesini döndürür.
- **Double flux:** Hem hizmet adresleri hem de yetkili name server adresleri döner; böylece kontrol katmanı da gizlenir.

Fast flux, yalnızca “çok sayıda DNS yanıtı” değil, saldırganların kullandığı bir yük dağıtım düzenidir. Daha güçlü kanıtlar; düşük TTL, yüksek sayıda benzersiz adres, geniş ASN/coğrafi dağılım, kısa düğüm ömrü, tekrarlanan uygulama davranışı ve şüpheli kayıt geçmişinin birlikte değerlendirilmesiyle elde edilir. CDN’ler bu özelliklerin birkaçını meşru olarak taşır. MITRE, DNS davranışının süreç ve sonrasındaki bağlantılarla ilişkilendirilmesini önerir.<sup>[[5]](#references)</sup>

Bir DGA; sözcüksel entropi, ünsüz/rakam örüntüleri, NXDOMAIN patlamaları, eş zamanlı ilk görülme zamanı olan domain’ler ve süreç bağlamı üzerinden tespit edilebilir. Wordlist DGA’lar ve üretken modeller, basit entropi kurallarını etkisiz kılar; bu nedenle filo genelinde zamansal kümelendirme ve endpoint soy ağacı daha önemli hâle gelir.

### Wordlist DGA için değişebilir görsel seed’i

Bir DGA’nın zamana bağlı olması gerekmez. Bir loader, herkese açık bir Telegram kanal sayfasını getirir, `tgme_page_photo_image` öğesinin `src` değerini okur, profil görselini indirir ve çözümlenmiş pikselleri yerine dosyanın **son 50 baytını** hash’ler. Dört hash seed’i; bir sıfat, isim, fiil ve sayı seçer. Görseli değiştirmek, yeni bir istemci dağıtmadan türetilen DNS adını değiştirir. Her iki tarafta da indirilen görselin tam baytlarını ve aynı word-list sırasını kullanın; görseli yeniden kodlamak veya listedeki öğelerin sırasını değiştirmek farklı adlar üretir.<sup>[[17]](#references)</sup>

İstemciden kurtarılan word list’lerle bu işlem, ad seçimi adımını yeniden üretir. Kaynağın bayt bazında hash’i 64 bitlik bir akümülatör, `0x1000193` çarpanı ve her bileşen için ayrı seed’ler kullanır:<sup>[[17]](#references)</sup>

<details>
<summary>Görsel seed’li wordlist ad seçimini yeniden üretme</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

[dead-drop resolver](#web-services-and-dead-drop-resolvers) uç noktanın kendisini yayımlarken buradaki herkese açık nesne yalnızca değiştirilebilir bir tohum sağlar; istemci uç noktayı yerel olarak türetir.

Ardından oluşturulan ad için `https://dns.google/resolve?name=<domain>&type=TXT` üzerinden DNS TXT kaydı sorgulanır. İstemci JSON yanıtındaki `data` alanını Base64 ile çözer, gömülü genel anahtarı kullanarak bir Ed25519 imzasını doğrular ve ancak bundan sonra komutu AES-ECB ile çözer. Gözlemlenen düz metin, bir yöntem seçicisi ve şifrelenmiş bir payload URL’siyle başlar. İmza denetimi sayesinde çözümlenebilen bir TXT kaydı tek başına kabul edilen görev verisini sağlayamaz.<sup>[[17]](#references)</sup>

## Ele geçirilmiş domain’ler ve domain shadowing

Bir aktör registrar/DNS hesabını ele geçirebilir, sahipsiz bir alt domain’i devralabilir veya başka açılardan itibarlı bir domain’in altına kayıtlar ekleyebilir. **Domain shadowing**, meşru apex’i korurken saldırganın denetimindeki çok sayıda alt domain’in değişen dağıtım veya C2 sunucularına yönelmesini sağlar. Domain’in geçmişinden ve itibarından yararlanır ve domain genelinde uygulanan engellemeleri aşabilir.<sup>[[6]](#references)</sup>

Savunucuların registrar ve yetkili DNS denetim günlüklerine, MFA’ya, registry/registrar kilitlerine, yeni delegasyonlar/API token’ları/name server’lar için uyarılara, certificate transparency izlemeye ve DNS’te referans verilen cloud kaynaklarının envanterine ihtiyacı vardır. Bir alt domain’in çözümleme ve sertifika geçmişini apex’in itibarından bağımsız olarak inceleyin.

## Web hizmetleri ve dead-drop resolver’lar

Bir **dead-drop resolver (T1102.001)**, geçerli C2’ye işaret eden kodlanmış bir işaretçiyi meşru bir gönderi, profil, belge, repository, cloud nesnesi veya blockchain alanı içinde saklar. Malware herkese açık nesneyi alır, bir domain/IP çözümler ve sonraki aşamayla iletişim kurar. Çift yönlü varyantlar, hizmet API’leri üzerinden komut veya dosya alışverişi yapar.<sup>[[7]](#references)</sup>

GitHub’a özgü bir resolver varyantı, yalnızca kimliği doğrulanmış bir repository kanalı başarısız olduğunda Issues Search API’sini kullanır. İstemci geçerli tarih, repository ve issue türüyle eşleşen issue’ları arar, her issue’nun yorumlar URL’sini izler ve `<!--` ile `-->` işaretleri arasındaki şifreli metni çıkarır. Host başına tarihten türetilen çözme işleminin ardından `Owner`, `LicRepo` ve `LicToken` gibi alanlar birincil repository sahibinin, yolun ve token’ın yerine geçer. Bu sayede operatör istemciyi değiştirmeden kimlik bilgilerini ve uç noktaları değiştirebilir; issue yorumu resolver görevi görürken repository dosyaları görev verisi kanalı olarak kalır.<sup>[[15]](#references)</sup>

Bir Android varyantı başlangıçta iki herkese açık Telegram sayfasından birini seçer ve APK içine gömülü bir işaretçinin iki örneği arasındaki şifreli metni çıkarır. Değeri Base64URL ile çözer ve AES-128-CBC ile şifresini açar: `SHA-256(marker)` değerinin ilk 16 baytı anahtar, kalan 16 baytı ise IV’dir. Düz metin, Telegram sayfasının URL’si değil, gerçek C2 temel URL’sidir. Çözümlemeyi yeniden üretirken sayfa içeriğini ve işaretçinin tam hâlini koruyun; herkese açık sayfanın değiştirilmesi, APK yeniden oluşturulmadan uç noktanın değiştirilmesini sağlar.<sup>[[16]](#references)</sup>

Bu yaklaşım dayanıklılık sağlar ve statik binary analizinde arka uç C2’yi gizler. Ayrıca kararlı nesne, tenant, repository, API ve erişim örüntüsü tanımlayıcıları oluşturur. Savunucular şunları ilişkilendirmelidir:

1. hizmetle iletişim kuran süreci;
2. tam API yolunu/nesneyi ve yanıt hash’ini;
3. çözme veya dize işleme etkinliğini;
4. kısa süre sonra gerçekleşen yeni giden bağlantıyı; ve
5. filonun başka yerlerindeki aynı davranışı.

GitHub’ın, cloud depolamanın veya sosyal medyanın tamamını engellemek genellikle uygulanabilir değildir. Hizmet farkındalıklı çıkış politikası ve süreç düzeyinde ilişkilendirme, yalnızca domain’e dayalı engellemeden daha etkilidir.

## Persona’lar, hesaplar ve tedarik bölmeleri

Persona, kurtarma e-postası, telefon, ödeme yöntemi, tarayıcı veya yönetici IP’si bölmeler arasında köprü kurduğunda altyapı anonimliği başarısız olur. Devlet bağlantılı operasyonlar, hesapları kullanımdan çok önce sosyal profiller, e-posta kimlikleri ve cloud hesaplarıyla donatmıştır; ATT&CK bunu sosyal, e-posta ve cloud alt tekniklerini içeren Establish Accounts (T1585) olarak kaydeder.<sup>[[8]](#references)</sup>

Bir savunucu veya araştırmacı şu verilerden bir grafik oluşturur:

- oluşturulma ve ilk oturum açma zamanı, yerel ayar, saat dilimi ve çalışma takvimi;
- kurtarma alanları, MFA cihazları, kimlik belgeleri ve ödeme araçları;
- tarayıcı/TLS parmak izleri ve kaynak ağ geçmişi;
- avatarın yeniden kullanımı, görselin kaynağı, yazım tarzı ve sosyal ağın büyümesi;
- ortak domain kayıt sahibi, name server, sertifika, analytics ID veya repository commit’i;
- herkese açık relay mimarisini atlayan yönetim düzlemi işlemleri.

Yetkili bir red team çalışması için sentetik persona’lar tatbikat yöneticisine belgelenmeli, kuruma ait kurtarma/ödeme kanallarını kullanmalı, ilgisiz gerçek kişileri taklit etmekten kaçınmalı ve planlanmış bir kullanım sonu olmalıdır. SOC çalışmadan habersiz kalabilir; ancak operasyon hesap verebilirlikten yoksun hâle gelmemelidir.

## Tehdit modellemesinde kullanılacak yeni bileşik örüntüler

Aşağıdakiler, adı belirtilen bir aktörün bu tasarımların her birini aynen kullandığına dair iddialar değil, **savunucu odaklı bileşimlerdir**. Gözlemlenmiş temel bileşenleri birleştirir ve purple-team varsayımları olarak kullanışlıdır.

### Asimetrik tek yönlü görev verisi

Komutlar herkese açık, yayın veya yalnızca ekleme yapılabilen bir kaynaktan gelirken sonuçlar gecikmeden sonra ilgisiz başka bir kanal üzerinden gönderilir. Bu temel bileşenlere web hizmeti üzerinden tek yönlü iletişim ve dead drop örnek verilebilir. Kanalların ayrılması, tek bir akışın çift yönlü görünmesini önler ve basit istek/yanıt ilişkilendirmesini zorlaştırır.<sup>[[9]](#references)</sup>

**Tespit:** Nesne düzeyindeki okumaları koruyun; ardından daha geniş bir zaman aralığında süreç durumu değişikliklerini ve sonraki giden aktarımları ilişkilendirin. Hemen yanıt gelmese bile aynı herkese açık nesneyi okuyan nadir süreçleri araştırın.

### Çok aşamalı kanal geçişi

Sessiz bir ilk aşama envanter çıkarır ve yalnızca seçili sistemleri ilgisiz ikinci aşama kanalına geçirir. İkinci aşamanın uç noktası, protokolü ve süreci ilk aşamayla hiçbir altyapıyı paylaşmayabilir. Bu, yetenekli altyapının açığa çıkmasını sınırlar ve ATT&CK T1104 kapsamında açıkça modellenmiştir.<sup>[[10]](#references)</sup>

**Tespit:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini ilişkilendirin; ilk domain’i engelledikten sonra olayı kapatmayın.

### Protokoller arası relay çevirisi

Farklı atlama noktaları paketleri şeffaf biçimde iletmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya mesaj kuyruğu API’si arasında çeviri yapar. Çeviri, uçtan uca tek bir protokol parmak izini ortadan kaldırır; ancak kendine özgü zamanlama, arabelleğe alma ve anlamsal dönüşüm özellikleri olan ağ geçitleri oluşturur. Protocol tunneling (T1572), proxy’ler ve hizmet taklidiyle birleştirilebilir.<sup>[[11]](#references)</sup>

**Tespit:** Bir protokolü alıp sıkı biçimde ilişkili bayt/zaman davranışıyla başka bir protokol başlatan ağ geçidi sunucularını arayın; uç noktanın amacını gerçekte taşıdığı protokolle karşılaştırın.

### Edge cihazlarda pasif etkinleştirme

Bir implant sinyal göndermek yerine, router/VPN’e zaten ulaşan trafiği izler ve yalnızca özel bir değer, kaynak portu örüntüsü veya kimliği doğrulanmış token algıladığında etkinleşir. Normal trafik gerçek hizmete ulaşmaya devam eder. ATT&CK bu yöntemi Traffic Signaling (T1205) olarak adlandırır ve belgelenmiş ağ cihazı ile APT örnekleri içerir.<sup>[[12]](#references)</sup>

**Tespit:** Firmware/dosya bütünlüğü, yetkili bir araştırma sırasında ham paket yakalama, beklenmeyen socket filtreleri ve hizmetin farklı koşullardaki davranışı. Periyodik bir sinyalin olmaması, edge cihazın temiz olduğunu kanıtlamaz.

### Serverless ve geçici kaynak rotasyonu

Bir ön uç kararlı bir mantıksal kimliği korurken kısa ömürlü function/container’lar farklı bölgelerdeki ve hesaplardaki aşamaları tek tek işler. Bu, diskte kalma süresini ve sabit kaynak IP’lerini azaltır; ancak kontrol düzlemi oluşturma kayıtları, image/layer, rol, secret, istek ID’si ve faturalama telemetrisi kalıcı ilişki grafiğini oluşturur.

**Tespit:** Cloud denetim ve çağrı günlüklerini workload dışında saklayın; dağıtım şablonlarını, rolleri, ortam anahtarlarını ve ön uç-kaynak ilişkilerini kümelendirin.

### Gizlilik katmanlarında çeşitlilik

Bir operasyon bilerek tek tip bir zincirden kaçınabilir: örneğin bir kanal kiralık relay kullanırken görev verisi herkese açık bir nesneden alınır, çıkış kuruma ait laboratuvar hücresel bağlantısından yapılır ve yönetim ayrı bir kurum ağı üzerinden yürütülür. Bu, tek bir sağlayıcının ele geçirilmesinin değerini azaltır; ancak katmanlar arası zamanlama ve operasyonel hata riskini artırır.

**Tespit:** Kimlik, DNS, SaaS, ağ ve cloud sensörlerindeki kampanya zaman çizelgelerini oluşturun. Aynı göstergeleri değil, eşzamanlı durum geçişlerini arayın.

### Merkeziyetsiz veya transparency log dead drop’ları

Bir aktör, kalıcı ve herkese açık, yalnızca ekleme yapılabilen herhangi bir sisteme, içerik adresli depoya veya transparency benzeri akışa küçük bir şifreli işaretçi yerleştirebilir. Herkese açık nesne dayanıklıdır; ancak tam dizini/içerik hash’i ve istemcinin sorgulama davranışı kararlı tanımlayıcılara dönüşür.

**Tespit:** API/nesne tanımlayıcılarının tamamını ve yanıt hash’lerini kaydedin; değiştirilemez nesneleri sorgulayan standart dışı süreçlerin ardından çözme veya yeni bağlantı gerçekleştiğinde uyarı verin.

### Gecikmeli store-and-forward operasyonları

Etkileşimli C2 güçlü zamanlama ilişkisi oluşturur. Store-and-forward tasarımı şifreli işleri toplu hâle getirir ve sonuçları dakikalar veya saatler sonra farklı bir kuyruk ya da fiziksel aktarım yoluyla döndürür. Daha zayıf uçtan uca zamanlama ilişkisi karşılığında yanıt verme hızından ödün verir.

**Tespit:** İlişkilendirme pencerelerini genişletin, kuyruk erişiminin periyodikliğini modelleyin ve uç noktalardaki hazırlık aşamalarını inceleyin. Toplu işlem sinyali paket zamanlamasından planlanmış süreç/dosya davranışına taşır; sinyali ortadan kaldırmaz.

## Tasarım incelemesi: gözlemcileri düşünün

Her yol için dağıtımdan önce ve veri toplama sonrasında bu tabloyu doldurun:

| Katman | Kaynağı görür mü? | Hedefi görür mü? | İçeriği görür mü? | Kararlı tanımlayıcılar | Saklama/yasal sorumlu |
|---|---:|---:|---:|---|---|
| yerel ağ/operatör | | | | | |
| giriş/erişim hizmeti | | | | | |
| geçiş operatörü/operatörleri | | | | | |
| çıkış/redirector/CDN | | | | | |
| yetkili DNS/registrar | | | | | |
| hedef | | | | | |
| hesap/ödeme sağlayıcısı | | | | | |

Sıradan bir sağlayıcı tüm sütunları doldurabiliyorsa mimari, hedeften gizlenme sağlar ancak sağlam bir ayrım sunmaz. Kurum içindeki hiçbir denetleyici etkinliği bir çalışmayla ilişkilendiremiyorsa bu mimari profesyonel red teaming için uygun değildir.

## References

- [1] [MITRE ATT&CK — Altyapı edinme (T1583), altyapıyı ele geçirme (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Çin bağlantılı casusluk aktörleri ORB ağlarını kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Çok atlamalı Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Altyapıyı ele geçirme: Domain’ler (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web hizmeti: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Hesap oluşturma (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web hizmeti: Tek yönlü iletişim (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Çok aşamalı kanallar (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Dünyanın en büyük konut proxy ağının faaliyetlerini kesintiye uğratmak](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Shadow kampanyaları: Küresel casusluğu ortaya çıkarmak](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel kampanyası Irak altyapısını hedef alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI arayüz katmanlarını oluşturdu. Kurbanlar PIN’lerini kaybediyor](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Geçmişin numaraları imzalı ChatGPT ve Claude binary’leri aracılığıyla yeniden kullanılıyor](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
