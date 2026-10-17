# Offensive Infrastructure ve Attribution Evasion

{{#include ../banners/hacktricks-training.md}}

Bir operatör, tek bir proxy kullanarak nadiren anlamlı bir anonimlik elde eder. Gerçek kampanyalarda bir **ayrıştırma grafiği** oluşturulur: operatör bir erişim düğümüne ulaşır, ara düğümler bu düğümü çıkış noktasından gizler, redirector'lar gerçek C2'yi korur ve geçici adlar herkese açık uca yönlendirilir.

Her yolun standartlaştırılmış artı/eksi yönlerini, dağıtım ve tespit bilgilerini görmek için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) sayfasını kullanın. Bu sayfa, saldırgan altyapısının bileşimini daha ayrıntılı ele alır.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Hedefin gördüğü son adres, bu nedenle klavyeyi kimin kontrol ettiğinin kanıtı değil, izlenen yolun kanıtıdır. MITRE başlıca bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) olarak eşleştirir.<sup>[[1]](#references)</sup>

## Altyapı sınıfları

| Sınıf | Bir aktör bunu neden kullanır? | Kalıcı maruziyet | Savunmacının en iyi pivot noktası |
|---|---|---|---|
| Kiralık VPS/cloud | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden kurması kolay | Kiracı, faturalandırma, konsol, kaynak oturum açma ve imaj geçmişi | Hesap/kontrol düzlemi olayları ve tekrarlanan sunucu parmak izi |
| Ticari VPN/Tor | Büyük ortak çıkış kümesi; sunucu yönetimi yok | Sağlayıcı/görünürlük ve uçtan uca zamanlama | Hedef davranışı, uç nokta kanıtları ve akış korelasyonu |
| Residential/mobil proxy | Tüketici ASN'si ve coğrafi açıdan makul görünüm | Broker/müşteri kayıtları; proxyware veya virüslü ana bilgisayar davranışı | İmkânsız seyahat, proxy protokolleri ve oturum başına adres değişimi |
| Ele geçirilmiş sunucu/yönlendirici/IoT | Kurbanın itibarını ve yargı yetki alanını ödünç alır | Implant, yönetim akışı ve tekrarlanan üst akış denetleyicisi | Tek bir çıkış IP'si yerine cihaz telemetrisi ve ORB topolojisi |
| CDN/redirector | Herkese açık edge'i arka uç C2'den ayırır | TLS/HTTP grameri, sertifika, yönlendirme ve cloud hesabı izleri | Edge-kaynak korelasyonu ve istek biçimi kümelendirmesi |
| Meşru web hizmeti | İzin verilen GitHub/cloud/sosyal medya trafiğine karışır | API token'ı, kiracı/nesne tanımlayıcıları ve olağandışı süreç kökeni | Uç nokta süreci ve hizmet/API anlambilimi |
| Fiziksel/hücresel/uydu yolu | Görünürdeki fiziksel kaynağı değiştirir | RF, operatör, abone, cihaz ve konum kayıtları | Radyo/fiziksel ve ağ kanıtlarının birlikte değerlendirilmesi |

## Operasyonel relay kutusu ağları

Bir **ORB ağı**, ara hizmet olarak kullanılan yönetilen bir proxy filosudur. Mandiant bunları kiralanmış sunuculardan oluşan tedarik edilmiş ağlar, ele geçirilmiş yönlendirici/IoT cihazlarından oluşan tedarik edilmemiş ağlar ve hibritler olarak sınıflandırır. Olgun bir topolojide dört mantıksal rol bulunur:<sup>[[2]](#references)</sup>

1. **Yönetim sunucusu (ACOS):** Envanteri, kimlik bilgilerini, durumu ve yönlendirme politikasını yönetir.
2. **Erişim/relay düğümü:** Müşterileri veya operatörleri doğrular; değişen bir ağa açılan sabit giriş noktasıdır.
3. **Geçiş düğümleri:** Kiralanmış veya ele geçirilmiş bir ya da daha fazla sistem, içeriği gizlenmiş bağlantıları iletir.
4. **Çıkış/hazırlık düğümü:** Keşif, istismar veya C2 hedeflerine son kaynak adresini sunar.

Ağ, çıkışları ülkeye, ASN'ye, gecikmeye veya kullanılabilirliğe göre seçebilir ve sağlıksız düğümleri değiştirebilir. Birden fazla tehdit grubu aynı ağı kiralayabilir. Mandiant, bazı ORB'lerle ilişkili bir IPv4 adresinin yalnızca 31 gün boyunca kullanıldığını gözlemlemiştir; bu nedenle, eski bir IP listesini engellemek yerine **ağın gelişen, aktöre benzer bir varlık olarak ele alınmasını** önerir.<sup>[[2]](#references)</sup>

### Bunun sağladıkları ve sızdırdıkları

- Hedef, coğrafi olarak yakında ve görünüşte konut bağlantısı olan bir çıkış görür.
- Çıkış, hedefi ve kendinden önceki hop'u görür; operatörü görmesi şart değildir.
- Erişim hizmeti müşteriyi ve rota isteğini görür. Bağımsız yönetilen bir ağ müşteriyi çıkışlardan ayrı tutabilir; ancak bu, karşı taraf için değerli kayıtlar oluşturur.
- IP'ler değişse bile tekrarlanan portlar, el sıkışma sırası, sunucu banner'ları, sertifikalar, çalışma süreleri ve denetleyici ilişkileri filoyu ortaya çıkarabilir.
- Ele geçirilmiş bir yönlendiricide genellikle uç nokta telemetrisi bulunmaz; ancak ISS'si yine de abone ve akış verilerine sahiptir. Cihaza el konulması implant/yapılandırma izlerini açığa çıkarır.

{% hint style="info" %}
Yetkili bir tatbikat için topolojiyi kuruluşa ait VM'ler veya yönlendiricilerle yeniden oluşturun ve denetleyicinin ilişkilendirme haritasını saklayın. Açık proxy'leri veya üçüncü taraf cihazları kullanmayın. [Lab kılavuzu](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir aracı mağdur etmeden savunmacıların görebileceği aynı hop yapısını oluşturur.
{% endhint %}

## Residential ve mobil proxy ağları

Residential proxy hizmetleri oturumları tüketici geniş bant adreslerine atar; mobil proxy'ler ise operatör NAT havuzları üzerinden çıkış yapar. Kaynaklar açıkça kaydolmuş cihazlardan, tüketici uygulamalarına eklenmiş SDK/proxyware'den, bayilerden veya malware'den gelebilir. Bu kaynaklar birbirine eşdeğer değildir: Bilgilendirilmiş rızanın olmaması, bir gizlilik hizmetini ele geçirilmiş altyapıya dönüştürür.

Döndürme modları tespiti etkiler:

- **İstek başına döndürme**, üst katman kimliği sabit kalırken IP ve ASN/coğrafya bilgilerinde hızlı süreksizlikler oluşturur;
- **yapışkan oturumlar**, bir çıkışı dakikalarca veya saatlerce koruyarak sıradan bir aboneyi andırır;
- **backconnect gateway'leri**, müşteriye tek bir broker uç noktası gösterir ve çıkışları kendi içinde seçer;
- **mobil havuzlar**, çok sayıda gerçek aboneyi az sayıda operatör NAT adresinin arkasına yerleştirir; bu da bir IP'yi engellemeyi maliyetli hâle getirir.

Savunmacılar IP'yi doğrulanmış oturum, TLS/istemci parmak izi, HTTP sıralaması, cihaz çerezi ve davranışla ilişkilendirmelidir. Sözde yerel bir residential oturum açma işleminin ardından, tüm üst katman özellikleri aynı kalırken başka bir ülkeden oturum açılması, tek başına itibardan daha güçlü bir göstergedir. Buna karşılık, adres paylaşımı ve mobil geçiş meşru değişimlere yol açar; bu nedenle residential/proxy sınıflandırmasını asla kesin hüküm olarak değerlendirmeyin.

### Proxyware kontrol düzlemleri ve bayi çakışmaları

Residential havuzunu düz bir çıkış listesi olarak modellemeyin. IPIDEA ekosistemi analizi, yeniden kullanılabilir **iki katmanlı bir kontrol düzlemini** ortaya çıkardı: Gömülü bir SDK önce cihaz/kayıt üst verilerini bir Tier One etki alanına bildirir ve zamanlama bilgilerini ve Tier Two `connect`/`proxy` IP:port çiftlerini alır. Düğüm, kodlanmış bir görev için Tier Two connect portunu düzenli olarak yoklar, eşleşen proxy portuna ikinci bir bağlantı açar ve sağlanan baytları istenen hedefe iletir. Görünüşte farklı SDK'lar ve proxy markaları ayrı keşif etki alanlarına sahipti; ancak ortak sahiplik ve bayi ilişkileri nedeniyle paylaşılan Tier Two altyapısında ve örtüşen çıkış havuzlarında birleşiyorlardı.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Bu, residential IP bloğundan daha kalıcı hunting pivotleri sağlar:<sup>[[13]](#references)</sup>

- beklenmedik bir utility, VPN, oyun veya gömülü cihaz süreci sabit bir cihaz kimliği/müşteri anahtarı gönderir ve değişen bir sunucu listesi alır;
- endpoint alışılmadık bir porttaki doğrudan IP'yi yoklar, ardından yeni bir hedef soketi açmadan hemen önce aynı adresteki başka bir porta bağlanır;
- görünürde farklı markalar Tier Two adreslerini, protokol söz dizimini, SDK kodunu veya exit-node örtüşmesini paylaşır;
- farklı Tier One domain’leriyle iletişim kuran farklı uygulamalar aynı Tier Two havuzundan adresler alır.

Bu örtüşme attribution'ı da sınırlar: bir IP'nin tek bir vendor'ın duyurduğu havuzda görülmesi, ilgili zamanda hangi reseller'ın, müşterinin veya threat actor'ın onu kullandığını kanıtlamaz. Akış zaman damgalarını, süreç soy ağacını, Tier One yanıt gövdelerini ve Tier Two görev tanımlayıcılarını koruyun.<sup>[[13]](#references)</sup> Yetkili bir çalışmada bu hiyerarşiyi yalnızca kuruluşa ait endpoint'lerle taklit edin; tüketici cihazlarını veya üçüncü taraf proxyware'i asla kaydetmeyin.

## Çok atlamalı proxy zincirleri

MITRE, external proxy'leri **multi-hop proxy'lerden (T1090.003)** ayırır. Önemli olan hop sayısı değil, bilginin ve yönetimin birbirinden ayrılmasıdır.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Taraflardan biri hem A'yı hem B'yi işletiyorsa, ortak günlükler veya akış zamanlaması devreyi yeniden oluşturmayı sağlayabilir. Aynı uç nokta/hesaptan art arda ticari VPN'ler eklemek, ortak kimlik, ödeme ve zamanlama kanıtlarını ortadan kaldırmadan gecikmeyi artırabilir. Tor, bağımsız seçilen relay'ler ve ortak bir istemci tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli etkileşimli bir ağ, her iki ucu da ölçen bir gözlemciye karşı dayanıklılık vaat edemez.

Yaygın hatalar arasında DNS veya IPv6 sızıntısı, uygulamaların kendi soketlerini açması, yönetim trafiğinin relay'lere doğrudan ulaşması, eşzamanlı etkinlik, yeniden kullanılan SSH anahtarları ve kimliği belirleyen hesaplarda oturum açılması bulunur. Doğru doğrulama bir arıza testidir: Her relay'i sırayla durdurun ve iş yükünün şifresiz bir bağlantı yoluna geri dönemediğini gösterin.

### Tünelin çökmesi ve upstream sızıntısı

Bir relay mimarisi, çoğu zaman arızalandığında en kolay ilişkilendirilebilir hale gelir. Unit 42, kurbana dönük VPS'ler, relay VPS'leri, konut proxy'leri, Tor ve diğer proxy hizmetlerinden oluşan çok katmanlı bir casusluk yolunu belgeledi; tünellerden biri atlandığında veya çöktüğünde, gizli upstream altyapısı relay ve kurbana dönük sistemlere doğrudan bağlandı. Aynı soruşturmada, upstream altyapısında kısa süreliğine açığa çıkan bir X.509 sertifikası da katmanlar arası pivot olarak kullanıldı.<sup>[[14]](#references)</sup>

**Veri düzlemini** (`victim <-> exit`) **kontrol düzleminden** (`operator/upstream -> relay administration`) ayrı tutun. Yalnızca başarılı C2 oturumlarını değil, sahip olduğunuz her katmandaki gelen bağlantı ve kimlik doğrulama günlüklerini, sertifika geçmişlerini ve kısa süreli başarısız bağlantıları da saklayın. Yalnızca relay kesintileri sırasında görünen veya birden fazla kurbana dönük düğümü doğrudan yöneten bir kaynak, sıradan bir exit'ten daha güçlü bir upstream adayıdır; ancak ASN/konum bilgisi yine de bir hipotezdir, operatörün kimliğinin kanıtı değildir.

Yetkili bir laboratuvar, iş yükünün bağlantı kesildiğinde güvenli biçimde başarısız olmasını sağlamalıdır. Bir Linux network namespace içinde yalıtılmış iş yükünde ilk rota tüneli kullanmalıdır; tünel kaldırıldıktan sonra istek ve rota sorgusu, fiziksel uplink'i seçmek yerine başarısız olmalıdır:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS ve IPv6 için testi her relay sınırında tekrarlayın. Herhangi bir probe başarılı olursa, policy routing veya firewall ayarlarını düzeltmeden önce gerçek interface/source address değerini kaydedin; bu gözlem, bir araştırmacının göreceği attribution leak'tir.

## Redirector katmanları ve trafik şekillendirme

Herkese açık bir **redirector**, operasyona özgü bir gramerle eşleşen trafiği kabul eder ve korumalı bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerikle yanıtlanabilir.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Birden fazla katman maruziyeti sınırlar: bir public domain'in yakılması, team server'ın açığa çıkmasını gerektirmez. CDN'ler anycast kapasitesi ve itibarlı bir dış domain sağlar; ancak CDN hesabı ve edge logları attribution noktalarına dönüşür. TLS fingerprints, sertifika geçmişleri, ayırt edici yollar/header sıraları, yanıt boyutları, yönlendirme davranışı ve origin allowlist'leri, sözde ilişkisiz front'ları aynı kümede toplayabilir.

Tespit için normalleştirmeden önce reverse-proxy alanlarını kaydedin; SNI/Host/authority değerlerini karşılaştırın; nadir header kombinasyonlarını inceleyin; yanıt gövdelerini ve TLS fingerprints değerlerini kümelendirin; yapılandırma örtüşmeleri için cloud/CDN audit log'larını arayın. Yetkili red team çalışmalarında gerçek bir markayı kopyalamaktan veya kimlik bilgisi toplamayı ilgisiz bir üçüncü tarafın arkasına yerleştirmekten kaçının.

## Domain fronting ve domainless fronting

Klasik **domain fronting (T1090.004)** yönteminde TLS bağlantısı, SNI alanında izin verilen bir front domain bildirirken şifreli HTTP `Host` veya HTTP/2 `:authority` alanı farklı bir back-end domain'e istek gönderir. İşbirliği yapan bir CDN, içteki değere göre yönlendirme yapar. TLS şifre çözme yetkisi olmayan bir ağ gözlemcisi front'u görür; CDN ise her iki değeri ve origin'i görür. Domainless varyantlarda SNI boş olabilir; hedefi başka bir yönlendirme alanı seçer.<sup>[[4]](#references)</sup>

Bu sihirli bir taklit yöntemi değildir: yalnızca aracı, bu uyumsuzluğa kasıtlı veya yanlışlıkla izin verdiğinde ve içteki adı nasıl yönlendireceğini bildiğinde çalışır. Büyük sağlayıcılar, hesaplar arası fronting'i kısıtlamıştır. Encrypted ClientHello (ECH), ağ yolundaki bir gözlemcinin görebildiklerini değiştirir; ancak CDN, endpoint veya uygulama kayıtlarını ortadan kaldırmaz.

Tespit noktaları şunları içerir:

- endpoint process ancestry ve ilgili uygulamadan beklenmeyen hedef;
- TLS incelemesinin yasal ve mümkün olduğu durumlarda SNI ile HTTP authority uyumsuzluğu;
- bir tenant/front'un başka bir authority/origin'e yönlendirme yaptığını gösteren CDN log'ları;
- normalde etkileşimli olan bir hizmete yönelik olağandışı, uzun süreli veya periyodik oturumlar;
- değişen front domain'leri arasında sabit şifreli akış boyutları ve düzenli aralıklar.

Güvenli bir lab, yönlendirme uyumsuzluğunu size ait bir reverse proxy üzerinde simüle eder; public CDN'yi kötüye kullanmaz.

## Dinamik çözümleme: DDNS, DGA ve fast flux

Dinamik çözümleme, mantıksal bir hizmeti sabit altyapıdan ayırır:

- **DDNS:** kimliği doğrulanmış bir istemci, adresi değiştikten sonra sabit bir adı günceller.
- **DGA:** hem endpoint hem de controller, zaman/anahtar seed'inden olası domain adları üretir; operatör bunların küçük bir alt kümesini kaydettirir.
- **Fast flux:** bir ad, genellikle düşük TTL değerleriyle, hızla değişen ele geçirilmiş/proxy adresleri kümesi döndürür.
- **Double flux:** kontrol katmanını da gizleyerek hem hizmet adresleri hem de yetkili name server adresleri dönüşümlü olarak değişir.

Fast flux, yalnızca “çok sayıda DNS yanıtı” değil, adversarial amaçla kullanılan bir yük dağıtım modelidir. Daha güçlü kanıtlar; düşük TTL, yüksek benzersiz adres sayısı, geniş ASN/coğrafya dağılımı, kısa node ömrü, tekrarlanan uygulama davranışı ve şüpheli kayıt geçmişini bir araya getirir. CDN'ler bu özelliklerin birkaçını meşru olarak paylaşır. MITRE, DNS davranışının process ve sonraki bağlantılarla ilişkilendirilmesini önerir.<sup>[[5]](#references)</sup>

DGA; sözcüksel entropi, sessiz harf/rakam örüntüleri, NXDOMAIN patlamaları, eşzamanlı ilk görülen domain'ler ve process bağlamı üzerinden tespit edilebilir. Wordlist DGA'lar ve üretken modeller, basit entropi kurallarını etkisiz kılar; bu nedenle filo genelinde zamansal kümelendirme ve endpoint lineage daha önemli hâle gelir.

## Ele geçirilmiş domain'ler ve domain shadowing

Bir aktör registrar/DNS hesabını ele geçirebilir, sahipsiz kalmış bir subdomain'i devralabilir veya başka açılardan itibarlı bir domain'in altına kayıtlar ekleyebilir. **Domain shadowing**, meşru apex'i korurken saldırganın kontrolündeki çok sayıda subdomain'in değişen delivery veya C2 host'larına yönelmesini sağlar. Domain'in geçmişinden ve itibarından yararlanır ve domain genelinde engellemeyi atlatabilir.<sup>[[6]](#references)</sup>

Savunucuların registrar ve authoritative-DNS audit log'larına, MFA'ya, registry/registrar kilitlerine, yeni delegasyonlar/API token'ları/name server'lar için uyarılara, certificate-transparency izlemeye ve DNS'in referans verdiği cloud kaynaklarının envanterine ihtiyacı vardır. Bir subdomain'in çözümlemesini ve sertifika geçmişini apex'in itibarından bağımsız olarak inceleyin.

## Web hizmetleri ve dead-drop resolver'lar

**Dead-drop resolver (T1102.001)**, mevcut C2'ye yönelik kodlanmış bir işaretçiyi meşru bir gönderi, profil, belge, repository, cloud object veya blockchain alanında saklar. Malware, public object'i alır, bir domain/IP'yi çözümler ve sonraki aşamayla bağlantı kurar. Çift yönlü varyantlar, hizmet API'leri üzerinden komut veya dosya alışverişi yapar.<sup>[[7]](#references)</sup>

GitHub'a özgü bir resolver varyantı, yalnızca kimliği doğrulanmış repository kanalı başarısız olduğunda Issues Search API'yi kullanır. İstemci, geçerli tarih, repository ve issue türüyle eşleşen issue'ları arar; her issue'nun comments URL'sini izler ve `<!--` ile `-->` işaretçileri arasındaki ciphertext'i çıkarır. Host başına tarihten türetilen şifre çözme işleminin ardından `Owner`, `LicRepo` ve `LicToken` gibi alanlar, birincil repository owner, path ve token değerlerinin yerini alır. Bu sayede operatör istemciyi değiştirmeden kimlik bilgilerini ve endpoint'leri döndürebilir; issue yorumu bir resolver, repository dosyaları ise tasking kanalı olarak kalır.<sup>[[15]](#references)</sup>

Bir Android varyantı, başlangıçta iki public Telegram sayfasından birini seçer ve APK'ya gömülü bir işaretçinin iki tekrarı arasındaki ciphertext'i çıkarır. Değeri Base64URL ile çözümler ve AES-128-CBC ile şifresini açar: `SHA-256(marker)` değerinin ilk 16 baytı anahtar, kalan 16 baytı IV'dir. Açık metin, Telegram sayfası URL'si değil, gerçek C2 base URL'sidir. Çözümlemeyi yeniden üretirken sayfa içeriğini ve işaretçinin tam değerini koruyun; public sayfayı değiştirmek, APK'yi yeniden derlemeden endpoint'i döndürür.<sup>[[16]](#references)</sup>

Bu yöntem dayanıklılık sağlar ve statik binary analizinden back-end C2'yi gizler. Aynı zamanda sabit object, tenant, repository, API ve erişim örüntüsü tanımlayıcıları oluşturur. Savunucular şu verileri birleştirmelidir:

1. hizmetle iletişim kuran process;
2. tam API yolu/object ve yanıt hash'i;
3. decoding veya string işleme etkinliği;
4. kısa süre sonra kurulan yeni outbound bağlantı; ve
5. filonun başka yerlerindeki aynı davranış.

GitHub, cloud storage veya sosyal medyanın tamamını engellemek nadiren uygulanabilir. Hizmet farkındalığına sahip egress politikası ve process düzeyinde korelasyon, yalnızca domain engellemeden daha etkilidir.

## Persona'lar, hesaplar ve tedarik bölmeleri

Bir persona, kurtarma e-postası, telefon, ödeme yöntemi, browser veya admin IP'si bölmeler arasında bağlantı kurduğunda altyapı anonimliği bozulur. Devlet bağlantılı operasyonlar, kullanılmadan çok önce sosyal profiller, e-posta kimlikleri ve cloud hesapları oluşturmuştur; ATT&CK bunu Establish Accounts (T1585) olarak kaydeder ve sosyal, e-posta ve cloud alt tekniklerini içerir.<sup>[[8]](#references)</sup>

Bir savunucu veya araştırmacı şu verilerden bir grafik oluşturur:

- oluşturulma ve ilk giriş zamanı, yerel ayar, saat dilimi ve çalışma düzeni;
- kurtarma alanları, MFA cihazları, kimlik belgeleri ve ödeme araçları;
- browser/TLS fingerprints ve kaynak ağ geçmişi;
- avatarın yeniden kullanımı, görselin kaynağı, yazım tarzı ve sosyal ağın büyümesi;
- ortak domain registrant'ı, name server, sertifika, analytics ID veya repository commit'i;
- public relay mimarisini atlayan yönetim düzlemi eylemleri.

Yetkili bir red team çalışmasında sentetik persona'lar tatbikat kontrolörüne belgelenmeli, kuruluşa ait kurtarma/ödeme kanallarını kullanmalı, ilgisiz gerçek kişileri taklit etmekten kaçınmalı ve planlı bir sonlandırma sürecine sahip olmalıdır. SOC habersiz kalabilir; operasyon denetlenebilir olmaktan çıkmamalıdır.

## Tehdit modellemesi için yeni bileşik örüntüler

Aşağıdakiler, **savunucu odaklı bileşimlerdir**; adı geçen bir aktörün bu tasarımların her birini birebir kullandığı iddiası değildir. Daha önce gözlemlenmiş primitive'leri bir araya getirir ve purple team varsayımları olarak kullanışlıdır.

### Asimetrik tek yönlü tasking

Komutlar public, broadcast veya append-only bir kaynaktan gelirken sonuçlar gecikme sonrasında ilgisiz başka bir kanaldan çıkar. Primitive örnekleri arasında web hizmeti üzerinden tek yönlü iletişim ve dead drop'lar bulunur. Kanalların ayrılması, tek bir akışın çift yönlü görünmesini engeller ve basit istek/yanıt korelasyonunu zorlaştırır.<sup>[[9]](#references)</sup>

**Tespit:** Önce object düzeyindeki okumaları koruyun; ardından process durum değişikliklerini ve daha sonraki outbound aktarımları daha geniş bir zaman aralığında ilişkilendirin. Hemen yanıt gelmese bile aynı public object'i okuyan nadir bir process'i araştırın.

### Çok aşamalı kanal yükseltme

Sessiz bir ilk aşama envanter çıkarır ve yalnızca seçilmiş sistemleri ilgisiz bir ikinci aşama kanalına geçirir. İkinci endpoint, protokol ve process, ilk aşamayla hiçbir altyapıyı paylaşmayabilir. Bu, gelişmiş altyapının maruziyetini sınırlar ve ATT&CK'te açıkça T1104 olarak modellenmiştir.<sup>[[10]](#references)</sup>

**Tespit:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini ilişkilendirin; ilk domain'i engelledikten sonra olayı kapatmayın.

### Protokoller arası relay çevirisi

Farklı hop'lar, paketleri şeffaf biçimde iletmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya bir message-queue API'sini birbirine dönüştürür. Çeviri, uçtan uca tek bir protokol fingerprint'ini ortadan kaldırır; ancak ayırt edici zamanlama, buffering ve anlamsal dönüşüm özelliklerine sahip gateway'ler oluşturur. Protocol tunneling (T1572), proxy'ler ve hizmet taklidiyle birleştirilebilir.<sup>[[11]](#references)</sup>

**Tespit:** Bir protokolü alıp başka bir protokolle sıkı biçimde bağlantılı bayt/zaman davranışı göstererek başlatan gateway host'larını arayın; endpoint'in amacını gerçekten taşınan protokolle karşılaştırın.

### Edge cihazlarında pasif etkinleştirme

Beacon göndermek yerine bir implant, router/VPN'e zaten ulaşan trafiği izler ve yalnızca bir magic value, kaynak portu örüntüsü veya kimliği doğrulanmış token ile etkinleşir. Normal trafik gerçek hizmete ulaşmaya devam eder. ATT&CK bunu Traffic Signaling (T1205) olarak adlandırır ve belgelenmiş network-device ve APT örnekleri içerir.<sup>[[12]](#references)</sup>

**Tespit:** Firmware/dosya bütünlüğünü, yetkili bir araştırma sırasında raw packet capture'ı, beklenmeyen socket filter'larını ve hizmet davranışındaki farklılıkları inceleyin. Periyodik beacon olmaması, bir edge cihazının temiz olduğunu kanıtlamaz.

### Serverless ve geçici origin dönüşümü

Bir front, sabit bir mantıksal kimliği korurken kısa ömürlü function/container'lar birkaç region/account'ta ayrı aşamaları yürütür. Bu, disk ömrünü ve sabit origin IP'lerini azaltır; ancak control-plane oluşturma kayıtları, image/layer, role, secret, request ID ve billing telemetry kalıcı grafiğin parçalarına dönüşür.

**Tespit:** Cloud audit ve invocation log'larını workload dışında saklayın; deployment template'lerini, role'leri, environment key'lerini ve front-origin ilişkilerini kümelendirin.

### Gizlilik katmanlarının çeşitliliği

Bir operasyon bilerek tek tip bir zincirden kaçınabilir: örneğin bir kanal kiralanmış bir relay kullanır, tasking public bir object üzerinden yürür, çıkış size ait bir lab cellular bağlantısından yapılır ve yönetim ayrı bir kuruluş ağı kullanır. Bu, tek bir sağlayıcının ele geçirilmesinin değerini azaltır; ancak katmanlar arası zamanlama ve operasyonel hata riskini artırır.

**Tespit:** Identity, DNS, SaaS, network ve cloud sensörleri arasında kampanya zaman çizelgeleri oluşturun. Aynı IOC'ler yerine eşzamanlı durum geçişlerini arayın.

### Merkeziyetsiz veya transparency log tabanlı dead drop'lar

Bir aktör, dayanıklı herhangi bir public append-only sisteme, content-addressed store'a veya transparency benzeri feed'e küçük, şifrelenmiş bir işaretçi yerleştirebilir. Public object dayanıklıdır; ancak tam index/content hash'i ve istemcinin polling davranışı sabit tanımlayıcılara dönüşür.

**Tespit:** Tam API/object tanımlayıcılarını ve yanıt hash'lerini kaydedin; değiştirilemeyen object'leri sorgulayan standart dışı process'ler ardından decoding veya yeni bağlantılar yaptığında uyarı üretin.

### Gecikmeli store-and-forward operasyonları

Etkileşimli C2, zamanlamada güçlü korelasyon oluşturur. Store-and-forward tasarımı şifreli işleri gruplar ve sonuçları dakikalar veya saatler sonra farklı bir queue ya da fiziksel aktarım üzerinden döndürür. Daha zayıf uçtan uca zamanlama karşılığında yanıt hızından ödün verir.

**Tespit:** Korelasyon pencerelerini genişletin, periyodik queue erişimini modelleyin ve endpoint'teki hazırlık faaliyetlerini inceleyin. Batching, sinyali paket zamanlamasından planlanmış process/dosya davranışına taşır; ortadan kaldırmaz.

## Tasarım incelemesi: gözlemcileri düşünün

Her yol için, dağıtımdan önce ve veri topladıktan sonra bu tabloyu doldurun:

| Katman | Kaynağı görür mü? | Hedefi görür mü? | İçeriği görür mü? | Sabit tanımlayıcılar | Saklama/yasal sorumlu |
|---|---:|---:|---:|---|---|
| yerel ağ/carrier | | | | | |
| giriş/erişim hizmeti | | | | | |
| traversal operatör(ler)i | | | | | |
| çıkış/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| hedef | | | | | |
| hesap/ödeme sağlayıcısı | | | | | |

Sıradan tek bir sağlayıcı her sütunu doldurabiliyorsa mimari, hedeften gizlenme sağlar ancak sağlam bir ayrıştırma sağlamaz. Dahili hiçbir kontrolör etkinliği bir tatbikatla ilişkilendiremiyorsa bu mimari profesyonel red team çalışmaları için uygun değildir.

## References

- [1] [MITRE ATT&CK — Altyapı Edinme (T1583), Altyapıyı Ele Geçirme (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Çin bağlantılı casusluk aktörleri ORB ağlarını kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Çoklu Hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Altyapıyı Ele Geçirme: Domain'ler (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Hizmeti: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Hesap Oluşturma (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Hizmeti: Tek Yönlü İletişim (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Çok Aşamalı Kanallar (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Dünyanın En Büyük Residential Proxy Ağının İşleyişini Kesintiye Uğratmak](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Gölge Kampanyalar: Küresel Casusluğun Ortaya Çıkarılması](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel Kampanyası Irak Altyapısını Hedef Alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: AI Overlay'leri Oluşturdu. Kurbanlar PIN'lerini Kaybediyor](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
