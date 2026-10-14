# Saldırgan Altyapısı ve Atıfın Gizlenmesi

{{#include ../banners/hacktricks-training.md}}

Bir operatör, tek bir proxy kullanarak nadiren anlamlı bir anonimlik elde eder. Gerçek kampanyalar bir **ayrıştırma grafiği** oluşturur: operatör bir erişim düğümüne ulaşır, geçiş düğümleri bu düğümü çıkış noktasından gizler, redirector'lar gerçek C2'yi korur ve tek kullanımlık adlar herkese açık uç noktaya yönelir.

Her yolun standartlaştırılmış artı/eksi, dağıtım ve tespit görünümü için [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) sayfasını kullanın. Bu sayfada, düşmanca altyapı bileşimi daha ayrıntılı inceleniyor.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

Hedefin gördüğü son adres, bu nedenle bir yolun kanıtıdır; klavyeyi kimin kontrol ettiğinin kanıtı değildir. MITRE, başlıca bileşenleri Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) ve Web Service (T1102) olarak eşleştirir.<sup>[[1]](#references)</sup>

## Altyapı sınıfları

| Sınıf | Bir aktör neden kullanır | Kalıcı olarak açığa çıkanlar | Savunmacının en iyi pivot noktası |
|---|---|---|---|
| Kiralık VPS/bulut | Hızlı, öngörülebilir, yönlendirilebilir ve yeniden kurması kolay | Kiracı, faturalandırma, konsol, kaynak oturum açma ve imaj geçmişi | Hesap/kontrol düzlemi olayları ve tekrarlanan sunucu parmak izi |
| Ticari VPN/Tor | Büyük paylaşımlı çıkış kümesi; sunucu yönetimi yok | Sağlayıcı/görünürlük ve uçtan uca zamanlama | Hedef davranışı, uç nokta kanıtı ve akış korelasyonu |
| Konut/mobil proxy | Tüketici ASN'si ve coğrafi açıdan makul görünüm | Aracı/müşteri kayıtları; proxyware veya bulaşmış ana makine davranışı | Olanaksız seyahat, proxy protokolleri ve oturum bazında adres değişimi |
| Ele geçirilmiş sunucu/yönlendirici/IoT | Kurbanın itibarını ve yargı alanını ödünç alır | Implant, yönetim akışı ve tekrarlanan üst akış denetleyicisi | Tek bir çıkış IP'si değil, cihaz telemetrisi ve ORB topolojisi |
| CDN/yönlendirici | Genel uç noktayı arka uç C2'den ayırır | TLS/HTTP dilbilgisi, sertifika, yönlendirme ve cloud hesabı izleri | Uç nokta-kaynak korelasyonu ve istek biçimi kümelenmesi |
| Meşru web hizmeti | İzin verilen GitHub/cloud/sosyal trafik içinde gizlenir | API token'ı, kiracı/nesne tanımlayıcıları ve olağandışı süreç kökeni | Uç nokta süreci ile hizmet/API semantiği |
| Fiziksel/hücresel/uydu yolu | Görünürdeki fiziksel kaynağı değiştirir | RF, operatör, abone, cihaz ve konum kayıtları | Radyo/fiziksel ve ağ kanıtlarının birlikte değerlendirilmesi |

## Operasyonel relay box ağları

Bir **ORB ağı**, ara hizmet olarak kullanılan, yönetilen bir proxy filosudur. Mandiant bunları kiralanmış sunuculardan oluşan sağlanmış ağlar, ele geçirilmiş yönlendirici/IoT cihazlarından oluşan sağlanmamış ağlar ve hibritler olarak sınıflandırır. Olgun bir topolojide dört mantıksal rol bulunur:<sup>[[2]](#references)</sup>

1. **Yönetim sunucusu (ACOS):** Envanteri, kimlik bilgilerini, sağlık durumunu ve yönlendirme politikasını yönetir.
2. **Erişim/relay düğümü:** Müşterilerin veya operatörlerin kimliğini doğrular; değişen bir mesh'e giden kararlı giriş noktasıdır.
3. **Geçiş düğümleri:** Kiralanmış veya ele geçirilmiş bir ya da daha fazla sistem, şeffaf olmayan bağlantıları aktarır.
4. **Çıkış/evreleme düğümü:** Keşif, exploit veya C2 hedeflerine son kaynak adresini sunar.

Mesh; ülkeye, ASN'ye, gecikmeye veya kullanılabilirliğe göre çıkış seçebilir ve sağlıksız düğümleri değiştirebilir. Birden fazla tehdit grubu aynı ağı kiralayabilir. Mandiant, bazı ORB'lerle ilişkili bir IPv4 adresinin 31 gün kadar kısa bir süre boyunca etkin kaldığını gözlemlemiştir; bu nedenle eski bir IP listesini engellemek yerine **ağı, zaman içinde değişen ve aktöre benzeyen bir varlık olarak** ele almayı önerir.<sup>[[2]](#references)</sup>

### Bunun sağladıkları—ve sızdırdıkları

- Hedef, coğrafi olarak yakında ve görünüşte konut bağlantısı olan bir çıkış görür.
- Çıkış, hedefi ve önceki atlamayı görür; operatörü görmeyebilir.
- Erişim hizmeti müşteriyi ve rota isteğini görür. Bağımsız yönetilen bir mesh, müşteriyi çıkışlardan ayrı tutabilir; ancak güçlü bir karşı taraf kaydı oluşturur.
- IP'ler değişse bile tekrarlanan portlar, handshake sıralaması, sunucu banner'ları, sertifikalar, çalışma süreleri ve denetleyici ilişkileri filoyu açığa çıkarabilir.
- Ele geçirilmiş bir yönlendiricide genellikle uç nokta telemetrisi bulunmaz; ancak ISS'sinde abone ve akış verileri bulunur. Cihaza el konulması implant/yapılandırma izlerini açığa çıkarır.

{% hint style="info" %}
Yetkili bir alıştırma için topolojiyi kuruluşa ait VM'ler veya yönlendiricilerle yeniden oluşturun ve denetleyicinin attribution eşlemesini saklayın. Açık proxy'leri veya üçüncü taraf cihazları ağa dahil etmeyin. [Lab kılavuzu](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain), bir aracıya zarar vermeden savunmacının görebileceği aynı atlama yapısını oluşturur.
{% endhint %}

## Konut ve mobil proxy ağları

Konut proxy hizmetleri oturumları tüketici geniş bant adreslerine atar; mobil proxy'ler operatör NAT havuzlarından çıkış yapar. Kaynaklar, açıkça kaydolmuş cihazlardan, tüketici uygulamalarıyla birlikte sunulan SDK/proxyware'den, yeniden satıcılardan veya zararlı yazılımlardan gelebilir. Bu kaynaklar birbirine eşdeğer değildir: bilgilendirilmiş rıza olmaması, bir gizlilik hizmetini ele geçirilmiş altyapıya dönüştürür.

Rotasyon modları tespiti etkiler:

- **istek başına rotasyon**, üst katman kimliği sabit kalırken IP ve ASN/coğrafi konumda hızlı kesintiler oluşturur;
- **yapışkan oturumlar**, çıkışı dakikalarca veya saatlerce sabit tutarak sıradan bir aboneye benzer;
- **backconnect gateway'leri**, müşteriye tek bir aracı uç noktası gösterir ve çıkışları kendi içinde seçer;
- **mobil havuzlar**, çok sayıda gerçek aboneyi az sayıda operatör NAT adresinin arkasında toplar; bu da IP engellemesini maliyetli hâle getirir.

Savunmacılar IP'yi kimliği doğrulanmış oturum, TLS/istemci parmak izi, HTTP sıralaması, cihaz çerezi ve davranışla ilişkilendirmelidir. Tüm üst katman özellikleri aynı kalırken başka bir ülkeden yapılan ve yerel olduğu varsayılan bir konut oturum açma işlemi, tek başına itibar verisinden daha güçlü bir göstergedir. Öte yandan adres paylaşımı ve mobil geçiş meşru değişimlere yol açar; bu nedenle konut/proxy sınıflandırmasını asla kesin hüküm olarak değerlendirmeyin.

### Proxyware kontrol düzlemleri ve yeniden satıcıların kesişimi

Konut havuzunu düz bir çıkış listesi olarak modellemeyin. IPIDEA ekosisteminin analizi, yeniden kullanılabilir **iki katmanlı bir kontrol düzlemini** ortaya çıkardı: gömülü bir SDK önce cihaz/kayıt meta verilerini Tier One alan adına bildirir ve zamanlama bilgisiyle Tier Two `connect`/`proxy` IP:port çiftlerini alır. Düğüm, kodlanmış bir görevi almak için düzenli aralıklarla Tier Two connect portunu yoklar; eşleştirilmiş proxy portuna ikinci bir bağlantı açar ve sağlanan baytları istenen hedefe aktarır. Görünüşte farklı SDK'lar ve proxy markaları ayrı keşif alan adlarına sahipti; ancak ortak sahiplik ve yeniden satıcı ilişkileri nedeniyle paylaşılan Tier Two altyapısında ve kesişen çıkış havuzlarında birleşiyordu.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Bu, bir residential IP bloğundan daha kalıcı hunting pivot'ları sağlar:<sup>[[13]](#references)</sup>

- beklenmedik bir utility, VPN, game veya embedded-device process'i sabit bir device ID/customer key gönderir ve değişen bir server listesi alır;
- endpoint, alışılmadık bir port üzerindeki doğrudan IP'yi sorgular, ardından yeni bir destination socket açmadan hemen önce aynı adresteki başka bir porta bağlanır;
- görünüşte farklı markalar, Tier Two adreslerini, protocol grammar'ı, SDK kodunu veya exit-node örtüşmesini paylaşır;
- farklı Tier One domain'leriyle iletişim kuran ayrı uygulamalar, aynı Tier Two havuzundan adresler alır.

Bu örtüşme attribution'ı da sınırlar: Bir IP'nin bir vendor'ın ilan ettiği havuzda görülmesi, ilgili zamanda hangi reseller'ın, customer'sının veya threat actor'ın bu IP'yi kullandığını kanıtlamaz. Flow timestamp'lerini, process lineage'ı, Tier One response body'lerini ve Tier Two task identifier'larını koruyun.<sup>[[13]](#references)</sup> Yetkili bir çalışmada bu hiyerarşiyi yalnızca kuruluşun sahip olduğu endpoint'lerle taklit edin; consumer device'ları veya üçüncü taraf proxyware'i asla kaydetmeyin.

## Multi-hop proxy zincirleri

MITRE, external proxy'leri **multi-hop proxy'lerden (T1090.003)** ayırır. Önemli olan hop sayısı değil, bilgi ve yönetimin birbirinden ayrılmasıdır.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Bir taraf hem A'yı hem B'yi işletiyorsa, ortak loglar veya akış zamanlaması devreyi yeniden kurmaya yardımcı olabilir. Aynı uç nokta/hesaptan art arda ticari VPN'ler kullanmak, ortak kimlik, ödeme ve zamanlama kanıtlarını ortadan kaldırmadan gecikmeyi artırabilir. Tor, bağımsız seçilen relay'ler ve ortak bir istemci tasarımıyla bu sorunu azaltır; ancak düşük gecikmeli etkileşimli bir ağ, her iki ucu da ölçen bir gözlemciye karşı direnç vad edemez.

Yaygın hatalar arasında DNS veya IPv6 bypass'ı, uygulamaların kendi socket'lerini açması, yönetim trafiğinin relay'lere doğrudan ulaşması, eşzamanlı etkinlik, yeniden kullanılan SSH anahtarları ve kimliği açığa çıkaran hesaplarda oturum açılması yer alır. Doğru doğrulama yöntemi bir arıza testidir: her relay'i sırayla durdurun ve workload'un açık bir yola geri dönemediğini gösterin.

### Tünel çökmesi ve upstream leakage

Bir relay mimarisi, çoğu zaman arızalandığında en kolay şekilde ilişkilendirilebilir. Unit 42, kurbanlara dönük VPS'ler, relay VPS'leri, residential proxy'ler, Tor ve diğer proxy hizmetlerini kullanan çok katmanlı bir casusluk yolu belgeledi; bir tünel atlandığında veya çöktüğünde, gizli upstream altyapısı relay ve kurbanlara dönük sistemlere doğrudan bağlandı. Aynı soruşturmada, upstream altyapısında kısa süreliğine açığa çıkan bir X.509 sertifikası da katmanlar arasında pivot yapmak için kullanıldı.<sup>[[14]](#references)</sup>

**Data plane**'i (`victim <-> exit`), **control plane**'den (`operator/upstream -> relay administration`) ayrı tutun. Yalnızca başarılı C2 oturumlarını değil, sahip olduğunuz her katmandaki ingress ve kimlik doğrulama loglarını, sertifika geçmişlerini ve kısa süreli başarısız bağlantıları da saklayın. Yalnızca relay kesintileri sırasında görünen veya kurbanlara dönük birden çok node'u doğrudan yöneten bir kaynak, sıradan bir exit'ten daha güçlü bir upstream adayıdır; ancak ASN/jeolokasyon hâlâ bir hipotezdir, operatör kimliğinin kanıtı değil.

Yetkili bir lab'de workload, bağlantı kesildiğinde kapalı kalacak şekilde yapılandırılmalıdır. Bir Linux network namespace'i içinde yalıtılmış workload için ilk route tüneli kullanmalıdır; tünel kaldırıldıktan sonra hem istek hem de route lookup başarısız olmalı, fiziksel uplink seçilmemelidir:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

DNS ve IPv6 için testi, ayrıca her relay sınırında tekrarlayın. Herhangi bir probe başarılı olursa, policy routing'i veya firewall'ı düzeltmeden önce gerçek interface/source address'i kaydedin; bu gözlem, bir araştırmacının göreceği attribution leak'tir.

## Redirector katmanları ve trafik şekillendirme

Herkese açık bir **redirector**, operasyona özgü bir grammar ile eşleşen trafiği kabul eder ve korumalı bir team server'a iletir. Diğer her şey reddedilebilir veya zararsız içerik sunularak karşılanabilir.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Birden fazla katman maruziyeti sınırlar: herkese açık bir domainin ortaya çıkması, team server'ın da açığa çıkmasını gerektirmez. CDN'ler anycast kapasitesi ve itibarlı bir dış domain sağlar; ancak CDN hesabı ve edge logları attribution noktalarına dönüşür. TLS fingerprints, sertifika geçmişleri, ayırt edici path/header sıraları, yanıt boyutları, redirect davranışı ve origin allowlist'leri, sözde ilgisiz ön uçları aynı kümeye dahil edebilir.

Tespit için normalleştirme öncesinde reverse-proxy alanlarını kaydedin; SNI/Host/authority değerlerini karşılaştırın; nadir header bileşimlerini inceleyin; yanıt gövdelerini ve TLS fingerprints'leri kümelendirin; yapılandırma örtüşmelerini bulmak için cloud/CDN audit loglarını arayın. Yetkili red team'ler gerçek bir markayı taklit etmekten veya kimlik bilgisi toplamayı ilgisiz bir üçüncü tarafın arkasına yerleştirmekten kaçınmalıdır.

## Domain fronting ve domainsiz fronting

Klasik **domain fronting (T1090.004)** yönteminde TLS bağlantısı SNI alanında izin verilen bir front domain'i bildirirken, şifrelenmiş HTTP `Host` veya HTTP/2 `:authority` alanı farklı bir back-end domain'i ister. İş birliği yapan bir CDN, iç değere göre yönlendirme yapar. TLS çözümlemesi yapmayan bir ağ gözlemcisi front domain'i görür; CDN ise her iki değeri ve origin'i görür. Domainsiz varyantlarda SNI boş olabilir; hedefi başka bir yönlendirme alanı seçer.<sup>[[4]](#references)</sup>

Bu, sihirli bir taklit yöntemi değildir: yalnızca aracı, uyumsuzluğa kasıtlı ya da kazara izin veriyorsa ve iç adı nasıl yönlendireceğini biliyorsa çalışır. Büyük sağlayıcılar hesaplar arası fronting'i kısıtladı. Encrypted ClientHello (ECH), yol üzerindeki bir gözlemcinin görebileceklerini değiştirir; ancak CDN, endpoint veya uygulama kayıtlarını silmez.

Tespit noktaları şunlardır:

- endpoint sürecinin ataları ve o uygulama için beklenmeyen hedef;
- TLS incelemesinin yasal ve mümkün olduğu durumlarda SNI ile HTTP authority uyuşmazlığı;
- bir tenant/front'un başka bir authority/origin'e yönlendirme yaptığını gösteren CDN logları;
- normalde etkileşimli olan bir hizmete kurulan olağandışı, uzun süreli veya periyodik oturumlar;
- değişen front domain'ler üzerinden sabit kalan şifreli akış boyutları ve aralıkları.

Güvenli laboratuvar çalışmasında yönlendirme uyuşmazlığı, kuruma ait bir reverse proxy üzerinde simüle edilir; herkese açık bir CDN kötüye kullanılmaz.

## Dinamik çözümleme: DDNS, DGA ve fast flux

Dinamik çözümleme, mantıksal bir hizmeti sabit altyapıdan ayırır:

- **DDNS:** Kimliği doğrulanmış bir istemci, adresi değiştikten sonra sabit bir adı günceller.
- **DGA:** Hem endpoint hem de controller, zaman/anahtar seed'inden olası domain adları türetir; operatör bunların küçük bir kısmını kaydeder.
- **Fast flux:** Bir ad, genellikle düşük TTL'lerle, hızla değişen ele geçirilmiş/proxy adresleri kümesi döndürür.
- **Double flux:** Hem hizmet adresleri hem de yetkili name server adresleri dönüşümlü olarak değişir; böylece kontrol katmanı da gizlenir.

Fast flux, yalnızca “çok sayıda DNS yanıtı” anlamına gelmez; düşmanca amaçlarla kullanılan bir yük dağıtım modelidir. Daha güçlü kanıtlar; düşük TTL, çok sayıda benzersiz adres, geniş ASN/coğrafi dağılım, kısa düğüm ömrü, tekrarlanan uygulama davranışı ve şüpheli kayıt geçmişinin bir araya gelmesiyle oluşur. CDN'ler de meşru olarak bu özelliklerin birkaçını taşır. MITRE, DNS davranışının süreç ve sonraki bağlantılarla ilişkilendirilmesini önerir.<sup>[[5]](#references)</sup>

DGA, sözcüksel entropi, ünsüz/rakam örüntüleri, NXDOMAIN patlamaları, eş zamanlı ilk görülen domain'ler ve süreç bağlamı üzerinden tespit edilebilir. Wordlist DGA'ları ve üretici modeller basit entropi kurallarını aşabildiği için filo genelinde zamansal kümelendirme ve endpoint soy ağacı daha da önem kazanır.

## Ele geçirilmiş domain'ler ve domain shadowing

Bir aktör registrar/DNS hesabını ele geçirebilir, sahipsiz kalmış bir subdomain'i devralabilir veya başka açılardan itibarlı bir domain'in altına kayıt ekleyebilir. **Domain shadowing**, meşru apex'i korurken saldırganın kontrolündeki çok sayıda subdomain'in değişen dağıtım veya C2 sunucularına yönelmesini sağlar. Domain'in yaşı ve itibarı kullanılır; domain genelinde engellemeden kaçınılabilir.<sup>[[6]](#references)</sup>

Savunucular registrar ve yetkili DNS audit loglarını, MFA'yı, registry/registrar kilitlerini, yeni delegation/API token/name server için uyarıları, certificate transparency izlemeyi ve DNS kayıtlarında adı geçen cloud kaynaklarının envanterini kullanmalıdır. Bir subdomain'in çözümlemesini ve sertifika geçmişini apex'in itibarından bağımsız olarak inceleyin.

## Web hizmetleri ve dead-drop resolver'lar

Bir **dead-drop resolver (T1102.001)**, güncel C2'ye işaret eden kodlanmış bir adresi meşru bir gönderi, profil, belge, repository, cloud nesnesi veya blockchain alanında saklar. Malware, herkese açık nesneyi alır, bir domain/IP çözer ve sonraki aşamayla iletişim kurar. Çift yönlü varyantlar, hizmet API'leri üzerinden komut veya dosya alışverişi yapar.<sup>[[7]](#references)</sup>

GitHub'a özgü bir resolver varyantı, yalnızca kimliği doğrulanmış bir repository kanalı başarısız olduğunda Issues Search API'yi kullanır. İstemci geçerli tarih, repository ve issue türüyle eşleşen issue'ları arar, her issue'nun yorumlar URL'sini izler ve `<!--` ile `-->` işaretleri arasındaki şifreli metni çıkarır. Host başına yapılan tarih tabanlı şifre çözmenin ardından `Owner`, `LicRepo` ve `LicToken` gibi alanlar birincil repository sahibinin, path'in ve token'ın yerini alır. Bu, operatörün istemciyi değiştirmeden kimlik bilgilerini ve endpoint'leri döndürmesini sağlar; issue yorumu resolver, repository dosyaları ise tasking kanalı olarak kalır.<sup>[[15]](#references)</sup>

Bu yöntem dayanıklılık sağlar ve statik binary analizinden back-end C2'yi gizler. Aynı zamanda sabit nesne, tenant, repository, API ve erişim örüntüsü tanımlayıcıları oluşturur. Savunucular şu verileri ilişkilendirmelidir:

1. hizmetle iletişim kuran süreç;
2. tam API path/nesnesi ve yanıt hash'i;
3. çözümleme veya string işleme etkinliği;
4. kısa süre sonra kurulan yeni outbound bağlantı; ve
5. filonun başka yerlerindeki aynı davranışlar.

Tüm GitHub'ı, cloud storage'ı veya sosyal medyayı engellemek nadiren uygulanabilir. Hizmet farkındalıklı egress policy ve süreç düzeyinde korelasyon, yalnızca domain engellemeden daha etkilidir.

## Persona'lar, hesaplar ve tedarik bölmeleri

Persona, kurtarma e-postası, telefon, ödeme yöntemi, browser veya admin IP'si bölmeler arasında bağlantı kurarsa altyapı anonimliğini yitirir. Devlet bağlantılı operasyonlar, kullanımdan çok önce sosyal profiller, e-posta kimlikleri ve cloud hesapları oluşturmuştur; ATT&CK bunu, sosyal, e-posta ve cloud alt tekniklerini içeren Establish Accounts (T1585) olarak kaydeder.<sup>[[8]](#references)</sup>

Bir savunucu veya araştırmacı şu verilerden bir grafik oluşturur:

- oluşturulma ve ilk giriş zamanı, yerel ayar, saat dilimi ve çalışma düzeni;
- kurtarma alanları, MFA cihazları, kimlik belgeleri ve ödeme araçları;
- browser/TLS fingerprints ve kaynak ağ geçmişi;
- avatarların yeniden kullanımı, görsel kaynağı, yazım tarzı ve sosyal ağın büyümesi;
- ortak domain kayıt sahibi, name server, sertifika, analytics ID veya repository commit'i;
- herkese açık relay mimarisini atlayan yönetim düzlemi eylemleri.

Yetkili bir red team çalışmasında sentetik persona'lar tatbikat denetleyicisine belgelenmeli, kuruma ait kurtarma/ödeme kanallarını kullanmalı, ilgisiz gerçek kişileri taklit etmekten kaçınmalı ve planlı bir emeklilik sürecine sahip olmalıdır. SOC çalışmadan habersiz kalabilir; ancak operasyon hesap veremez hâle gelmemelidir.

## Tehdit modellemesi için ortaya çıkan bileşik örüntüler

Aşağıdakiler, **savunucu odaklı bileşimlerdir**; adı geçen bir aktörün bu tasarımların her birini aynen uyguladığı iddiası değildir. Gözlemlenmiş ilkeleri bir araya getirir ve purple-team hipotezleri olarak kullanılabilir.

### Asimetrik tek yönlü tasking

Komutlar herkese açık, yayın tabanlı veya yalnızca eklemeye izin veren bir kaynaktan gelirken sonuçlar gecikmenin ardından ilgisiz bir kanaldan çıkar. Bu ilkenin örnekleri arasında web hizmeti üzerinden tek yönlü iletişim ve dead drop'lar bulunur. Ayrım, tek bir akışın çift yönlü görünmesini engeller ve basit istek/yanıt korelasyonunu zorlaştırır.<sup>[[9]](#references)</sup>

**Tespit:** Nesne düzeyindeki okumaları koruyun; ardından süreç durumu değişikliklerini ve sonraki outbound aktarımları daha geniş bir zaman aralığında ilişkilendirin. Hemen yanıt gelmese bile aynı herkese açık nesneyi okuyan nadir süreçleri araştırın.

### Çok aşamalı kanal yükseltme

Sessiz bir ilk aşama envanter çıkarır ve yalnızca seçilen sistemleri ilgisiz bir ikinci aşama kanalına yükseltir. İkinci endpoint, protokol ve süreç ilk aşamayla hiçbir altyapıyı paylaşmayabilir. Bu, yetenekli altyapının maruziyetini sınırlar ve ATT&CK T1104'te açıkça modellenmiştir.<sup>[[10]](#references)</sup>

**Tespit:** `first network process -> downloaded/configured state -> new process or injection -> unrelated destination` zincirini ilişkilendirin; ilk domain'i engelledikten sonra olayı kapatmayın.

### Protokoller arası relay çevirisi

Farklı noktalar, paketleri şeffaf biçimde iletmek yerine HTTPS, QUIC, WebSocket, DNS, SSH veya bir message-queue API'sini birbirine dönüştürür. Çeviri, uçtan uca tek bir protokol fingerprint'ini ortadan kaldırır; ancak kendine özgü zamanlama, buffering ve anlamsal dönüşüm izleri bırakan gateway'ler oluşturur. Protocol tunneling (T1572), proxy'ler ve hizmet taklidiyle birleştirilebilir.<sup>[[11]](#references)</sup>

**Tespit:** Bir protokolü alıp diğeriyle bağlantı kuran ve bayt/zaman davranışları sıkı biçimde ilişkili gateway host'larını arayın; endpoint'in amacını gerçekten taşınan protokolle karşılaştırın.

### Edge cihazlarında pasif etkinleştirme

Beacon göndermek yerine bir implant, router/VPN'e zaten ulaşan trafiği izler ve yalnızca sihirli bir değer, kaynak portu örüntüsü veya kimliği doğrulanmış token gördüğünde etkinleşir. Normal trafik gerçek hizmete ulaşmaya devam eder. ATT&CK bu yöntemi Traffic Signaling (T1205) olarak adlandırır ve belgelenmiş ağ cihazı ile APT örnekleri içerir.<sup>[[12]](#references)</sup>

**Tespit:** Firmware/dosya bütünlüğünü, yetkili av sırasında ham paket yakalamayı, beklenmeyen socket filter'ları ve hizmet davranışındaki farklılıkları inceleyin. Periyodik bir beacon'ın olmaması, edge cihazının temiz olduğunu kanıtlamaz.

### Serverless ve geçici origin rotasyonu

Bir front, sabit bir mantıksal kimliği korurken kısa ömürlü function/container'lar birkaç region/account'ta tek tek aşamaları işler. Bu, disk üzerinde kalma süresini ve sabit origin IP'lerini azaltır; ancak control-plane oluşturma kayıtları, image/layer, role, secret, request ID ve faturalama telemetrisi kalıcı bir grafik oluşturur.

**Tespit:** Cloud audit ve invocation loglarını workload dışında saklayın; deployment template'lerini, role'leri, environment key'lerini ve front-origin ilişkilerini kümelendirin.

### Gizlilik katmanı çeşitliliği

Bir operasyon, örneğin bir kanal için kiralık relay, tasking için herkese açık bir nesne, çıkış noktası olarak kuruma ait bir laboratuvar cellular bağlantısı ve yönetim için ayrı bir kurum ağı kullanarak tek tip bir zincirden bilerek kaçınabilir. Bu, tek bir sağlayıcının ele geçirilmesinin değerini azaltır; ancak katmanlar arası zamanlama ve operasyonel hata riskini artırır.

**Tespit:** Kimlik, DNS, SaaS, ağ ve cloud sensörlerinden kampanya zaman çizelgeleri oluşturun. Aynı göstergeleri değil, eş zamanlı durum geçişlerini arayın.

### Merkeziyetsiz veya transparency log tabanlı dead drop'lar

Bir aktör, kalıcı ve herkese açık herhangi bir append-only sisteme, content-addressed depoya veya transparency benzeri akışa küçük bir şifreli işaretçi yerleştirebilir. Herkese açık nesne dayanıklıdır; ancak tam index/content hash'i ve istemcinin polling davranışı sabit tanımlayıcılara dönüşür.

**Tespit:** Tam API/nesne tanımlayıcılarını ve yanıt hash'lerini kaydedin; değişmez nesneleri yoklayan, ardından çözümleme veya yeni bağlantılar kuran standart dışı süreçler için uyarı oluşturun.

### Gecikmeli store-and-forward operasyonları

Etkileşimli C2, güçlü zamanlama korelasyonu oluşturur. Store-and-forward tasarımı şifreli işleri toplu hâle getirir ve sonuçları dakikalar ya da saatler sonra farklı bir queue veya fiziksel aktarım üzerinden döndürür. Daha zayıf uçtan uca zamanlama korelasyonu karşılığında yanıt hızı düşer.

**Tespit:** Korelasyon aralıklarını genişletin, periyodik queue erişimini modelleyin ve endpoint'te hazırlanan verileri inceleyin. Toplu işleme, sinyali paket zamanlamasından zamanlanmış süreç/dosya davranışına taşır; ortadan kaldırmaz.

## Tasarım incelemesi: gözlemcileri düşünün

Her yol için dağıtımdan önce ve veri toplandıktan sonra bu tabloyu doldurun:

| Katman | Kaynağı görür mü? | Hedefi görür mü? | İçeriği görür mü? | Sabit tanımlayıcılar | Saklama/yasal sorumlu |
|---|---:|---:|---:|---|---|
| yerel ağ/carrier | | | | | |
| giriş/erişim hizmeti | | | | | |
| geçiş operatör(ler)i | | | | | |
| çıkış/redirector/CDN | | | | | |
| yetkili DNS/registrar | | | | | |
| hedef | | | | | |
| hesap/ödeme sağlayıcısı | | | | | |

Tek bir sıradan sağlayıcı tüm sütunları doldurabiliyorsa mimari, hedeften gizlenme sağlar ama sağlam bir ayrım sağlamaz. Hiçbir kurum içi denetleyici etkinliği bir tatbikata bağlayamıyorsa bu mimari profesyonel red team çalışmaları için uygun değildir.

## References

- [1] [MITRE ATT&CK — Altyapı edinme (T1583), Altyapıyı ele geçirme (T1584) ve Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Çin bağlantılı casusluk aktörleri ORB ağlarını kullanıyor](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Çok atlamalı Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Altyapıyı ele geçirme: Domain'ler (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Hizmeti: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Hesap oluşturma (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Hizmeti: Tek yönlü iletişim (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Çok aşamalı kanallar (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Trafik sinyalleme (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Dünyanın en büyük residential proxy ağını etkisiz hâle getirme](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — Gölge kampanyalar: Küresel casusluğun ortaya çıkarılması](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Blinder Tunnel kampanyası Irak altyapısını hedef alıyor](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
