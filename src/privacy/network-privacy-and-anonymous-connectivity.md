# Network Privacy ve Anonim Bağlantı

{{#include ../banners/hacktricks-training.md}}

Ağ gizliliği bir yönlendirme kararıdır; kimliği bütünüyle gizlemez. Bir yol seçerken **kaynağı**, **hedefi**, **içeriği** ve **zamanlamayı** kimin ilişkilendirememesi gerektiğini sorun.

Standartlaştırılmış envanter için—her erişim yolu ailesinde `Pros`, `Cons`, adım adım `Procedure` ve `Detection`—[Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) ile başlayın. Bu sayfada yaygın ve uygulanabilir seçenekler ayrıntılandırılır.

## Her gözlemci genellikle neleri görebilir?

| Yol | Yerel ağ / ISP | Aracı | Hedef | Temel kısıtlama | Göreli hız |
|---|---|---|---|---|---|
| Doğrudan HTTPS | Kaynak, hedef metadata'sı, zamanlama/hacim | Hosting/CDN bağlantıyı görür | Kaynak IP, tarayıcı/uygulama verileri | Kaynak IP gizliliği sağlamaz | En hızlı |
| Ticari VPN | VPN'e bağlı kaynak; genellikle hedef metadata'sını göremez | VPN, kaynak ve hedef metadata'sını görür | VPN çıkış IP'si | Tek bir sağlayıcı ilişkilendirme noktası hâline gelir | Genellikle hızlı |
| Self-hosted VPN/VPS | VPS'ye bağlı kaynak | Hosting/hesap/ödeme/kontrol düzlemi logları | VPS çıkış IP'si | Kiralanan sunucuya/hesaba kolayca atfedilebilir | Genellikle hızlı |
| Tor Browser | Tor'a/bridge'e bağlı kaynak; zamanlama/hacim | Her relay sınırlı bir kısmı görür | Tor exit, tarayıcı verileri | Daha yavaş; hesap/uç nokta/ilişkilendirme riskleri | Orta/yavaş |
| Tails/Whonix | Daha güçlü yönlendirme sınırlarıyla benzer Tor yolu | Aynı Tor kısıtlamaları | Tor exit/uygulama verileri | Operasyonel hatalar ve host/donanım riski sürer | Orta/yavaş |
| Public guest Wi-Fi + HTTPS | Mekân yerel cihazı/zamanlamayı ve hedefleri görür | Mekânın ISP'si metadata'yı görür | Misafir public IP'si | Fiziksel/captive portal/cihaz ilişkilendirmesi | Hızlı/değişken |
| Cellular hotspot | Operatör aboneyi/cihazı/konumu ve hedefleri görür | Kullanılıyorsa VPN/Tor | Operatör, VPN veya Tor çıkış IP'si | Mobil abonelik ve konum kalıcı tanımlayıcılardır | Hızlı/değişken |
| Mixnet | Erişim sağlayıcı mixnet kullanımını; zamanlamayı/hacmi görür | Birden fazla mixing node | Gateway/çıkış | Gelişmekte olan ekosistem; gecikme ve bant genişliği maliyeti | En yavaş |

HTTPS, aktarım sırasında içeriği korur ancak tüm metadata'yı korumaz. EFF, sayfa yolları, kimlik bilgileri ve mesajlar şifrelenmiş olsa bile alan adının, zamanın ve trafik boyutunun aracılar tarafından görülebileceğini belirtiyor.<sup>[[1]](#references)</sup>

Şifreli bir overlay, kendiliğinden bir anonimlik ağı değildir: Yggdrasil'de doğrudan eşler birbirlerinin IP adreslerini görebilir.<sup>[[20]](#references)</sup> Yggdrasil'in [userspace forwarding ve SOCKS transport](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) özellikleri bir tunneling seçeneğidir; kaynak anonimliğini sağlayan bir katman değildir.<sup>[[20]](#references)[[21]](#references)</sup>

## VPN'ler: yoğunlaşmış güvenle hızlı gizlilik

VPN; hedef metadata'sını erişim ISP'sinden gizlemek, güvenilmeyen bir ağdaki ilk hop'u korumak, bir engagement için sabit bir çıkış adresi sunmak veya özel bir ağa erişmek için kullanışlıdır. Kullanıcıyı **anonim** hâle getirmez. VPN, kaynak bağlantısını görür ve hedef metadata'sını gözlemleyebilir; hesaplar, çerezler, GPS, fingerprint'ler ve ödeme bilgileri varlığını sürdürür.<sup>[[1]](#references)</sup>

### Sağlayıcı değerlendirme kontrol listesi

1. **Sahiplik ve yargı yetkisi:** Tüzel kişiliği, ana şirketi, faaliyet gösterdiği ülkeleri, altyapı alt yüklenicilerini ve geçerli yasal süreçleri belirleyin.
2. **Toplanan veriler:** Hesap/faturalandırma, kaynak IP'si, bağlantı zaman damgaları, bant genişliği, crash telemetry, DNS sorguları ve hedef loglarını birbirinden ayırın. “Tarama logu tutmuyoruz” ifadesi “veri toplamıyoruz” anlamına gelmez.
3. **Saklama ve silme:** Kesin süreleri, yedeklerin, fraud sistemlerinin ve veri işleyenlerin de aynı takvime uyup uymadığını öğrenin.
4. **Kanıt:** Kapsamı, tarihi, bulguları ve düzeltmeleri belirtilen kamuya açık denetimleri; yeniden üretilebilir/açık istemcileri; şeffaflık raporlarını ve belgelenmiş olayları tercih edin.
5. **Protokol ve istemci:** Güncel WireGuard, OpenVPN veya incelenmiş başka bir protokol; otomatik güncellemeler; DNS ve IPv6 yönetimi; kill switch ve platform başına leak testleri kullanın.
6. **İş modeli:** Ücretsiz veya sübvansiyonlu bir hizmetin nasıl finanse edildiğini anlayın. Bir uygulama mağazasında bulunması, tek başına güvenilir çalıştığının kanıtı değildir.
7. **Ödeme uyumu:** Alternatif ödeme, faturalandırma bilgilerinin VPN sağlayıcısına açıklanmasını azaltabilir; ancak her bağlantıda gözlemlenen kaynak IP'sini ortadan kaldırmaz.

### VPN'i yapılandırma ve doğrulama

1. Sağlayıcının/kurumun imzalı istemcisini resmî kaynağından yükleyin.
2. Belgelenmiş bir rotanın VPN'i atlaması gerekmiyorsa **full tunnel** seçin. Split tunneling ilişkilendirme ve leak yolları oluşturur.
3. Fail-closed/always-on davranışını etkinleştirin ve yeniden bağlanma sırasında trafiği engelleyin.
4. DNS'i tunnel üzerinden yönlendirin ve hem IPv4'ü hem IPv6'yı test edin. Bir protokolü yalnızca güvenli biçimde tunnel üzerinden yönlendirilemiyorsa ve işlev kaybı kabul ediliyorsa devre dışı bırakın.
5. Uyku/uyanma, ağ değiştirme, captive portal girişi, tunnel çökmesi ve hotspot tethering senaryolarını test edin. NCSC, bazı platformlarda tether edilen istemcilerin telefonun VPN'ini atlayabileceği konusunda uyarıyor.<sup>[[2]](#references)</sup>
6. Gözlemlenen IPv4, IPv6, DNS resolver'ı ve bağlantı zamanlamasını kaydetmek için kurumun kontrolündeki bir test endpoint'i kullanın. Hassas bir engagement'ı rastgele “leak test” sitelerine açmayın.
7. İstemci, işletim sistemi, ağ veya politika değişikliklerinden sonra yeniden test edin.

### Hostile-LAN yönlendirme atlatmaları

İşletim sistemi, paketi VPN şifrelemeden **önce** bir rota seçtiği için, bazı paketler VPN “bağlı” görünmeye devam ederken VPN'i atlayabilir. TunnelCrack, yaygın yönlendirme istisnalarını kötüye kullanmanın iki yolunu gösterdi: **LocalNet**, bir Internet hedefinin doğrudan bağlı alt ağdaymış gibi görünmesini sağlar; **ServerIP** ise VPN gateway çözümlemesini spoof ederek hedef adresin VPN transport'unun ihtiyaç duyduğu açık ağ istisnasını devralmasını sağlar. Bunlar WireGuard, OpenVPN, IPsec veya TLS'nin kırılmasından değil, istemci/yönlendirme hatalarından kaynaklanır. HTTPS payload'ları uçtan uca şifreli kalır; ancak yerel gözlemci hedef/zamanlama metadata'sını ve şifresiz protokol verilerini elde edebilir.<sup>[[18]](#references)</sup>

TunnelVision, DHCP option 121 üzerinden aynı şifreleme öncesi primitive'i uygular. Kötü amaçlı veya ele geçirilmiş bir DHCP server, VPN'in tüm trafiği kapsayan rotasından daha spesifik, classless bir rota yükleyerek rastgele bir host veya aralık için fiziksel interface'i seçebilir. VPN control channel çalışır durumda kalabileceğinden, yalnızca tunnel bağlantısı kesildiğinde devreye giren bir kill switch etkinleşmeyebilir; tek bir public “IP leak” kontrolü de seçici atlatmaları gözden kaçırabilir.<sup>[[19]](#references)</sup>

Fiziksel interface'te yalnızca DHCP'ye ve kimliği doğrulanmış VPN transport'una izin veren bir packet-filter kill switch bunu fail-closed davranışına dönüştürmelidir. Ancak hedefli rota enjeksiyonu yine de seçici bir denial side channel oluşturabilir. Sonuçları ciddi olabilecek Linux iş yüklerinde, uygulama namespace'inin fiziksel interface'i veya açık ağ varsayılan rotası olmadığı daha güçlü [workload başına rota zorunlu kılma modelini](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) tercih edin.<sup>[[19]](#references)</sup>

#### Sahip olunan lab ortamında doğrulama

Yönlendirme ve packet-filter uygulamaları platforma özel olduğundan, ürün geneli iddialar hızla güncelliğini yitirir. Tam olarak kullandığınız istemci/işletim sistemi/sürüm kombinasyonunu sahip olduğunuz bir AP, DHCP server, VPN endpoint'i ve hedefle test edin. Yalnızca test server'ında değil, endpoint'in kendisinde de capture alın; bir egress-IP sitesi tek başına her hedefin tunnel üzerinden geçtiğini kanıtlamaz.<sup>[[18]](#references)[[19]](#references)</sup>

1. VPN'e bağlanın, VPN server adresini kaydedin ve tüm IPv4/IPv6 yönlendirme tablolarını ve policy-routing kurallarını kaydedin. Windows'ta `route print`; macOS'ta `netstat -rn`; Linux'ta aşağıdaki komutları kullanın.
2. Size ait birkaç hedef IP için seçilen rotayı sorgulayın. Belgelenmiş VPN transport endpoint'i dışında, next hop/interface tunnel olmalıdır.
3. TunnelVision için kontrollü DHCP ağında lease'i yenileyin ve option 121 rotasını **yalnızca size ait bir test hedefi için** kurun. Başarılı sonuç, trafiğin tunnel üzerinden taşınması veya engellenmesidir; fiziksel interface üzerinden hedefe doğrudan trafik gönderilmesi değildir.
4. LocalNet için istemciye `203.0.113.0/24` gibi yalnızca lab'da kullanılacak public dokümantasyon alt ağı atayın ve size ait test hedefini bu alt ağa yerleştirin. LAN erişimini etkinleştirmenin Internet sınıfındaki hedeflerin tunnel'ı atlamasına yol açmadığını doğrulayın.
5. ServerIP için VPN'e bağlanmadan önce kontrollü DNS'in size ait VPN hostname'ini size ait test hedefine çözümlenmesini sağlayın; lab gateway, VPN transport'unu size ait gerçek VPN endpoint'ine yönlendirsin. İstemci, spoof edilmiş adrese giden ilgisiz uygulama trafiğini istisna tutmamalıdır.
6. “Local network access” seçeneğini hem etkin hem devre dışı durumdayken; yeniden bağlanma, uyku/uyanma, ağ değiştirme ve VPN süreci çökmesi sonrasında tekrarlayın. IPv4, IPv6 ve DNS'i ayrı ayrı test edin.
7. Fiziksel interface capture'ını inceleyin. Burada DHCP ve VPN server'a giden şifreli paketler bulunmalı; size ait test hedefine doğrudan adreslenmiş paketler bulunmamalıdır. Ayrıca, reddedilen bir atlatmanın kullanıcı istemlerinden veya bağlantı onarımından sonra sessizce devreye girmediğini doğrulayın.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: daha güçlü web bağlantısızlığı

Tor, hiçbir tekil relay'in normalde hem kaynağı hem de hedefi bilmemesi için birden fazla relay üzerinden bir circuit kurar. Hedef, kullanıcının IP'si yerine bir Tor exit görür; yerel ağ ise normalde bir Tor bağlantısı görür.<sup>[[3]](#references)</sup> Tor, düşük gecikmeli TCP uygulamaları için tasarlanmıştır; bu nedenle daha yavaştır ve her iki ucu da ilişkilendirebilen bir saldırgana karşı koruma garantisi veremez.<sup>[[4]](#references)</sup>

### Güvenli Tor Browser iş akışı

1. Tor Browser'ı yalnızca Tor Project'ten veya resmî bir mirror'dan indirin ve mümkünse imzayı doğrulayın.
2. Tor SOCKS portuna yönlendirilmiş normal bir browser yerine **Tor Browser** kullanın. Sıradan browser'lar DNS/WebRTC ve tanımlayıcı durum bilgilerini sızdırabilir.<sup>[[5]](#references)</sup>
3. Varsayılan boyutu, fontları, uzantıları ve gizlilik ayarlarını koruyun. Ek eklentiler browser'ı daha benzersiz hâle getirebilir.<sup>[[6]](#references)</sup>
4. Artan işlev kaybı kabul edilebilirse **Safer** veya **Safest** güvenlik seviyesini seçin.
5. Doğrudan Tor engellendiğinde veya sıradan relay IP'lerinin yerel ağda görünmesi kabul edilemez olduğunda bridge kullanın. Bridge'ler kolayca tanınmayı zorlaştırır; trafik analizini ortadan kaldırmaz.<sup>[[7]](#references)</sup>
6. Tanımlayıcı bir hesaba giriş yapmayın, tanımlayıcı bilgiler vermeyin veya indirilen etkin belgeleri ağa bağlı harici bir uygulamada açmayın.
7. Her kimlik için ayrı bir oturum/bağlam kullanın. “New circuit”, browser/uygulama kimliğini silmekle aynı şey değildir; uygun olduğunda **New Identity** kullanın veya izole ortamı yeniden başlatın.
8. Kimliği doğrulanmış HTTPS'yi veya onion service'i tercih edin. Bir Tor exit, şifrelenmemiş HTTP trafiğini gözlemleyebilir.

### Tor ve VPN birlikte kullanımı

Bunları birleştirmek otomatik olarak daha güvenli değildir. Tor'dan önce VPN kullanmak, VPN kaynağı görürken ISP'den doğrudan Tor relay bağlantılarını gizleyebilir; Tor'dan sonra VPN kullanmak ise VPN'e Tor sonrası etkinlikleri istikrarlı biçimde gösterir ve anonimlik kümesini küçültebilir. Yanlış yapılandırma leak'lere yol açabilir. Tor Project, bu tür birleşimleri yalnızca gelişmiş ve açıkça tanımlanmış tehdit modelleri için önerir.<sup>[[8]](#references)</sup>

## Halka açık ve misafir Wi-Fi

Modern HTTPS sayesinde pasif komşular genellikle düzgün biçimde şifrelenmiş web içeriğini okuyamaz; ancak misafir Wi-Fi anonimlik sağlamaz. Mekân; bağlantı zamanlarını, cihaz tanımlayıcılarını, captive portal verilerini, hedefleri ve DHCP ayrıntılarını kaydedebilir. Kameralar, alışverişler, ulaşım ve fiziksel gözlem de kullanıcıyı tanımlayabilir. Benzer isimli sahte bir hotspot, portal kimlik bilgilerini de ele geçirebilir veya şifrelenmemiş trafiği değiştirebilir.<sup>[[9]](#references)</sup>

### Yasal misafir ağı iş akışı

1. Yalnızca misafirler için sunulan veya sahibinin açıkça izin verdiği bir ağı kullanın. Personelden tam SSID'yi ve portal adımlarını öğrenin.
2. Endpoint'i ve travel router'ı gelmeden önce güncelleyin. Dosya/yazıcı paylaşımını, gelen bağlantı keşfini, otomatik katılmayı ve kayıtlı ağları arama özelliğini devre dışı bırakın.
3. İşletim sisteminin özel/randomized Wi-Fi adresini etkinleştirin. Güncel Apple sistemleri açık/zayıf ağlarda dönen adresler kullanabilir; modern Android cihazlarda randomization genellikle SSID başına kalıcıdır. Bu, yalnızca tek bir yerel tanımlayıcının etkisini azaltır.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Ayrıcalıklı bir workstation ile misafir ağı arasında, kurum tarafından denetlenen bir travel router'ı veya düşük güvenli bir bridge cihazını tercih edin. Bu, firewall/VPN politikasını merkezileştirir ancak router'ı mekândan gizlemez.<sup>[[12]](#references)</sup>
5. Captive portal'ı yalnızca belirlenmiş düşük güvenli cihaz/browser üzerinden tamamlayın. Anonim olduğu varsayılan bir bağlamda kişisel veya yeniden kullanılan kimlik bilgilerini asla girmeyin. Bağlantı sağlandıktan sonra portal browser'ını kapatın.
6. Hassas etkinliklerden önce full-tunnel VPN veya Tor başlatın ve fail-closed davranışını doğrulayın.
7. Kullanımdan sonra ağı unutun ve portal hesabının/veri saklama politikasını gözden geçirin.

{% hint style="danger" %}
Komşunun Wi-Fi'ını kırmak, portalı atlatmak, sızdırılmış misafir kimlik bilgilerini kullanmak, başka bir misafirin erişimini kopyalamak veya bir kafede Raspberry Pi gizlemek yetkisiz etkinliktir; bunlar gizlilik teknikleri değildir. Güvenli seçenekler; yasal bir misafir ağı, müşteri tarafından onaylanmış bir site veya mülk sahibinin yazılı izniyle yerleştirilip alınan, belgelenmiş bir drop node kullanmaktır.
{% endhint %}

## Travel router'lar

Bir travel router, workstation'ı düşmanca yerel yayınlardan izole edebilir, firewall uygulayabilir, tutarlı bir iç SSID sağlayabilir ve VPN'e otomatik olarak yeniden bağlanabilir. **Anonim değildir**: üst ağ onun radyo kimliğini ve trafik zamanlamasını görür; VPN sağlayıcısı da tünel kaynağını görür.

- Desteklenen OpenWrt/vendor firmware kullanın ve kullanılmayan hizmetleri kaldırın.
- Ethernet veya benzersiz parolalı, özel bir yönetim SSID'si üzerinden yönetin.
- WAN tarafından yönetimi, UPnP'yi, WPS'yi, dosya paylaşımını ve istenmeyen gelen trafiği devre dışı bırakın.
- Yalnızca desteklendiği ve izin verildiği durumlarda randomized/private WAN MAC kullanın.
- DNS ve IPv6 dâhil VPN politikasını router'da uygulayın ve tünel kesilirse dışarı giden trafiği engelleyin.
- Telefon hotspot'unun bağlı cihazları telefonun VPN'i üzerinden tünellediğini varsaymayın; test edin.

## Hücresel bağlantı, SIM'ler ve eSIM'ler

Hücresel bağlantı kullanışlıdır ancak anonim değildir. Operatörler abone/cihaz tanımlayıcılarını ve ağa bağlanmadan elde edilen konum bilgilerini tutar; eSIM de hâlâ bir mobil aboneliktir. Ön ödemeli olması, kayıtsız olduğu anlamına güvenilir biçimde gelmez; gereklilikler ülkeye göre değişir ve güncellenir.<sup>[[13]](#references)</sup>

Operasyonel olarak:

- Kişisel verilerin açığa çıkmasını azaltmak için ayrı ve desteklenen bir cihaz kullanın; hayalî bir abone kimliği oluşturmak için değil.
- Birlikte konumlanma tehdit modelinizdeyse, kişisel telefonunuzun yanında sürekli “ayrı” bir cihaz taşımayın.
- Kullanılmayan hücresel bağlantıyı, Wi-Fi'ı, Bluetooth'u ve konum erişimini devre dışı bırakın; cihazı kapatmak, arayüzdeki geçiş düğmelerinden daha güçlü bir radyo sınırı sağlar.
- Operatörün aboneliği/cihaz konumunu ve tünel endpoint'ini hâlâ bildiğini göz önünde bulundurarak hassas trafiği onaylanmış VPN/Tor yolundan geçirin.
- Güncel kayıt ve veri saklama kurallarını ulusal düzenleyici kurumdan veya yerel hukuk danışmanından doğrulayın; internetteki “anonim SIM ülkeleri” listelerine güvenmeyin.

## DNS ve TLS metadata'sı

- **DoH/DoT/DoQ**, istemci ile resolver arasındaki DNS'i şifreleyerek basit yerel okumayı veya değiştirmeyi önler; ancak resolver sorguları ve aktarım tanımlayıcılarını görür. Güveni başka yere taşırlar; anonimlik sağlamazlar.<sup>[[14]](#references)</sup>
- **ODoH**, proxy ekleyerek proxy ile hedefin iş birliği yapmadığı varsayımı altında resolver'ın istemci IP'sini öğrenmesini önler. Trafik analizi açıkça kapsam dışıdır.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)**, istemci, DNS ve sunucu desteklediğinde TLS handshake içindeki iç sunucu adını koruyabilir. Hedef IP, zamanlama, hacim ve endpoint görünür kalır.<sup>[[16]](#references)</sup>
- Düzgün yapılandırılmış bir VPN veya Tor ortamında DNS, o ortamın desteklenen yolunu izlemelidir. Ayrı bir resolver eklemek yeni bir gözlemci veya fingerprint oluşturabilir.

### Şifrelenmiş DNS/ECH doğrulama iş akışı

1. DNS'in VPN/Tor ortamı, işletim sistemi veya uygulama tarafından kontrol edileceğine karar verin. İlgisiz resolver'ları üst üste eklemek yerine, amaçlanan **tek** katmanda yapılandırın.
2. Yayımlanmış gizlilik/veri saklama politikasına göre bir resolver seçin ve platform destekliyorsa katı şifreli modu etkinleştirin. Fırsatçı fallback sessizce düz metne dönebilir.
3. Kontrolünüzdeki yetkili test bölgesinde benzersiz bir alt alan adı sorgulayın; yetkili log'un amaçlanan recursive resolver'ı gördüğünü doğrulayın.
4. Yetkilendirme kapsamında yalnızca test cihazının trafiğini yakalayın. Erişim ağının düz metin DNS'i okuyamadığını doğrulayın; şifrelenmiş resolver/tünel endpoint'ini görebildiğini unutmayın.
5. Engellenmiş/erişilemeyen şifreli bir resolver'ı test edin. Başarı koşulu, yanlışlıkla açık bir sorgu gönderilmesi değil, seçilen fail-closed davranışı veya belgelenmiş fallback davranışıdır.
6. ECH için, ECH etkinleştirilmiş ve kontrolünüzde olan bir host kullanın; istemci/sunucu tanılamasını inceleyerek **iç** ClientHello'nun kabul edildiğini doğrulayın. Yalnızca bir HTTPS kaydının sunulması ECH'nin başarılı olduğunu kanıtlamaz.
7. Ağ değişikliklerinden, captive portal'lardan, browser güncellemelerinden ve VPN yeniden bağlantılarından sonra testi tekrarlayın. Daha sonraki yöneticilerin bir bypass oluşturmaması için DNS/ECH'nin hangi bileşen tarafından yönetildiğini kaydedin.

## Mixnet'ler

Nym veya Katzenpost gibi mixnet'ler, zamanlama korelasyonuna karşı koymak için sabit boyutlu paketler, gecikme, yeniden sıralama ve cover traffic ekler. Bu özelliklerin maliyeti gecikme ve bant genişliğidir; bağımsız ve büyük ölçekli dağıtım kanıtları sınırlıdır. Güncel tüketici mixnet'lerini Tor/VPN'lerin daha hızlı veya garantili alternatifleri olarak değil, **gelişmekte olan/yüksek gecikmeli seçenekler** olarak değerlendirin.<sup>[[17]](#references)</sup>

### Değerlendirme iş akışı

1. Güncel tutulan bir istemciyi ve desteklenen uygulamanın tam olarak hangisi olduğunu belirleyin; gelişigüzel browser/sistem trafiğini belgelenmemiş bir proxy üzerinden zorla yönlendirmeyin.
2. Giriş, mix node'ları, gateway, hedef ve iş birliği varsayımları için güncel tehdit modelini okuyun.
3. Resmî ve imzalı kaynaktan ayrı bir test ortamına kurun ve yalnızca size ait, zararsız bir endpoint kullanın.
4. Teslimat gecikmesini, mesaj boyutu sınırlarını, güvenilirliği, yeniden iletimi ve gateway kullanılamadığında ne olduğunu ölçün.
5. Amaçlanan yolu ve kaynağı doğrulamak için yerel trafiği ve size ait endpoint'i inceleyin. Yanıtların aynı gizlilik tasarımını kullanıp kullanmadığını kontrol edin.
6. Kapatma/hata durumlarını test edin: uygulama sessizce doğrudan internet erişimine dönmemelidir.
7. Yalnızca hız için cover traffic'i devre dışı bırakmayın, gecikmeleri azaltmayın veya alışılmadık sabit rotalar seçmeyin; bu değişiklikler belirtilen anonimlik modelini geçersiz kılabilir.
8. Belirli dağıtım, bağımsız analiz ve operasyonel güvenilirlik, sonuçların önem düzeyini karşılayana kadar deneysel olarak tutun.

## Ağ ön kontrol listesi

- [ ] Yetkilendirme; erişim ağını, hedefi, tarihleri ve kaynak altyapıyı kapsıyor.
- [ ] Endpoint'te ilgisiz kimlikler veya etkin eşitleme oturumları bulunmuyor.
- [ ] IPv4, IPv6, DNS ve yeniden bağlantı davranışı planla uyumlu.
- [ ] Kontrol edilen DHCP/yerel alt ağ rota enjeksiyonu, test trafiğini fiziksel arayüze yönlendiremiyor.
- [ ] Hedef yalnızca beklenen çıkış noktasını görüyor.
- [ ] Captive portal ve hotspot davranışı, hassas trafik kullanılmadan test edildi.
- [ ] Yerel paylaşım/keşif ve otomatik ağ katılımı devre dışı.
- [ ] Gözlemci tablosu ve geriye kalan trafik korelasyonu riski kabul edildi.
- [ ] Sağlayıcı politikası, veri saklama ve acil durum iletişim bilgileri güncel.

Bilgi paylaşımı ayrıştırılmış relay'ler, rota zorlamalı iş yükleri, pluggable transport'lar, onion service'ler, I2P ve tek kullanımlık uzak browser'lar için [Gelişmiş Ağ Gizliliği Mimarileri](advanced-network-privacy-architectures.md) sayfasına geçin.



## References

- [1] [EFF — Size Uygun VPN'i Seçmek](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Cihaz güvenliği kılavuzu: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Tor'un sunduğu gizlilik ve anonimlik korumaları](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Tor'a kısa bir giriş](https://spec.torproject.org/intro/)
- [5] [Tor Project — Tor'u diğer browser'larla kullanma](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Tor Browser'daki plugin'ler ve eklentiler](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Tor engelini aşma](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Tor Browser'ı VPN ile kullanma](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Halka açık Wi-Fi ağları güvenli midir?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Apple cihazlarında Wi-Fi gizliliği](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — MAC randomization uygulama](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Güvenli ayrıcalıklı erişim workstation'ları için ilkeler](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Zorunlu SIM kaydı: politika ve düzenleyici perspektifler](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — DNS Gizlilik Hizmeti Operatörleri için Öneriler](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Tehdit Modeli](https://katzenpost.network/docs/threat_model/)
- [18] [Xue ve diğerleri — Tünelleri atlatma: Rota tablolarını kötüye kullanarak VPN istemcisi trafiğini sızdırma](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Saldırganlar rota tabanlı VPN'lerin perdesini nasıl kaldırabilir ve tam VPN leak'ine yol açabilir?](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [Yggdrasil SSS: Yggdrasil anonim midir?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [Yggstack README](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
