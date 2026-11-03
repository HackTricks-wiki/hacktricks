# Endüstriyel Kontrol Sistemlerine Saldırı

{{#include ../banners/hacktricks-training.md}}

## Bu Bölüm Hakkında

Bu bölümde endüstriyel kontrol sistemi (ICS) bileşenleri, mimarileri, protokolleri ve güvenlik değerlendirme yöntemleri tanıtılmaktadır. ICS, fiziksel süreçleri izleyen veya bu süreçlerde değişikliğe neden olan programlanabilir sistem ve cihazları kapsayan daha geniş operasyonel teknoloji (OT) alanının bir parçasıdır. Yaygın örnekler arasında denetleyici kontrol ve veri toplama (SCADA) sistemleri, dağıtık kontrol sistemleri (DCS'ler) ve programlanabilir lojik denetleyiciler (PLC'ler) bulunur.<sup>[[1]](#references)</sup>

Bu ortamlardaki güvenlik çalışmaları; proses güvenliği, güvenilirlik, kullanılabilirlik, deterministik çalışma ve ekipman yaşam döngüleri gibi geleneksel BT'den farklı gereksinimleri dikkate almalıdır. Teknik açıdan geçerli bir güvenlik kontrolü bile fiziksel süreci aksatıyorsa uygun olmayabilir. Bu nedenle test ve düzeltme çalışmaları sistem sahibi ve operasyon personeliyle koordineli yürütülmelidir.<sup>[[1]](#references)</sup>

Sistemin ele geçirilmesi veya kazara aksatılması üretimi durdurabilir, ekipmana zarar verebilir, tehlikeli maddelerin salınmasına, çevresel zarara, yaralanmaya veya can kaybına yol açabilir. Bu olası fiziksel etkiler nedeniyle, aktif testlerden önce kontrol edilen süreci ve güvenli çalışma sınırlarını anlamak gerekir.<sup>[[1]](#references)</sup>

Birçok OT kurulumu, ekipmanların uzun hizmet ömrü ve değişikliklerin operasyonel ve güvenlik testleri gerektirmesi nedeniyle eski işletim sistemlerini, uygulamaları ve protokolleri kullanmaya devam eder. Bazı protokoller modern kimlik doğrulama veya şifreleme olmadan tasarlanmıştır. Yama uygulamak da tedarikçi desteği veya bakım zaman aralıkları nedeniyle kısıtlanabilir; doğrudan yükseltmenin mümkün olmadığı durumlarda ağ segmentasyonu, erişim denetimi ve izleme ile bu eksiklikleri telafi edin.<sup>[[1]](#references)</sup>

## Değerlendirme Öncelikleri

Kontrol edilen süreci, sistem sınırlarını, ağ topolojisini, varlıkları, veri akışlarını, güven ilişkilerini ve harici bağlantıları anlayarak başlayın. Benzer cihaz türleri farklı tesislerde farklı işlevler görebilir; bu nedenle bir kurulumun mimarisinin veya etki modelinin başka bir kurulum için de geçerli olduğunu varsaymayın.<sup>[[1]](#references)</sup>

Mümkün olduğunda pasif keşfi ve mevcut mühendislik belgelerini tercih edin. Her türlü aktif tarama veya exploitation, güvenlik kısıtlarını, bakım zaman aralıklarını, kurtarma prosedürlerini ve durdurma koşullarını tanımlayan onaylı bir test planına uygun olmalıdır. Bulgular hem siber güvenlik etkileri hem de fiziksel süreç üzerindeki olası etkileri açısından değerlendirilmelidir.<sup>[[1]](#references)</sup>

Aynı mimari bilgisi; varlık envanteri, ağ segmentasyonu, izleme, olay müdahalesi ve risk temelli güvenlik açığı yönetimi gibi savunma faaliyetlerini de destekler.<sup>[[1]](#references)</sup>

## Süpervizör soğutma kontrol cihazının kötüye kullanılması

Bir soğutma sistemi yöneticisi, kompresör ve vitrin kontrol cihazlarını koordine eder ancak vitrinleri kendisi soğutmaz. Bu nedenle yönetim arayüzüne erişim, normal yapılandırma dağıtımı yoluyla birçok bağlı cihazın kontrolünü sağlayabilir. Bu, tek bir termostatı değiştirmekten veya bir kompresörü doğrudan çalıştırmaktan farklıdır.<sup>[[3]](#references)[[4]](#references)</sup>

### Tarihten türetilen bakım koduyla giriş

Etkilenen Danfoss sistem yöneticilerinde alternatif bir XML girişi, hesap parolası yerine kontrol cihazının tarihinden türetilen bir kodu kabul eder.<sup>[[2]](#references)[[3]](#references)</sup> Synacktiv, SM800 ve SC255 üzerinde `eds_only` ve `quantum_only` özniteliklerini `xml_load_file` ve `check_authorize` üzerinden `check_code_of_day` işlevine kadar izledi. Danışma belgesi ayrıca `xml.cgi` üzerindeki `read_date_time` işlevinin kontrol cihazının tarihini kimlik doğrulaması olmadan açıkladığını gösteriyor.<sup>[[2]](#references)</sup> Claroty, AK-SM 800A üzerinde buna karşılık gelen bir `getauth` yolu buldu ancak tetikleyici öznitelikleri sansürledi; eski modellerdeki öznitelik adlarının bu platformda da çalıştığı varsayılmamalıdır.<sup>[[3]](#references)</sup>

Synacktiv, kimlik doğrulaması gerektirmeyen tarih sorgusunu şöyle belgeliyor:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Kodun cihaza özgü bir sırrı yoktur: [firmware](../hardware-physical-access/firmware-analysis/) üzerinden algoritmanın elde edilmesi, aynı etkilenen uygulamaya sahip cihazlar için tarihi geçerli bir kimlik bilgisi sağlayabilir.<sup>[[2]](#references)[[3]](#references)</sup> Önce modeli ve firmware sürümünü doğrulayın. Tek başına tarih yanıtı, alternatif giriş yönteminin mevcut olduğunu veya bir oturum elde edildiğini kanıtlamaz.

### Toplu yapılandırma ve defrost ısıtıcısının kötüye kullanımı

Yönetici erişimini elde ettikten sonra, sistem yöneticisine eşlenmiş kasa denetleyicilerini ve yapılandırma dağıtım işlevinin bunları birlikte güncelleyip güncelleyemediğini belirleyin. Kasa sıcaklık ayarının değiştirilmesi normalde kabini yalnızca oda sıcaklığına kadar ısıtır. Ortam sıcaklığının üzerine çıkarmak için kullanılacak kontrol, kasa denetleyicisinin elektrikli evaporatör defrost ısıtıcısıdır: defrost sırasında soğutma durur ve bir sensör veya zamanlayıcı döngüyü sonlandırana kadar bu ısıtıcı çalışır. Defrost yöntemini, zamanlamasını, sonlandırma sıcaklığını ve süre sınırını değiştirmek ısıtıcının çalışmaya devam etmesini sağlayabilir. Yönetici bu değişiklikleri birçok kasaya dağıtıp ilgili alarmları bastırabilir; böylece tek bir denetim sistemi ihlali, mağaza genelinde bir süreç değişikliğine dönüşebilir.<sup>[[4]](#references)</sup>

Bu, fiziksel süreç açısından tehlike oluşturur; canlı sistemde güvenli bir kavram kanıtı değildir. Varsa termal kesiciler ısıtıcının çalışmasını sınırlayabilir, ancak sürekli çalışma, önceden zayıflamış bir elektrik bağlantısının yine de aşırı ısınmasına yol açabilir. Yapılandırmayı ve etkisini yalnızca onaylı bir laboratuvarda veya operatörün süreç güvenliği planına uygun şekilde doğrulayın.<sup>[[4]](#references)</sup>

## Protocol entry points

- [Modbus testi](../network-services-pentesting/pentesting-modbus.md), Modbus TCP'yi, seri varyantları, function code'ları ve register erişimini kapsar.
- [OPC UA testi](../network-services-pentesting/4840-pentesting-opc-ua.md), endüstriyel veri alışverişi hizmetini kapsar.
- [BACnet testi](../network-services-pentesting/47808-udp-bacnet.md), bina otomasyon kontrol ağlarını kapsar.

## References

- [1] [NIST SP 800-82 Rev. 3 - Operasyonel Teknoloji (OT) Güvenlik Kılavuzu](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Danfoss System-Managers SM800 ve SC255'te kimlik doğrulama atlatma](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Denetleyiciyi Dondur, Yiyeceğin Buzunu Çöz](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Buzdolabını ısıtmak için ulus devlet olmanız gerekmez](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
