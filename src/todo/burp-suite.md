# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload türleri

Burp Intruder aşağıdaki yerleşik payload oluşturucuları ve dönüşümlerini içerir:<sup>[[1]](#references)</sup>

- **Simple list:** Payload olarak yapılandırılmış bir dize listesini kullanır.
- **Runtime file:** Çalışma zamanında her satırdan bir payload okur. Burp dosyanın tamamını belleğe yüklemediğinden bu, büyük listeler için kullanışlıdır.
- **Case modification:** Değiştirilmemiş değeri, küçük harfli ve büyük harfli biçimlerini, `Propername` (ilk harf büyük, geri kalanı küçük) veya `ProperName` (ilk harf büyük, kalan karakterler değiştirilmeden) biçimini üretir. Burp yinelenen sonuçları eler.
- **Numbers:** Yapılandırılmış bir aralıkta ardışık veya rastgele sayılar üretir.
- **Brute forcer:** Seçilen bir karakter kümesi ile minimum/maksimum uzunluk için tüm permütasyonları üretir.

## Eklentiler ve yardımcı araçlar

- **Collabfiltrator**, komutları çalıştıran ve çıktısını DNS sorguları üzerinden Burp Collaborator'a sızdıran payload'lar üretir.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**, diğer raporlama iş akışlarında kullanılmak üzere Burp bulgularını dışa aktarır.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**, HTTP isteklerini çeşitli dillerdeki script'lere dönüştürür.<sup>[[4]](#references)</sup>

## Session Switcher ile çoklu oturum yetkilendirme testi

[Session Switcher](https://github.com/doyensec/burp-session-switcher), çerezleri ve yaygın olmayan başlıkları adlandırılmış kimlik bilgisi profilleri olarak saklayan, Burp Suite `2025.5+` için bir Java eklentisidir. Repeater veya yakalanan bir Proxy isteği dâhil olmak üzere düzenlenebilir bir istek düzenleyicisinde profil seçildiğinde, isteğin kimlik doğrulama bilgileri değiştirilir. Bu bir replay kolaylığıdır, **yetki atlatma değildir**: yatay erişimi, dikey rol sınırlarını, tenant izolasyonunu ve [web test metodolojisinin](../pentesting-web/web-vulnerabilities-methodology.md) bir parçası olarak [IDOR/BOLA](../pentesting-web/idor.md) durumlarını kontrol ederken aynı isteği farklı hesaplar adına göndermek için kullanın.<sup>[[5]](#references)[[8]](#references)</sup>

### Tekrarlanabilir kimlik farkı iş akışı

Aşağıdaki iş akışı kaynak/eylem ile isteği gerçekleştiren kimliği ayrı test değişkenleri olarak tutar; böylece güncel olmayan token'ların veya yanlış tarayıcı oturumunun neden olduğu hatalı sonuçları azaltır.<sup>[[5]](#references)[[8]](#references)</sup>

1. İlgili her kullanıcıyı, rolü ve tenant'ı temsil eden test hesaplarıyla ayrı tarayıcı profillerinde veya container'larda kimlik doğrulaması yapın.
2. Bir kimliğin çerezlerini ve başlıklarını içeren isteği açın, **Sessions > New** seçeneğini belirleyin ve profile `tenant-a-user` veya `tenant-b-admin` gibi açık bir ad verin. Her test kimliği için bu adımı tekrarlayın.
3. Aday bir isteği Repeater'a gönderin ve yalnızca seçili oturumu değiştirerek; yöntemi, endpoint'i, parametreleri veya nesne tanımlayıcısını değiştirmeden yeniden gönderin. Yalnızca durum kodlarını değil, yanıt verilerini ve gözlemlenebilir durum değişikliklerini karşılaştırın.
4. Nesne düzeyindeki kontrollerde, A hesabına ait olduğu bilinen bir nesneye yönelik isteği B hesabının profili seçiliyken yeniden gönderin. İşlev düzeyindeki kontrollerde, aynı ayrıcalıklı eylemi daha düşük ayrıcalıklı profillerle yeniden gönderin.
5. Yeniden kimlik doğrulaması veya token rotasyonundan sonra karşılaştırmayı tekrarlamadan önce geçerli bir tarayıcı isteğinde **Update** seçeneğini kullanın veya bir Auto Update kuralı yapılandırın.

### Yakalama ve enjeksiyon anlamları

Testten önce güncelleme/enjeksiyon modlarını gözden geçirin; çünkü iki kimliğin kimlik bilgilerini içeren karma bir istek karşılaştırmayı geçersiz kılabilir. Geçerli varsayılanlar tüm istek çerezlerini bir profile yansıtır, yalnızca önceden saklanmış yaygın olmayan başlıkları günceller, seçili profilin çerezlerini hedef isteğe yansıtır (mevcut çerezlerini kaldırır) ve profilin başlıklarını ekler. Seçici; tam bir alt alan adıyla, üst düzey uygulama alan adıyla (varsayılan) veya kaydedilmiş tüm profillerle sınırlandırılabilir.<sup>[[7]](#references)</sup>

- **Mirror**, tüm çerez kümesinin kimliği belirlediği ve hedefteki güncel olmayan çerezlerin kaldırılması gerektiği durumlarda kullanışlıdır.
- **Update existing**, tarayıcı trafiğinden ilgisiz çerez veya başlıkları öğrenmeden dönen değerleri takip eder.
- **Add all**, profilde veya istekte zaten saklanmış ek değerleri korur; önceki oturumdan kalan kimlik belirleyici verilerin bulunmadığını doğrulayın.
- **Do nothing**, kimlik bilgisi sınıfı ilgisiz olduğunda çerezlerin veya başlıkların profil güncellemelerine dâhil edilmesini engeller.

### Proxy tabanlı oturum senkronizasyonu

Auto Update kuralları, Proxy trafiğini kaydedilmiş bir profille ilişkilendirir ve profilin çerezlerini/başlıklarını yeniler. Özel bir istek başlığı, profile özgü bir `User-Agent` işaretleyicisi, tanımlayıcı bir çerez, `X-PwnFox-Color` veya bir JWT claim'i gibi kararlı bir ayırt edici tercih edin; ilgisiz uygulamaların profili güncellemesini önlemek için bunu scope/alan adı/yol koşullarıyla birleştirin. Tek bir kuraldaki tüm koşullar sıralı olarak mantıksal `AND` şeklinde değerlendirilir; bu nedenle kısıtlayıcı kontrolleri önce ekleyin. `OR` mantığını uygulamak için aynı profili hedefleyen birden fazla kural oluşturun. Negatif eşleştirme de desteklenir.<sup>[[6]](#references)</sup>

Eşleşen her kural için çerezler ve başlıklar bakımından ayrı ayrı **Mirror request**, **Add all**, **Update existing** veya **Do nothing** seçeneklerinden birini belirleyin. Yalnızca istek içeren kurallar, Proxy isteği aldığında çalışır; yanıt durumu, yanıt başlığı veya yanıt gövdesi koşulu eklemek değerlendirmeyi yanıt gelene kadar erteler. Vurgu rengi eşleşen trafiği işaretleyebilir; böylece her tarayıcı kimliğinin yalnızca amaçlanan profili güncellediğini doğrulamak kolaylaşır.<sup>[[6]](#references)</sup>

Kaydedilmiş profiller Burp projesinde tutulur ve JSON proje verisi dışa aktarımları oturumları, dolayısıyla çerezlerini ve başlıklarını da içerir. Her iki dosyayı da etkin kimlik bilgisi materyali olarak değerlendirin, erişimlerini kısıtlayın ve çalışma tamamlandıktan sonra saklanan eklenti verilerini silin.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger belgeleri - Burp Intruder payload türleri](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher kaynak kodu ve kullanım belgeleri](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher Auto Update kuralları](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher ayarları](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Burp Suite'te çoklu oturum yetkilendirme testini kolaylaştırma](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
