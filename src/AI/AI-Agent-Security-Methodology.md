# AI Agent Güvenlik Metodolojisi

{{#include ../banners/hacktricks-training.md}}

Bir agent değerlendirmesi, **saldırganın kontrolündeki girdiden dışarıdan gözlemlenebilir bir etkiye** uzanan yolu izlemelidir. Jailbreaking, karakter değişiklikleri ve system prompt'un ifşa edilmesi, bir akıl yürütme kanalının etkilenebildiğini kanıtlar; ancak yüksek etkili bulgu, veri erişimine, yetkisiz bir araç eylemine, sonraki aşamadaki bir injection sink'e, kalıcılığa veya başka bir agent'a uzanan zincirdir.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), kapsamı etiketlemek için yararlıdır (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust ve rogue agents). Bu etiketleri, modelin beklenmedik metnini testin sonu saymak yerine uçtan uca bir saldırı yolu oluşturduktan sonra kullanın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedef haritasını oluşturun

Payload yazmadan önce her agent iş akışı için şu beş boyutu kaydedin:<sup>[[2]](#references)</sup>

| Boyut | Nelerin listeleneceği | Güvenlik sorusu |
|---|---|---|
| **Güvenilmeyen girdi** | Chat/API parametreleri, URL'ler, belgeler, e-posta, ticket'lar, takvim kayıtları, alınan parçalar, bellek, araç sonuçları ve peer-agent mesajları | Saldırgan içeriği daha sonra model bağlamına girecek şekilde nereye yerleştirebilir? |
| **Araçlar** | Araç adları ve şemaları, yan etkiler, otomatik yürütme, onay davranışı ve dinamik olarak yüklenen araçlar | Hangi çağrılar sırları okur, durumu yazar, mesaj gönderir, verileri siler, kod çalıştırır veya değer aktarır? |
| **Yetki** | Kullanıcı yetkilendirmesi, service account'lar, API token'ları, kimlik bilgilerinin geçerlilik süresi, tenant/kaynak kapsamı ve ağ erişimi | Her çağrı hangi kimlikle çalışır ve yetkilendirme araç sınırında yeniden denetlenir mi? |
| **İşleme** | Sorgu oluşturucular, shell'ler, URL fetcher'lar, template engine'ler, yorumlayıcılar, parser'lar, dosya işlemleri ve deserializer'lar | Model tarafından oluşturulan veriler başka bir yorumlayıcı için nerede syntax'a dönüşür? |
| **Çıktı** | Yanıtlar, işlenmiş Markdown/HTML, bağlantılar, görsel fetch'leri, webhook'lar, e-posta, dosyalar, log'lar, raporlar, metrikler ve peer-agent trafiği | Hangi gözlemlenebilir kanal sır taşıyabilir veya ikincil bir isteği tetikleyebilir? |

Bunu, duyurulan entegrasyonların bir listesine indirgemeyin. Yararlı bir çıktı; her kaynağı ulaştığı tam bağlam konumuna, o noktada kullanılabilen araçlara, her aracın kullandığı kimlik bilgilerine, sonraki aşamadaki yorumlayıcıya ve tüm dışarı veri aktarımı yollarına eşler. Aynı araç, kullanıcı başına verilen bir read token ile düşük etkili, paylaşılan bir yönetici kimlik bilgisiyle kritik etkili olabilir.<sup>[[2]](#references)</sup>

## Keşif

### Tüm iletim ve veri alma yollarının haritasını çıkarın

İletim yüzeyinden (web, mobil, API, e-posta, chat platformu, browser extension) başlayıp istemci ile backend arasındaki trafiği proxy üzerinden inceleyin. UI tarafından gizlenen alanları, arama/otomatik tamamlama/filtre parametrelerini, konuşma durumu nesnelerini, yükleme ve indeksleme işlerini, araç yanıtlarını ve sub-agent trafiğini inceleyin. Gerçek istek şemasını görebilmek için mobil istemcilerde sertifika pinning'i aşmak üzere bir emulator ve instrumentation gerekebilir.<sup>[[2]](#references)</sup>

Ardından modelin altındaki stack'in haritasını çıkarın: orchestration framework'ü, prompt assembly, retrieval ve memory store'ları, runtime (örneğin Python, container veya WASM), mount edilmiş volume'ler, host servisleri, dahili API'ler, cloud metadata erişilebilirliği ve komşu ağlar. Framework varsayılanları önemlidir; çünkü bazı “tool call” işlemleri kod oluşturup çalıştırarak gerçekleştirilir. Sonucun kapsam içinde kalıp kalmadığını runtime/sandbox sınırı belirler.<sup>[[2]](#references)</sup>

### Tahribatsız probe'larla yönlendirmeyi belirleyin

Kapsam dahilindeki bir isteği, tam yanıtı, durum kodunu, gecikmeyi ve streaming davranışını koruyarak birkaç ilgisiz istekle karşılaştırın. Göreve özgü akıl yürütme başlamadan önce verilen tutarlı bir ret, ayrı bir gateway/classifier bulunduğuna işaret edebilir; bağlama dayalı bir ret, isteğin modele ulaştığını düşündürür; boş veya tamamen extractive bir yanıt, keyword search ya da dar kapsamlı retrieval kullanıldığına işaret edebilir. Bunları hipotez olarak ele alın ve aynı probe'u alternatif API alanları ve veri alma yolları üzerinden yeniden göndererek doğrulayın.<sup>[[2]](#references)</sup>

Keşif, değerlendirme ekibi agent davranışını değiştiren en erken saldırgan kontrollü kaynağı **ve** bu kaynaktan erişilebilen araçları, kimlikleri, yorumlayıcıları ve çıktıları belirleyebildiğinde tamamlanır.<sup>[[2]](#references)</sup>

## Exploitation: güven sınırını aşın

Yalnızca prompt ifadelerini değil, kanalları test edin. Görünür giriş noktasının neleri engellediğini belirlemek için doğrudan injection ile başlayın, ardından aynı amacı aşağıdaki daha az görünür yollar üzerinden yeniden test edin:<sup>[[2]](#references)</sup>

- **Dolaylı içerik:** sayfalar, dosyalar, e-posta, ticket'lar, metadata, alt text, HTML yorumları, ekran dışı metin veya zero-width karakterler. Payload iletim teknikleri için [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) bölümüne bakın.
- **Retrieval ve bellek:** daha sonra alınacak içeriği veya sonraki oturumlarda yeniden yüklenecek durumu zehirleyin. Orijinal kaynağın silinmesinin davranışı ortadan kaldırıp kaldırmadığını kaydedin.
- **Araç çıktısı ve peer agent'lar:** dahili trafiğin yalnızca kullanıcı girdisine ve son çıktıya uygulanan filtreleri atlayıp atlamadığını test etmek için işaretleyiciyi bir araç yanıtına veya agent'lar arası mesaja yerleştirin.
- **Supply chain:** araç tanımlayıcılarını, plugin'leri, bağlı sunucuları, skill'leri, modelleri ve bağımlılıkları güvenilir talimat kaynakları olarak inceleyin. MCP'ye özgü testler için [MCP Servers](AI-MCP-Servers.md#mcp-vulns) bölümüne bakın.
- **İnsan onayı:** gerçek yapılandırılmış araç çağrısını, model tarafından oluşturulan onay metniyle karşılaştırın. Saldırgan etkisinin hedefi, kapsamı, etkilenecek nesneleri veya geri alınamaz yan etkileri atlamaya yol açıp açamayacağını test edin.

Önce zararsız, benzersiz bir işaretleyici kullanın. Kaynak yapıtı, gözlemlenebiliyorsa oluşturulan bağlamı, seçilen araç çağrısını, onay verisini, backend isteğini/yanıtını ve son durumu saklayın. Böylece etki, eylemin gerçekleştiğine dair halüsinasyon iddiasından ayrılır.<sup>[[2]](#references)</sup>

## Execution: gerçek etkiyi kanıtlayın

Etkiden etkiye uzanan iki farklı yol vardır:<sup>[[2]](#references)</sup>

1. **Capability abuse:** Yetkili araç zaten hedeflenen işi gerçekleştiriyordur. Örnekler arasında bir tenant'ın kaydını okuyup saldırganın görebildiği bir rapora yazmak, e-posta göndermek, kayıtları değiştirmek, dosya silmek veya ödeme başlatmak bulunur. İkincil bir yazılım hatası gerekmez.
2. **Downstream sink exploitation:** Saldırganın yönlendirdiği model çıktısı başka bir bileşen için syntax'a dönüşür. [SQL injection](../pentesting-web/sql-injection/README.md) veya [NoSQL injection](../pentesting-web/nosql-injection.md) açısından veritabanı sorgularını, [command injection](../pentesting-web/command-injection.md) açısından shell wrapper'larını, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md) açısından seçilen URL'leri, path traversal açısından dosya işlemlerini, RCE açısından template/code evaluator'ları ve [unsafe deserialization](../pentesting-web/deserialization/README.md) açısından nesne parser'larını inceleyin.

Her aday için şu zinciri kanıtlayın:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Salt okunur bir entegrasyon, okuduğu verileri daha sonraki herhangi bir bileşen yayımlayabiliyorsa yine de istismar edilebilir. Sıradan yanıtların yanı sıra saldırganın kontrolündeki bağlantılar, otomatik görsel getirme, webhook'lar, log'lar, raporlar, sayaçlar, bildirimler ve diğer agent'lara gönderilen mesajlar gibi daha az belirgin egress kanallarını da test edin.<sup>[[2]](#references)</sup>

## Hedeflere yönelik eylemler

Bir eylemi doğruladıktan sonra, ilk görünür etkide durmak yerine etkinin tüm kapsamını değerlendirin:<sup>[[2]](#references)</sup>

- **Veri sızdırma:** Sırlar, kullanıcı kayıtları, dahili dosyalar, konuşma verileri veya prompt/context içeriği gözlemlenebilir bir kanal üzerinden dışarı çıkar.
- **Yetkisiz eylem:** Agent, saldırganın amacı doğrultusunda meşru yazma yeteneklerini kullanır.
- **Hizmet engelleme:** Yıkıcı araçlar veya yinelenen, maliyetli işlemler bütünlüğü ya da kullanılabilirliği etkiler.
- **Kalıcılık:** Zehirlenmiş bellek, indekslenmiş içerik, güvenilir durum veya çalışma zamanı değişiklikleri, bunları başlatan oturum ya da kaynak kaldırıldıktan sonra da varlığını sürdürür.
- **Yayılma:** Güvenilir bir eş, ele geçirilmiş agent'ın mesajını veya paylaşılan durumunu kullanır ve kendi araçlarıyla kimlik bilgilerini kullanarak eylemi tekrarlar.

Önem derecesi, modelin metninin ne kadar şaşırtıcı göründüğüne değil; erişilebilir verilere, etkin ayrıcalıklara, hedefin istismar edilebilirliğine, egress'e, kalıcılığa ve yayılmaya göre belirlenmelidir.<sup>[[2]](#references)</sup>

## Değerlendirme sırasında doğrulanacak kontroller

Prompt filtreleri ve daha iyi bir sistem prompt'u saldırganın maliyetini artırabilir, ancak yetkilendirme sınırları olarak değerlendirilmemelidir. Aşağıdaki kontrolleri aynı zinciri doğrudan girdi, dolaylı içerik, bellek, araçlar ve eş agent'lar üzerinden yeniden çalıştırarak doğrulayın:<sup>[[2]](#references)</sup>

- Belirley deterministik bir policy katmanı, **her araç çağrısında** kimliği doğrulanmış kullanıcıyı, tenant'ı, nesneyi, eylemi ve hedefi denetler; model, çağıranın kimliğini sağlayamaz veya geçersiz kılamaz.
- Okuma ve yazma yetenekleri ayrı, en az ayrıcalıklı ve kısa ömürlü kimlik bilgileri kullanır; yüksek etkili araçlar yalnızca gerektiğinde sunulur ve içe aktarılan içerikten otomatik olarak çalıştırılmaz.
- Ağ egress'i ve dahili hedefler, modelin seçtiği URL'lerden bağımsız olarak izin listesine alınır; gerekli olmadıkça çalışma zamanının metadata uç noktalarına, bağlanmış sırlara ve komşu servislere erişimi engellenir.
- Onay arayüzü, standart yapılandırılmış istekten oluşturulur ve serbest biçimli bir model özeti yerine tam argümanları, kimliği, hedefi, etkilenecek nesneleri ve yan etkileri gösterir.
- Başarı, hedef sistemden veya kayıt sisteminden doğrulanır. Agent'ın anlatımı, araç çağrısı isteği ya da HTTP yönlendirmesi, iddia edilen durum değişikliğinin kanıtı değildir.
- Bellek ve retrieval kayıtları kaynak bilgilerini ve güven etiketlerini korur, geçersiz kılınabilir ve daha sonraki bir eylemde kullanıldıklarında yeniden yetkilendirilir.
- Agent'lar arası mesajlar, güvenilmeyen istekler olarak kimlik doğrulamasından ve yetkilendirmeden geçirilir; bir eşin itibarı veya agent card'ı, alıcının araçlarını örtük olarak devretmez.

## References

- [1] [2026 için OWASP Agentic Applications İlk 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent'lara Saldırmak İçin Hacker Rehberi](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
