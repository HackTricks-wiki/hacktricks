# Yapay Zeka Ajanı Güvenlik Metodolojisi

{{#include ../banners/hacktricks-training.md}}

Ajan değerlendirmesi, **saldırganın kontrolündeki girdiden harici olarak gözlemlenebilir bir etkiye** uzanan yolu izlemelidir. Jailbreaking, karakter değişiklikleri ve system prompt'un ifşa edilmesi, bir akıl yürütme kanalının etkilenebilir olduğunu gösterir; ancak yüksek etkili bulgu, bu etkinin veri erişimine, yetkisiz bir araç eylemine, sonraki aşamadaki bir enjeksiyon noktasına, kalıcılığa veya başka bir ajana uzanan zinciridir.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), kapsamı etiketlemek için kullanışlıdır (hedef ele geçirme, araçların kötüye kullanılması, yetki suistimali, tedarik zinciri, kod yürütme, bellek zehirleme, ajanlar arası güven, zincirleme hatalar, insan güveni ve başına buyruk ajanlar). Bu etiketleri, uçtan uca bir saldırı yolu oluşturduktan sonra kullanın; modelin beklenmedik metin üretmesini testin sonu olarak görmeyin.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedef haritasını oluşturun

Payload'ları yazmadan önce her ajan iş akışı için şu beş boyutu kaydedin:<sup>[[2]](#references)</sup>

| Boyut | Nelerin listeleneceği | Güvenlik sorusu |
|---|---|---|
| **Güvenilmeyen girdi** | Chat/API parametreleri, URL'ler, belgeler, e-postalar, destek kayıtları, takvim girdileri, alınan parçalar, bellek, araç sonuçları ve eş ajanlardan gelen mesajlar | Saldırgan, daha sonra model bağlamına girecek içeriği nereye yerleştirebilir? |
| **Araçlar** | Araç adları ve şemaları, yan etkiler, otomatik yürütme, onay davranışı ve dinamik olarak yüklenen araçlar | Hangi çağrılar sırları okuyabilir, durumu değiştirebilir, mesaj gönderebilir, verileri silebilir, kod yürütebilir veya değer aktarabilir? |
| **Yetki** | Kullanıcı yetkilendirmesi, service account'lar, API token'ları, kimlik bilgisi ömrü, tenant/kaynak kapsamı ve ağ erişimi | Her çağrı hangi kimlikle çalışıyor ve yetkilendirme araç sınırında yeniden kontrol ediliyor mu? |
| **İşleme** | Sorgu oluşturucular, shell'ler, URL fetcher'lar, şablon motorları, yorumlayıcılar, parser'lar, dosya işlemleri ve deserializer'lar | Model tarafından oluşturulan veri nerede başka bir yorumlayıcı için sözdizimine dönüşüyor? |
| **Çıktı** | Yanıtlar, işlenen Markdown/HTML, bağlantılar, görsel istekleri, webhook'lar, e-postalar, dosyalar, log'lar, raporlar, metrikler ve eş ajan trafiği | Hangi gözlemlenebilir kanal bir sırrı taşıyabilir veya ikincil bir isteği tetikleyebilir? |

Bunu, reklamı yapılan entegrasyonların listesine indirgemeyin. Yararlı bir çıktı; her kaynağı ulaştığı tam bağlam konumuna, o noktada kullanılabilen araçlara, her aracın kullandığı kimlik bilgisine, sonraki aşamadaki yorumlayıcıya ve tüm dışarı veri aktarım yollarına eşler. Aynı araç, kullanıcıya özel bir okuma token'ıyla düşük etkili; ortak bir yönetici kimlik bilgisiyle ise kritik olabilir.<sup>[[2]](#references)</sup>

## Keşif

### Her teslim ve veri alım yolunu haritalayın

Teslim yüzeyinden (web, mobil, API, e-posta, chat platformu, browser extension) başlayıp istemci ile backend arasındaki trafiği proxy üzerinden inceleyin. Arayüzde gizlenen alanları, arama/otomatik tamamlama/filtre parametrelerini, konuşma durumu nesnelerini, yükleme ve indeksleme işlerini, araç yanıtlarını ve alt ajan trafiğini inceleyin. Gerçek istek şeması görünür hâle gelmeden önce certificate pinning'i aşmak için yalnızca mobil istemcilerde emulator ve instrumentation gerekebilir.<sup>[[2]](#references)</sup>

Ardından modelin altındaki yığını haritalayın: orkestrasyon framework'ü, prompt'un bir araya getirilmesi, retrieval ve bellek depoları, runtime (örneğin Python, container veya WASM), mount edilmiş volume'lar, host servisleri, dahili API'ler, cloud metadata erişilebilirliği ve komşu ağlar. Framework varsayılanları önemlidir; çünkü bazı “tool call”lar kod üretilerek veya değerlendirilerek uygulanır. Sonucun sınırlar içinde kalıp kalmayacağını runtime/sandbox sınırı belirler.<sup>[[2]](#references)</sup>

### Yönlendirmeyi zararsız problarla belirleyin

Kapsam içindeki bir isteği, tam yanıtı, durum kodunu, gecikmeyi ve streaming davranışını koruyarak birkaç ilgisiz istekle karşılaştırın. Göreve özgü herhangi bir akıl yürütmeden önce gelen istikrarlı bir ret, ayrı bir gateway/classifier bulunduğunu gösterebilir; bağlama duyarlı bir ret, isteğin modele ulaştığına işaret eder; boş veya yalnızca bilgi çıkaran bir yanıt ise anahtar kelime aramasını ya da dar kapsamlı retrieval'ı gösterebilir. Bunları varsayım olarak ele alın ve aynı probu alternatif API alanları ile veri alım yollarından tekrar göndererek doğrulayın.<sup>[[2]](#references)</sup>

Keşif, değerlendirme saldırganın kontrolündeki hangi en erken kaynağın ajan davranışını değiştirdiğini **ve** bu kaynaktan erişilebilen araçları, kimlikleri, yorumlayıcıları ve çıktıları belirleyebildiğinde tamamlanır.<sup>[[2]](#references)</sup>

## Exploitation: bir güven sınırını aşın

Yalnızca prompt ifadesini değil, kanalları da test edin. Görünen ön kapının neleri engellediğini belirlemek için doğrudan enjeksiyonla başlayın; ardından eşdeğer amacı aşağıdaki daha az görünür yollardan tekrar deneyin:<sup>[[2]](#references)</sup>

- **Dolaylı içerik:** sayfalar, dosyalar, e-postalar, destek kayıtları, metadata, alt metin, HTML yorumları, ekran dışı metin veya zero-width karakterler. Payload iletme teknikleri için [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) sayfasına bakın.
- **Retrieval ve bellek:** daha sonra alınacak içeriği veya sonraki oturumlarda yeniden yüklenecek durumu zehirleyin. Orijinal kaynağın silinmesinin davranışı ortadan kaldırıp kaldırmadığını kaydedin.
- **Araç çıktısı ve eş ajanlar:** dahili trafiğin yalnızca kullanıcı girdisine ve son çıktıya uygulanan filtreleri atlayıp atlamadığını test etmek için işaretçiyi bir araç yanıtına veya ajandan ajana gönderilen mesaja yerleştirin.
- **Tedarik zinciri:** araç tanımlayıcılarını, eklentileri, bağlı sunucuları, becerileri, modelleri ve bağımlılıkları güvenilir talimat kaynakları olarak inceleyin. MCP'ye özgü testler için [MCP Servers](AI-MCP-Servers.md#mcp-vulns) sayfasına bakın.
- **İnsan onayı:** gerçek yapılandırılmış araç çağrısını modelin oluşturduğu onay metniyle karşılaştırın. Saldırganın etkisinin hedefi, kapsamı, etkilenen nesneleri veya geri alınamaz yan etkileri atlamaya yol açıp açamayacağını test edin.

Önce zararsız, benzersiz bir işaretçi kullanın. Kaynak öğeyi, gözlemlenebiliyorsa bir araya getirilmiş bağlamı, seçilen araç çağrısını, onay verilerini, backend isteğini/yanıtını ve son durumu saklayın. Böylece etki yaratma ile bir eylemin gerçekleştiğine dair halüsinasyon iddiasını birbirinden ayırabilirsiniz.<sup>[[2]](#references)</sup>

### Alt ajan bağlam yalıtımı

Claude Agent SDK'de fork kullanmayan bir alt ajan kendi `AgentDefinition.prompt`'unu, delegasyon prompt'unu ve kullanabildiği araçları alır; ancak üst ajanın system prompt'unu veya konuşmasını almaz. Tanımında `tools` belirtilmezse alt ajanlar için kullanılabilen araçları devralır; proje `CLAUDE.md` dosyası yine de yüklenebilir. Bu nedenle, alt ajan aynı filesystem veya execution araçlarını kullanabiliyorsa yalnızca üst ajana yönelik bir prompt kısıtlaması güvenilir bir sınır oluşturmaz.<sup>[[4]](#references)</sup>

Sınırı, üst ajanın reddettiği doğrudan bir isteği aynı görev, adı belirtilmiş bir alt ajana devredildiğinde karşılaştırarak test edin. NCC Group, reddedilen bir işletim sistemi dosya listeleme işleminin, alt ajana zararsız bir "layout map" olarak yeniden çerçevelendiğinde başarılı olduğunu bildiriyor.<sup>[[3]](#references)</sup>

Yalnızca üst ajanın son yanıtını değil, alt ajanın gerçek araç çağrılarını ve etkin araç izin listesini inceleyin; alt ajanın üst ajanın erişemediği dosyalara erişip erişmediğini doğrulayın.<sup>[[4]](#references)</sup> Bu, bir guardrail devralma hatasıdır; [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) veya container escape kanıtı değildir.<sup>[[3]](#references)[[4]](#references)</sup>

## Yürütme: gerçek etkiyi kanıtlayın

Etkiden sonuca giden birbirinden farklı iki yol vardır:<sup>[[2]](#references)</sup>

1. **Yeteneğin kötüye kullanılması:** Yetkilendirilmiş araç hedeflenen işi zaten yapıyordur. Örnekler: bir tenant'ın kaydını okuyup saldırganın görebildiği bir rapora yazmak, e-posta göndermek, kayıtları değiştirmek, bir dosyayı silmek veya ödeme başlatmak. İkincil bir yazılım açığı gerekmez.
2. **Sonraki aşamadaki injection noktasının exploit edilmesi:** Saldırganın yönlendirdiği model çıktısı başka bir bileşen için sözdizimine dönüşür. [SQL injection](../pentesting-web/sql-injection/README.md) veya [NoSQL injection](../pentesting-web/nosql-injection.md) için database query'lerini, [command injection](../pentesting-web/command-injection.md) için shell wrapper'larını, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md) için seçilen URL'leri, path traversal için dosya işlemlerini, RCE için şablon/kod değerlendiricilerini ve [unsafe deserialization](../pentesting-web/deserialization/README.md) için nesne parser'larını inceleyin.

Her aday için şu zinciri kanıtlayın:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Salt okunur bir entegrasyon, okuduğu verileri daha sonraki herhangi bir bileşen yayımlayabiliyorsa yine de istismar edilebilir. Sıradan yanıtların yanı sıra saldırganın kontrolündeki bağlantılar, otomatik görsel alma, webhook'lar, günlükler, raporlar, sayaçlar, bildirimler ve diğer agent'lara gönderilen mesajlar gibi daha az belirgin veri çıkışlarını da test edin.<sup>[[2]](#references)</sup>

## Hedeflere yönelik eylemler

Bir eylemi doğruladıktan sonra, ilk görünür etkide durmak yerine etki alanının tamamını değerlendirin:<sup>[[2]](#references)</sup>

- **Veri sızdırma:** Sırlar, kullanıcı kayıtları, dahili dosyalar, konuşma verileri veya prompt/bağlam içeriği gözlemlenebilir bir kanal üzerinden dışarı çıkar.
- **Yetkisiz eylem:** Agent, saldırganın amacı doğrultusunda meşru yazma yeteneklerini kullanır.
- **Hizmet engelleme:** Yıkıcı araçlar veya tekrarlanan, maliyetli işlemler bütünlüğü ya da erişilebilirliği etkiler.
- **Kalıcılık:** Zehirlenmiş bellek, dizine eklenmiş içerik, güvenilir durum veya çalışma zamanı değişiklikleri, bunları oluşturan oturum ya da kaynak kaldırıldıktan sonra da varlığını sürdürür.
- **Yayılma:** Güvenilir bir eş, ele geçirilmiş agent'ın mesajını veya paylaşılan durumunu kullanır ve kendi araçlarıyla kimlik bilgilerini kullanarak eylemi tekrarlar.

Önem derecesi, modelin metninin ne kadar şaşırtıcı göründüğüne değil; erişilebilir verilere, etkin ayrıcalıklara, sink'in istismar edilebilirliğine, veri çıkışına, kalıcılığa ve yayılmaya göre belirlenmelidir.<sup>[[2]](#references)</sup>

## Değerlendirme sırasında doğrulanacak kontroller

Prompt filtreleri ve daha iyi bir system prompt saldırganın işini zorlaştırabilir; ancak bunlar yetkilendirme sınırları olarak görülmemelidir. Aşağıdaki kontrolleri, aynı zinciri doğrudan girdi, dolaylı içerik, bellek, araçlar ve eş agent'lar üzerinden yeniden çalıştırarak doğrulayın:<sup>[[2]](#references)</sup>

- Deterministik bir policy katmanı, **her araç çağrısında** kimliği doğrulanmış kullanıcıyı, tenant'ı, nesneyi, eylemi ve hedefi denetler; model çağıranın kimliğini sağlayamaz veya değiştiremez.
- Okuma ve yazma yetenekleri ayrı, en az ayrıcalıklı ve kısa ömürlü kimlik bilgileri kullanır; yüksek etkili araçlar yalnızca gerektiğinde kullanıma açılır ve alınan içerikten otomatik olarak hiçbir zaman çalıştırılmaz.
- Ağ veri çıkışı ve dahili hedefler, modelin seçtiği URL'lerden bağımsız olarak izin listesine alınır; gerekli olmadıkça çalışma zamanının metadata uç noktalarına, bağlı sırlara ve komşu hizmetlere erişimi engellenir.
- Onay arayüzü, kanonik yapılandırılmış isteğe göre oluşturulur ve serbest biçimli bir model özeti yerine tam argümanları, kimliği, hedefi, etkilenen nesneleri ve yan etkileri gösterir.
- Başarı, hedef sistemden veya doğruluk kaynağı olan sistemden doğrulanır. Agent'ın anlatımı, bir araç çağrısı isteği veya HTTP yönlendirmesi, iddia edilen durum değişikliğinin kanıtı değildir.
- Bellek ve retrieval girdileri kaynak bilgilerini ve güven etiketlerini korur, geçersiz kılınabilir ve daha sonraki bir eylemde kullanıldıklarında yeniden yetkilendirilir.
- Agent'lar arası mesajlar, güvenilmeyen istekler olarak kimlik doğrulamasından ve yetkilendirmeden geçirilir; bir eşin itibarı veya agent card'ı, alıcının araçlarını örtük olarak devretmez.

## References

- [1] [2026 için Agentic Uygulamalara Yönelik OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent'lara Saldırı: Hacker'ın Rehberi](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Bir AI Agent'ı Sandbox'ından Çıkarmak Gerçekten Ne Kadar Zor?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK'deki Subagent'lar](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
