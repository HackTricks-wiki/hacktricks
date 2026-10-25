# AI Agent Güvenlik Metodolojisi

{{#include ../banners/hacktricks-training.md}}

Bir agent değerlendirmesi, **saldırgan denetimindeki girdiden dışarıdan gözlemlenebilir bir etkiye** uzanan yolu izlemelidir. Jailbreaking, karakter değişiklikleri ve system prompt ifşası, bir akıl yürütme kanalının etkilenebildiğini kanıtlar; ancak yüksek etkili bulgu, veriye erişim, yetkisiz bir tool eylemi, aşağı akıştaki bir injection sink, kalıcılık veya başka bir agent’a uzanan zincirdir.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), kapsamı etiketlemek için kullanışlıdır (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust ve rogue agents). Bu etiketleri, uçtan uca bir saldırı yolu oluşturduktan sonra kullanın; modelin beklenmedik metin üretmesini testin sonu olarak görmeyin.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedef haritasını oluşturun

Payload yazmaya başlamadan önce her agent iş akışı için şu beş boyutu kaydedin:<sup>[[2]](#references)</sup>

| Boyut | Nelerin listeleneceği | Güvenlik sorusu |
|---|---|---|
| **Güvenilmeyen girdi** | Chat/API parametreleri, URL'ler, belgeler, e-posta, ticket'lar, takvim kayıtları, alınan parçalar, bellek, tool sonuçları ve eş agent mesajları | Saldırgan, daha sonra model bağlamına girecek içeriği nereye yerleştirebilir? |
| **Tools** | Tool adları ve şemaları, yan etkiler, otomatik yürütme, onay davranışı ve dinamik olarak yüklenen tools | Hangi çağrılar sırları okuyabilir, durumu değiştirebilir, mesaj gönderebilir, veri silebilir, kod yürütebilir veya değer aktarabilir? |
| **Yetki** | Kullanıcı delegasyonu, service account'lar, API token'ları, kimlik bilgilerinin geçerlilik süresi, tenant/kaynak kapsamı ve ağ erişimi | Her çağrı hangi kimlikle çalışıyor ve yetkilendirme tool sınırında yeniden yapılıyor mu? |
| **İşleme** | Sorgu oluşturucular, shell'ler, URL fetcher'ları, template engine'ler, yorumlayıcılar, parser'lar, dosya işlemleri ve deserializer'lar | Model tarafından oluşturulan veri nerede başka bir yorumlayıcı için syntax hâline geliyor? |
| **Çıktı** | Yanıtlar, işlenmiş Markdown/HTML, bağlantılar, görsel fetch'leri, webhook'lar, e-posta, dosyalar, log'lar, raporlar, metrikler ve eş agent trafiği | Hangi gözlemlenebilir kanal bir sırrı taşıyabilir veya ikincil bir isteği tetikleyebilir? |

Bunu, tanıtımı yapılan entegrasyonların listesine indirgemeyin. Kullanışlı bir çıktı; her kaynağı ulaştığı bağlamdaki tam konum, o noktada kullanılabilen tools, her tool'un kullandığı kimlik bilgisi, aşağı akıştaki yorumlayıcı ve tüm egress rotalarıyla eşleştirir. Aynı tool, kullanıcı başına bir read token ile düşük etkili; paylaşılan bir administrator kimlik bilgisiyle kritik olabilir.<sup>[[2]](#references)</sup>

## Keşif

### Her teslimat ve alım yolunu haritalayın

Teslimat yüzeyinden (web, mobil, API, e-posta, chat platformu, browser extension) başlayın ve istemci ile backend arasındaki trafiği proxy'leyin. Arayüzde gizlenen alanları, arama/otomatik tamamlama/filtre parametrelerini, konuşma durumu nesnelerini, yükleme ve indeksleme işlerini, tool yanıtlarını ve sub-agent trafiğini inceleyin. Yalnızca mobilde bulunan istemcilerde, gerçek istek şeması görünür hâle gelmeden önce certificate pinning'i aşmak için bir emulator ve instrumentation gerekebilir.<sup>[[2]](#references)</sup>

Ardından modelin altındaki stack'i haritalayın: orchestration framework'ü, prompt assembly, retrieval ve memory store'ları, runtime (ör. Python, container veya WASM), bağlanan volume'lar, host servisleri, dahili API'ler, cloud metadata erişimi ve komşu ağlar. Framework varsayılanları önemlidir; bazı “tool call” işlemleri kod oluşturup değerlendirilerek gerçekleştirilir. Sonucun sınırlar içinde kalıp kalmadığını runtime/sandbox sınırı belirler.<sup>[[2]](#references)</sup>

### Yönlendirmeyi zararsız probe'larla parmak izine dönüştürün

Kapsam içindeki bir isteği, tam yanıtı, durum kodunu, gecikmeyi ve streaming davranışını koruyarak birden fazla ilgisiz istekle karşılaştırın. Göreve özgü herhangi bir akıl yürütmeden önce gelen tutarlı bir ret, ayrı bir gateway/classifier bulunduğuna işaret edebilir; bağlama duyarlı bir ret, isteğin modele ulaştığını düşündürür; boş veya yalnızca bilgi çıkaran bir yanıt, keyword search ya da dar kapsamlı retrieval bulunduğunu gösterebilir. Bunları hipotez olarak ele alın ve aynı probe'u alternatif API alanları ile alım yollarından yeniden göndererek doğrulayın.<sup>[[2]](#references)</sup>

Keşif, değerlendirme ekibi agent davranışını değiştiren en erken saldırgan denetimindeki kaynağı **ve** bu kaynaktan erişilebilen tools, kimlikler, yorumlayıcılar ve çıktıları belirleyebildiğinde tamamlanır.<sup>[[2]](#references)</sup>

## Exploitation: bir güven sınırını aşın

Yalnızca prompt ifadelerini değil, kanalları test edin. Önce görünür giriş noktasının neleri engellediğini belirlemek için doğrudan injection kullanın; ardından eşdeğer amacı aşağıdaki daha az görünür yollardan yineleyin:<sup>[[2]](#references)</sup>

- **Dolaylı içerik:** sayfalar, dosyalar, e-posta, ticket'lar, metadata, alt text, HTML yorumları, ekran dışında kalan metin veya zero-width karakterler. Payload teslim teknikleri için [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) sayfasına bakın.
- **Retrieval ve bellek:** daha sonra alınacak içeriği veya sonraki oturumlarda yeniden yüklenecek durumu zehirleyin. Orijinal kaynağın silinmesinin davranışı ortadan kaldırıp kaldırmadığını kaydedin.
- **Tool çıktısı ve eş agent'lar:** dahili trafiğin yalnızca kullanıcı girdisine ve son çıktıya uygulanan filtreleri atlayıp atlamadığını test etmek için işaretçiyi bir tool yanıtına veya agent'lar arası mesaja yerleştirin.
- **Supply chain:** tool descriptor'larını, plugin'leri, bağlı sunucuları, skill'leri, modelleri ve bağımlılıkları güvenilir talimat kaynakları olarak inceleyin. MCP'ye özgü testler için [MCP Servers](AI-MCP-Servers.md#mcp-vulns) sayfasına bakın.
- **İnsan onayı:** gerçek yapılandırılmış tool call'u modelin oluşturduğu onay metniyle karşılaştırın. Saldırgan etkisinin hedefi, kapsamı, etkilenecek nesneleri veya geri alınamaz yan etkileri atlayıp atlayamadığını test edin.

Önce zararsız, benzersiz bir işaretçi kullanın. Kaynak artefaktı, gözlemlenebiliyorsa oluşturulan bağlamı, seçilen tool call'u, onay verilerini, backend isteğini/yanıtını ve son durumu koruyun. Böylece etkilemenin, bir eylemin gerçekleştiğine dair halüsinasyon iddiasından ayrılması sağlanır.<sup>[[2]](#references)</sup>

### Tool-risk judge içinde policy biçimli metin

Model tabanlı bir tool gate, başka açılardan yararlı olan sınıflandırma bağlamında saldırgan denetimindeki metni alabilir. Örneğin LangChain'in deneysel `AutoModeMiddleware`'i, önerilen bir tool call'u, argümanlarını, isteğe bağlı tool açıklamasını ve son 30 mesaja kadarını TypeSafe `is_risky` judge'ına gönderir. Döndürülen Noul olasılığı en az `0.5` olduğunda yapılandırılmış tools'ları engeller; listelenmeyen tools bu middleware tarafından sınıflandırılmaz.<sup>[[5]](#references)</sup> TypeSafe ayrıca, state'in veri olarak kullanılması amaçlansa bile state içindeki adversarial metnin sınıflandırmayı etkileyebileceği konusunda uyarır.<sup>[[6]](#references)</sup>

**Sahte policy**, yalnızca system message olduğunu iddia etmekten farklıdır. Daha düşük güven düzeyindeki state içine alternatif etiketler veya risk tanımları yerleştirir ve judge'ı geliştirici tarafından tanımlanan kriterler yerine bunları kullanmaya yönlendirir. Datadog'un testinde, kullanıcı tarafından düzenlenebilen `profile_description`, `can_edit:false` ile birlikte tool argümanlarına kopyalanıyordu. Policy benzeri metni, ayrı bir izin kontrolünün herhangi bir değişiklik yapılmadan önce yazma girişimini reddetmesi gerektiği için düşük riskli olduğunu savunuyordu. 40 çalıştırmada ortalama `is_risky` puanı `0.893`'ten `0.290`'a düşerken, doğrudan role-spoofing karşılaştırmasının ortalaması `0.905` oldu. Ortalamanın `0.5` altına düşmesi, her bir çağrının gate'i geçtiğini kanıtlamaz; deney ayrıca yetkisiz bir yazma işleminin tamamlandığını da göstermemiştir.<sup>[[7]](#references)</sup>

Bu sınırı test ederken classifier kararını tool'un gerçek yetkilendirme sonucundan ayırın. Hangi düzenlenebilir alanların judge'a ulaştığını kontrol edin, aynı önerilen eylemi policy benzeri metinle ve metin olmadan karşılaştırın ve son durumu bağımsız olarak doğrulayın. Ayrı bir izin kontrolü, connector'ın service account yetkileri yerine kimliği doğrulanmış istekte bulunanın yetkisini kullanmalıdır.<sup>[[7]](#references)</sup> Diğer classifier hata türleri için [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) sayfasına bakın; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) farklı bir yönlendirme ve kimlik bilgisi sınırını ele alır.

### Subagent bağlam izolasyonu

Fork kullanmayan bir Claude Agent SDK subagent'ı kendi `AgentDefinition.prompt` değerini, delegation prompt'unu ve kullanabildiği tools'ları alır; ancak parent system prompt'unu veya konuşmasını almaz. Tanımında `tools` belirtilmezse subagent'ların kullanabildiği tools'ları devralır; proje `CLAUDE.md` dosyası yine de yüklenebilir. Bu nedenle, child aynı filesystem veya execution tools'larını kullanabiliyorsa yalnızca parent'a uygulanan bir prompt kısıtlaması güvenilir bir sınır değildir.<sup>[[4]](#references)</sup>

Sınırı test etmek için parent'ın reddettiği doğrudan bir isteği, adı belirtilmiş bir subagent'a devredilen aynı görevle karşılaştırın. NCC Group, reddedilen bir işletim sistemi dosya listeleme işleminin child'a zararsız bir "layout map" olarak yeniden ifade edildiğinde başarılı olduğunu bildiriyor.<sup>[[3]](#references)</sup>

Yalnızca parent'ın son yanıtını değil, child'ın gerçek tool call'larını ve etkin tool allowlist'ini inceleyin; child'ın parent'ın erişemeyeceği dosyalara erişip erişmediğini doğrulayın.<sup>[[4]](#references)</sup> Bu, bir guardrail devralma hatasıdır; [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) veya container escape kanıtı değildir.<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: gerçek etkiyi kanıtlayın

Etkilemeden etkiye ulaşan iki farklı yol vardır:<sup>[[2]](#references)</sup>

1. **Capability abuse:** Yetkili tool, hedeflenen işlemi zaten gerçekleştirebiliyordur. Örnekler arasında bir tenant'ın kaydını okuyup saldırganın görebildiği bir rapora yazmak, e-posta göndermek, kayıtları değiştirmek, bir dosyayı silmek veya ödeme başlatmak yer alır. İkincil bir yazılım açığı gerekmez.
2. **Aşağı akış sink exploitation:** Saldırganın yönlendirdiği model çıktısı başka bir bileşen için syntax hâline gelir. Veritabanı sorgularını [SQL injection](../pentesting-web/sql-injection/README.md) veya [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper'larını [command injection](../pentesting-web/command-injection.md), seçilen URL'leri [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), dosya işlemlerini traversal, template/code evaluator'larını RCE ve nesne parser'larını [unsafe deserialization](../pentesting-web/deserialization/README.md) açısından inceleyin.

Her aday için şu zinciri kanıtlayın:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Salt okunur bir entegrasyon, sonraki herhangi bir bileşen okuduğu içeriği yayımlayabiliyorsa yine de istismar edilebilir. Sıradan yanıtların yanı sıra saldırganın kontrolündeki bağlantılar, otomatik görsel getirme, webhook'lar, günlükler, raporlar, sayaçlar, bildirimler ve diğer ajanlara gönderilen mesajlar gibi daha az belirgin dışa aktarım yollarını da test edin.<sup>[[2]](#references)</sup>

## Hedeflere yönelik eylemler

Bir eylemi doğruladıktan sonra, ilk görünür etkide durmak yerine etki alanının tamamını değerlendirin:<sup>[[2]](#references)</sup>

- **Veri sızdırma:** Sırlar, kullanıcı kayıtları, dahili dosyalar, konuşma verileri veya istem/bağlam içeriği gözlemlenebilir bir kanal üzerinden dışarı çıkar.
- **Yetkisiz eylem:** Ajan, saldırganın amacı doğrultusunda meşru yazma yeteneklerini kullanır.
- **Hizmet engelleme:** Yıkıcı araçlar veya tekrarlanan, yüksek maliyetli işlemler bütünlüğü ya da kullanılabilirliği etkiler.
- **Kalıcılık:** Zehirlenmiş bellek, dizine eklenmiş içerik, güvenilir durum veya çalışma zamanı değişiklikleri, bunlara yol açan oturum ya da kaynak kaldırıldıktan sonra da varlığını sürdürür.
- **Yayılma:** Güvenilir bir eş, ele geçirilmiş ajanın mesajını veya paylaşılan durumunu kullanır ve kendi araçlarıyla kimlik bilgilerini kullanarak eylemi tekrarlar.

Önem derecesi, modelin metninin ne kadar şaşırtıcı göründüğüne değil; erişilebilir verilere, etkin ayrıcalıklara, hedefin istismar edilebilirliğine, dışa aktarım olanağına, kalıcılığa ve yayılmaya göre belirlenmelidir.<sup>[[2]](#references)</sup>

## Değerlendirme sırasında doğrulanacak kontroller

İstem filtreleri ve daha iyi bir sistem istemi, saldırganın işini zorlaştırabilir; ancak bunlar yetkilendirme sınırları olarak görülmemelidir. Aşağıdaki kontrolleri aynı zinciri doğrudan girdi, dolaylı içerik, bellek, araçlar ve eş ajanlar üzerinden yeniden çalıştırarak doğrulayın:<sup>[[2]](#references)</sup>

- Deterministik bir politika katmanı, **her araç çağrısında** kimliği doğrulanmış kullanıcıyı, kiracıyı, nesneyi, eylemi ve hedefi denetler; model çağıranın kimliğini belirleyemez veya geçersiz kılamaz.
- Okuma ve yazma yetenekleri ayrı, en az ayrıcalıklı ve kısa ömürlü kimlik bilgileri kullanır; yüksek etkili araçlar yalnızca gerektiğinde kullanıma açılır ve alınan içerikten hareketle asla otomatik çalıştırılmaz.
- Ağ çıkışı ve dahili hedefler, modelin seçtiği URL'lerden bağımsız olarak izin listelerine göre sınırlandırılır; gerekli olmadıkça çalışma zamanının meta veri uç noktalarına, bağlanmış sırlara ve komşu hizmetlere erişimi engellenir.
- Onay arayüzü, kanonik yapılandırılmış istekten oluşturulur ve serbest biçimli bir model özeti yerine tam argümanları, kimliği, hedefi, etkilenen nesneleri ve yan etkileri gösterir.
- Başarı, hedef sistemden veya kayıt sisteminden doğrulanır. Ajanın anlatımı, araç çağrısı isteği ya da HTTP yönlendirmesi, iddia edilen durum değişikliğinin kanıtı değildir.
- Bellek ve erişim kayıtları kaynak bilgisini ve güven etiketlerini korur, geçersiz kılınabilir ve daha sonraki bir eylemde kullanıldıklarında yeniden yetkilendirilir.
- Ajanlar arası mesajlar, kimliği doğrulanmış ve yetkilendirilmiş güvenilmeyen istekler olarak ele alınır; bir eşin itibarı veya ajan kartı, alıcının araçlarını kullanma yetkisini örtük biçimde devretmez.

A2A ajan kartları, görev akışları ve bunların saldırı yüzeyi hakkında bilgi için [A2A Protocol Security](AI-A2A-Protocol.md) sayfasına bakın.

## References

- [1] [2026 için OWASP Agentic Applications İlk 10 Listesi](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Ajanlarına Saldırı: Hacker Rehberi](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Bir AI Ajanını Korumalı Alanından Çıkarmak Gerçekten Ne Kadar Zor?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK'deki Alt Ajanlar](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode ara yazılımının kaynak kodu](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev modelinin pürüzlülüğü: hasmane içerik](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Yargıç olarak Jev: Sahte politika Jev'i nasıl yönlendiriyor?](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
