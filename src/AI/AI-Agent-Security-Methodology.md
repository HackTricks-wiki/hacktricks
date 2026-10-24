# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Bir agent değerlendirmesi, **saldırganın kontrol ettiği girdiden dışarıdan gözlemlenebilir bir etkiye** uzanan yolu izlemelidir. Jailbreaking, karakter değişiklikleri ve system prompt ifşası, bir akıl yürütme kanalının etkilenebilir olduğunu kanıtlar; ancak yüksek etkili bulgu, veriye erişime, yetkisiz bir araç eylemine, sonraki aşamadaki bir injection sink'e, kalıcılığa veya başka bir agent'a uzanan zincirdir.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), kapsamı etiketlemek için kullanışlıdır (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust ve rogue agents). Bu etiketleri, uçtan uca bir saldırı yolu oluşturduktan sonra kullanın; modelin beklenmedik metnini testin sonu olarak görmeyin.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedef haritasını oluşturun

Payload'ları hazırlamadan önce her agent iş akışı için şu beş boyutu kaydedin:<sup>[[2]](#references)</sup>

| Boyut | Listelenecekler | Güvenlik sorusu |
|---|---|---|
| **Güvenilmeyen girdi** | Chat/API parametreleri, URL'ler, belgeler, e-posta, ticket'lar, takvim girdileri, alınan parçalar, bellek, araç sonuçları ve eş agent mesajları | Saldırgan içeriği daha sonra model context'ine girecek şekilde nereye yerleştirebilir? |
| **Araçlar** | Araç adları ve şemaları, yan etkiler, otomatik yürütme, onay davranışı ve dinamik olarak yüklenen araçlar | Hangi çağrılar sırları okur, durumu yazar, mesaj gönderir, veriyi siler, kod yürütür veya değer aktarır? |
| **Yetki** | Kullanıcı yetkilendirmesi, service account'lar, API token'ları, kimlik bilgilerinin geçerlilik süresi, tenant/kaynak kapsamı ve ağ erişimi | Her çağrı hangi kimlikle çalışır ve yetkilendirme araç sınırında yeniden yapılıyor mu? |
| **İşleme** | Sorgu oluşturucular, shell'ler, URL fetcher'ları, template engine'ler, yorumlayıcılar, parser'lar, dosya işlemleri ve deserializer'lar | Model tarafından oluşturulan veri, başka bir yorumlayıcı için nerede sözdizimine dönüşüyor? |
| **Çıktı** | Yanıtlar, render edilen Markdown/HTML, bağlantılar, görsel fetch'leri, webhook'lar, e-posta, dosyalar, log'lar, raporlar, metrikler ve eş agent trafiği | Hangi gözlemlenebilir kanal bir sırrı taşıyabilir veya ikincil bir isteği tetikleyebilir? |

Bunu, reklamı yapılan entegrasyonların bir listesine indirgemeyin. Yararlı bir çıktı; her kaynağı ulaştığı tam context konumuyla, o noktada kullanılabilen araçlarla, her aracın kullandığı kimlikle, sonraki aşamadaki yorumlayıcıyla ve tüm egress yollarıyla eşleştirir. Aynı araç, kullanıcı başına bir read token ile düşük etkili; paylaşılan bir administrator kimlik bilgisiyle kritik olabilir.<sup>[[2]](#references)</sup>

## Keşif

### Her teslim ve veri alım yolunun haritasını çıkarın

Teslim yüzeyiyle (web, mobil, API, e-posta, chat platformu, browser extension) başlayın ve istemciden backend'e giden trafiği proxy'leyin. UI tarafından gizlenen alanları, arama/autocomplete/filter parametrelerini, konuşma durumu nesnelerini, upload ve indexing işlerini, araç yanıtlarını ve sub-agent trafiğini inceleyin. Yalnızca mobilde bulunan istemcilerde gerçek istek şeması görünür olmadan önce certificate pinning'i aşmak için bir emulator ve instrumentation gerekebilir.<sup>[[2]](#references)</sup>

Ardından modelin altındaki stack'in haritasını çıkarın: orchestration framework'ü, prompt assembly, retrieval ve memory store'ları, runtime (örneğin Python, container veya WASM), mount edilmiş volume'ler, host servisleri, internal API'ler, cloud metadata'ya erişilebilirlik ve komşu ağlar. Framework varsayılanları önemlidir; çünkü bazı “tool call”'lar kod üreterek veya değerlendirerek uygulanır. Runtime/sandbox sınırı, bu sonucun sınırlar içinde kalıp kalmayacağını belirler.<sup>[[2]](#references)</sup>

### Yıkıcı olmayan probe'larla yönlendirmeyi belirleyin

Kapsam içindeki bir isteği, tam yanıtı, status code'u, gecikmeyi ve streaming davranışını koruyarak ilgisiz birkaç istekle karşılaştırın. Göreve özgü herhangi bir akıl yürütmeden önce gelen tutarlı bir ret, ayrı bir gateway/classifier olduğunu gösterebilir; bağlama göre değişen bir ret, isteğin modele ulaştığını düşündürür; boş veya yalnızca bilgi çıkaran bir yanıt, keyword search ya da dar kapsamlı retrieval işareti olabilir. Bunları hipotez olarak ele alın ve aynı probe'u alternatif API alanları ve veri alım yolları üzerinden yeniden oynatarak doğrulayın.<sup>[[2]](#references)</sup>

Keşif, değerlendirme; agent davranışını değiştiren saldırgan kontrollü en erken kaynağı **ve** bu kaynaktan erişilebilen araçları, kimlikleri, yorumlayıcıları ve çıktıları belirleyebildiğinde tamamlanır.<sup>[[2]](#references)</sup>

## Exploitation: bir güven sınırını aşın

Yalnızca prompt ifadelerini değil, kanalları da test edin. Görünür giriş kapısının neleri engellediğini belirlemek için doğrudan injection ile başlayın; ardından eşdeğer amacı aşağıdaki daha az görünür yollar üzerinden tekrar deneyin:<sup>[[2]](#references)</sup>

- **Dolaylı içerik:** sayfalar, dosyalar, e-posta, ticket'lar, metadata, alt text, HTML yorumları, ekran dışı metin veya zero-width karakterler. Payload teslim teknikleri için [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) sayfasına bakın.
- **Retrieval ve bellek:** daha sonra alınacak içeriği veya sonraki oturumlarda yeniden yüklenecek durumu zehirleyin. Özgün kaynağın silinmesinin davranışı ortadan kaldırıp kaldırmadığını kaydedin.
- **Araç çıktısı ve eş agent'lar:** iç trafiğin yalnızca kullanıcı girdisine ve nihai çıktıya uygulanan filtreleri atlayıp atlamadığını test etmek için işaretleyiciyi bir araç yanıtına veya agent'lar arası mesaja yerleştirin.
- **Supply chain:** araç tanımlayıcılarını, plugin'leri, bağlı sunucuları, skill'leri, modelleri ve bağımlılıkları güvenilir talimat kaynakları olarak inceleyin. MCP'ye özgü testler için [MCP Servers](AI-MCP-Servers.md#mcp-vulns) sayfasına bakın.
- **İnsan onayı:** gerçek yapılandırılmış araç çağrısını model tarafından oluşturulan onay metniyle karşılaştırın. Saldırgan etkisinin hedefi, kapsamı, etkilenen nesneleri veya geri alınamaz yan etkileri atlamaya yol açıp açamayacağını test edin.

Önce zararsız ve benzersiz bir işaretleyici kullanın. Kaynak öğesini, gözlemlenebiliyorsa oluşturulmuş context'i, seçilen araç çağrısını, onay verilerini, backend isteğini/yanıtını ve nihai durumu koruyun. Böylece etki yaratmakla bir eylemin gerçekleştiğine dair halüsinasyon ürünü bir iddiayı birbirinden ayırabilirsiniz.<sup>[[2]](#references)</sup>

### Tool-risk judge içindeki policy benzeri metin

Model tabanlı bir tool gate, başka açılardan yararlı olan sınıflandırma context'i içindeki saldırgan kontrollü metni alabilir. Örneğin LangChain'in deneysel `AutoModeMiddleware`'ı önerilen bir araç çağrısını, argümanlarını, isteğe bağlı araç açıklamasını ve en son 30 mesaja kadar olan konuşma geçmişini TypeSafe `is_risky` judge'ına gönderir. Döndürülen Noul olasılığı en az `0.5` olduğunda yapılandırılmış araçları engeller; listede olmayan araçlar bu middleware tarafından sınıflandırılmaz.<sup>[[5]](#references)</sup> TypeSafe ayrıca, state'in veri olarak kullanılması amaçlansa bile state içindeki adversarial metnin sınıflandırmayı etkileyebileceği konusunda uyarır.<sup>[[6]](#references)</sup>

**Sahte politika**, yalnızca system message olduğunu iddia etmekten farklıdır. Düşük güven düzeyindeki state içine alternatif etiketler veya risk tanımları yerleştirir ve judge'ı geliştirici tarafından tanımlanmış ölçütler yerine bu tanımları kullanmaya yönlendirir. Datadog'un testinde, kullanıcı tarafından düzenlenebilen bir `profile_description`, `can_edit:false` ile birlikte araç argümanlarına kopyalanmıştı. Politika benzeri metin, ayrı bir izin kontrolünün herhangi bir değişiklik yapılmadan önce isteği reddetmesi gerektiği için yazma girişiminin düşük riskli olduğunu savunuyordu. 40 çalıştırmada ortalama `is_risky` puanı `0.893` değerinden `0.290` değerine düşerken, doğrudan role-spoofing karşılaştırmasının ortalaması `0.905` oldu. Ortalamanın `0.5` değerinin altına düşmesi her bir çağrının gate'i geçtiğini kanıtlamaz ve deney, **tamamlanmış yetkisiz bir yazma işlemi** göstermemiştir.<sup>[[7]](#references)</sup>

Bu sınırı test ederken classifier kararını aracın gerçek yetkilendirme sonucundan ayırın. Düzenlenebilir alanlardan hangilerinin judge'a ulaştığını kontrol edin, aynı önerilen eylemi politika benzeri metinle ve bu metin olmadan karşılaştırın ve nihai durumu bağımsız olarak doğrulayın. Ayrı bir izin kontrolü, connector'ın service account yetkilerini değil, kimliği doğrulanmış istekte bulunanın yetkisini kullanmalıdır.<sup>[[7]](#references)</sup> Diğer classifier hata biçimleri için [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) sayfasına bakın; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) farklı bir yönlendirme ve kimlik bilgisi sınırını ele alır.

### Subagent context izolasyonu

Fork kullanmayan bir Claude Agent SDK subagent'ı kendi `AgentDefinition.prompt`'unu, delegation prompt'unu ve kullanabildiği araçları alır; ancak parent system prompt'unu veya konuşmasını almaz. Tanımında `tools` belirtilmezse subagent'ların kullanabildiği araçları devralır; proje `CLAUDE.md` dosyası yine de yüklenebilir. Bu nedenle, child aynı dosya sistemi veya yürütme araçlarını kullanabiliyorsa yalnızca parent'a uygulanan bir prompt kısıtlaması güvenilir bir sınır değildir.<sup>[[4]](#references)</sup>

Parent'ın reddettiği doğrudan bir isteği aynı görevi adı belirtilmiş bir subagent'a devrederek karşılaştırın. NCC Group, zararsız bir "layout map" olarak yeniden çerçevelenen bir child isteğiyle reddedilen işletim sistemi dosyalarının listelenmesinin başarılı olduğunu bildiriyor.<sup>[[3]](#references)</sup>

Yalnızca parent'ın nihai yanıtını değil, child'ın gerçek araç çağrılarını ve etkin araç allowlist'ini inceleyin; child'ın parent'ın erişemeyeceği dosyalara erişip erişmediğini doğrulayın.<sup>[[4]](#references)</sup> Bu, guardrail devralma hatasıdır; [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) veya container escape kanıtı değildir.<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: gerçek etkiyi kanıtlayın

Etkiden sonuca giden iki ayrı yol vardır:<sup>[[2]](#references)</sup>

1. **Capability abuse:** Yetkili araç hedeflenen işi zaten yapar. Örnekler arasında bir tenant'ın kaydını okuyup saldırganın görebildiği bir rapora yazmak, e-posta göndermek, kayıtları değiştirmek, bir dosyayı silmek veya ödeme başlatmak bulunur. İkincil bir yazılım hatası gerekmez.
2. **Downstream sink exploitation:** Saldırganın yönlendirdiği model çıktısı, başka bir bileşen için sözdizimine dönüşür. [SQL injection](../pentesting-web/sql-injection/README.md) veya [NoSQL injection](../pentesting-web/nosql-injection.md) için veritabanı sorgularını, [command injection](../pentesting-web/command-injection.md) için shell wrapper'larını, [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md) için seçilen URL'leri, path traversal için dosya işlemlerini, RCE için template/code evaluator'larını ve [unsafe deserialization](../pentesting-web/deserialization/README.md) için nesne parser'larını inceleyin.

Her aday için şu zinciri kanıtlayın:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Salt okunur bir entegrasyon bile, sonraki herhangi bir bileşen okuduğu içeriği yayımlayabiliyorsa istismar edilebilir. Olağan yanıtların yanı sıra saldırganın kontrolündeki bağlantılar, otomatik görsel getirme, webhook'lar, günlükler, raporlar, sayaçlar, bildirimler ve diğer ajanlara gönderilen mesajlar gibi daha az belirgin egress kanallarını da test edin.<sup>[[2]](#references)</sup>

## Hedeflere yönelik eylemler

Bir eylemi doğruladıktan sonra, ilk görünür etkide durmak yerine tüm etki alanını değerlendirin:<sup>[[2]](#references)</sup>

- **Exfiltration:** Sırlar, kullanıcı kayıtları, dahili dosyalar, konuşma verileri veya prompt/bağlam içeriği gözlemlenebilir bir kanal üzerinden dışarı çıkar.
- **Yetkisiz eylem:** Ajan, saldırganın amacı doğrultusunda meşru yazma yeteneklerini kullanır.
- **Hizmet reddi:** Yıkıcı araçlar veya tekrarlanan maliyetli işlemler bütünlüğü ya da kullanılabilirliği etkiler.
- **Persistence:** Zehirlenmiş bellek, dizine eklenmiş içerik, güvenilir durum veya çalışma zamanı değişiklikleri, bunları başlatan oturum ya da kaynak kaldırıldıktan sonra da kalıcı olur.
- **Yayılma:** Güvenilir bir eş, güvenliği ihlal edilmiş ajanın mesajını veya paylaşılan durumunu kullanır ve kendi araçlarıyla kimlik bilgilerini kullanarak eylemi tekrarlar.

Önem derecesi, modelin metninin ne kadar şaşırtıcı göründüğüne değil; erişilebilir verilere, etkin ayrıcalığa, hedefin istismar edilebilirliğine, egress'e, kalıcılığa ve yayılmaya göre belirlenmelidir.<sup>[[2]](#references)</sup>

## Değerlendirme sırasında doğrulanacak kontroller

Prompt filtreleri ve daha iyi bir system prompt, saldırganın maliyetini artırabilir ancak yetkilendirme sınırları olarak değerlendirilmemelidir. Aşağıdaki kontrolleri; doğrudan girdi, dolaylı içerik, bellek, araçlar ve eş ajanlar üzerinden aynı zinciri yeniden çalıştırarak doğrulayın:<sup>[[2]](#references)</sup>

- Deterministik bir politika katmanı, **her araç çağrısında** kimliği doğrulanmış kullanıcıyı, kiracıyı, nesneyi, eylemi ve hedefi denetler; model, çağıranın kimliğini sağlayamaz veya geçersiz kılamaz.
- Okuma ve yazma yetenekleri ayrı, en az ayrıcalıklı ve kısa ömürlü kimlik bilgileri kullanır; yüksek etkili araçlar yalnızca gerektiğinde kullanıma açılır ve alınan içerikten hareketle hiçbir zaman otomatik çalıştırılmaz.
- Ağ egress'i ve dahili hedefler, modelin seçtiği URL'lerden bağımsız olarak izin listesine alınır; gerekli olmadıkça çalışma zamanı meta veri uç noktalarına, bağlanmış sırlara ve komşu servislere erişemez.
- Onay arayüzü, standart yapılandırılmış istekten oluşturulur ve serbest biçimli model özeti yerine tam bağımsız değişkenleri, kimliği, hedefi, etkilenecek nesneleri ve yan etkileri gösterir.
- Başarı, hedef sistemden veya kayıt sisteminden doğrulanır. Ajanın anlatımı, araç çağrısı isteği ya da HTTP yönlendirmesi, iddia edilen durum değişikliğinin kanıtı değildir.
- Bellek ve retrieval girdileri kaynak bilgilerini ve güven etiketlerini korur, geçersiz kılınabilir ve sonraki bir eylemde kullanıldıklarında yeniden yetkilendirilir.
- Ajanlar arası mesajlar, kimliği doğrulanmış ve yetkilendirilmiş güvenilmeyen istekler olarak ele alınır; bir eşin itibarı veya ajan kartı, alıcının araçlarını örtük biçimde devretmez.

## References

- [1] [2026 için Agentic Applications OWASP Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Ajanlarına Saldırma Hacker Rehberi](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Bir AI Ajanını Sandbox'ından Çıkarmak Gerçekten Ne Kadar Zor?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK'deki Alt Ajanlar](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode ara yazılımının kaynak kodu](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model düzensizliği: Hasmane içerik](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev bir yargıç olarak: Sahte politika Jev'i nasıl yönlendiriyor](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
