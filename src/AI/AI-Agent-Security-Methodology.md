# AI Agent Güvenlik Metodolojisi

{{#include ../banners/hacktricks-training.md}}

Bir agent değerlendirmesi, **saldırganın kontrolündeki girdiden dışarıdan gözlemlenebilir bir etkiye** giden yolu izlemelidir. Jailbreaking, karakter değişiklikleri ve system prompt ifşası, bir akıl yürütme kanalının etkilenebildiğini kanıtlar; ancak yüksek etkili bulgu, bu etkinin veri erişimine, yetkisiz bir tool eylemine, sonraki aşamadaki bir injection sink'e, kalıcılığa veya başka bir agente uzanan zinciridir.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), kapsamı etiketlemek için kullanışlıdır (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust ve rogue agents). Bu etiketleri, modelin beklenmedik metnini testin sonu saymak yerine uçtan uca bir saldırı yolu oluşturduktan sonra kullanın.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedef haritasını oluşturun

Payload yazmadan önce her agent iş akışı için şu beş boyutu kaydedin:<sup>[[2]](#references)</sup>

| Boyut | Nelerin listeleneceği | Güvenlik sorusu |
|---|---|---|
| **Güvenilmeyen girdi** | Chat/API parametreleri, URL'ler, belgeler, e-posta, ticket'lar, takvim kayıtları, alınan parçalar, bellek, tool sonuçları ve eş agent mesajları | Saldırgan, daha sonra model bağlamına girecek içeriği nereye yerleştirebilir? |
| **Tool'lar** | Tool adları ve şemaları, yan etkiler, otomatik yürütme, onay davranışı ve dinamik olarak yüklenen tool'lar | Hangi çağrılar sırları okur, durumu yazar, mesaj gönderir, veri siler, kod çalıştırır veya değer aktarır? |
| **Yetki** | Kullanıcı yetkilendirmesi, service account'lar, API token'ları, kimlik bilgilerinin geçerlilik süresi, tenant/kaynak kapsamı ve ağ erişimi | Her çağrı hangi kimlikle çalışır ve yetkilendirme tool sınırında yeniden kontrol edilir mi? |
| **İşleme** | Sorgu oluşturucular, shell'ler, URL fetcher'lar, şablon motorları, yorumlayıcılar, parser'lar, dosya işlemleri ve deserializer'lar | Model tarafından üretilen veri nerede başka bir yorumlayıcı için sözdizimine dönüşür? |
| **Çıktı** | Yanıtlar, işlenen Markdown/HTML, bağlantılar, görsel fetch'leri, webhook'lar, e-posta, dosyalar, log'lar, raporlar, metrikler ve eş agent trafiği | Hangi gözlemlenebilir kanal bir sırrı taşıyabilir veya ikincil bir isteği tetikleyebilir? |

Bunu, tanıtımı yapılan entegrasyonların listesine indirgemeyin. Yararlı bir çıktı; her kaynağı ulaştığı tam bağlam konumuna, o noktada kullanılabilen tool'lara, her tool'un kullandığı kimlik bilgisine, sonraki aşamadaki yorumlayıcıya ve tüm egress yollarına eşler. Aynı tool, kullanıcı başına bir read token ile düşük etkili; paylaşılan bir administrator credential ile kritik olabilir.<sup>[[2]](#references)</sup>

## Keşif

### Tüm iletim ve veri alma yollarını haritalayın

İletim yüzeyinden (web, mobil, API, e-posta, chat platformu, browser extension) başlayın ve istemciden backend'e giden trafiği proxy üzerinden inceleyin. Arayüzde gizlenen alanları, arama/otomatik tamamlama/filtre parametrelerini, konuşma durumu nesnelerini, yükleme ve indeksleme işlerini, tool yanıtlarını ve alt-agent trafiğini inceleyin. Yalnızca mobilde bulunan istemcilerde, gerçek istek şeması görünür olmadan önce certificate pinning'i aşmak için bir emulator ve instrumentation gerekebilir.<sup>[[2]](#references)</sup>

Ardından modelin altındaki yığını haritalayın: orchestration framework'ü, prompt birleştirme, retrieval ve bellek depoları, runtime (örneğin Python, container veya WASM), mount edilmiş volume'ler, host servisleri, dahili API'ler, cloud metadata erişilebilirliği ve komşu ağlar. Framework varsayılanları önemlidir; çünkü bazı “tool call”lar kod üretilerek veya değerlendirilerek uygulanır. Sonucun yalıtılmış kalıp kalmayacağını runtime/sandbox sınırı belirler.<sup>[[2]](#references)</sup>

### Tahribatsız sondalarla yönlendirmeyi parmak izleyin

Kapsam içindeki bir isteği birkaç ilgisiz istekle karşılaştırırken yanıtın tamamını, durum kodunu, gecikmeyi ve streaming davranışını koruyun. Göreve özgü herhangi bir akıl yürütme başlamadan önce gelen kararlı bir ret, ayrı bir gateway/classifier olduğunu gösterebilir; bağlama duyarlı bir ret, isteğin modele ulaştığını düşündürür; boş veya yalnızca bilgi çıkaran bir yanıt, keyword search ya da dar kapsamlı retrieval kullanıldığına işaret edebilir. Bunları hipotez olarak ele alın ve aynı sondayı alternatif API alanları ve veri alma yolları üzerinden yeniden oynatarak doğrulayın.<sup>[[2]](#references)</sup>

Keşif; değerlendirme, agent davranışını değiştiren en erken saldırgan kontrollü kaynağı **ve** bu kaynaktan erişilebilen tool'ları, kimlikleri, yorumlayıcıları ve çıktıları belirleyebildiğinde tamamlanır.<sup>[[2]](#references)</sup>

## Exploitation: bir güven sınırını aşın

Yalnızca prompt ifadelerini değil, kanalları da test edin. Görünür giriş noktasının neleri engellediğini belirlemek için doğrudan injection ile başlayın, ardından eşdeğer niyeti aşağıdaki daha az görünür yollar üzerinden tekrar deneyin:<sup>[[2]](#references)</sup>

- **Dolaylı içerik:** sayfalar, dosyalar, e-posta, ticket'lar, metadata, alt text, HTML yorumları, ekran dışındaki metinler veya zero-width karakterler. Payload iletme teknikleri için [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) bölümüne bakın.
- **Retrieval ve bellek:** daha sonra alınacak içeriği veya sonraki oturumlarda yeniden yüklenecek durumu zehirleyin. Orijinal kaynağın silinmesinin davranışı ortadan kaldırıp kaldırmadığını kaydedin.
- **Tool çıktısı ve eş agent'lar:** dahili trafiğin yalnızca kullanıcı girdisine ve son çıktıya uygulanan filtreleri atlayıp atlamadığını test etmek için işareti bir tool yanıtına veya agent'lar arası mesaja yerleştirin.
- **Supply chain:** tool tanımlayıcılarını, plugin'leri, bağlı sunucuları, skill'leri, modelleri ve bağımlılıkları güvenilir talimat kaynakları olarak gözden geçirin. MCP'ye özgü testler için [MCP Servers](AI-MCP-Servers.md#mcp-vulns) bölümüne bakın.
- **İnsan onayı:** gerçek yapılandırılmış tool çağrısını model tarafından oluşturulan onay metniyle karşılaştırın. Saldırganın etkisinin hedefin, kapsamın, etkilenen nesnelerin veya geri döndürülemez yan etkilerin atlanmasına yol açıp açamayacağını test edin.

Önce zararsız, benzersiz bir işaret kullanın. Kaynak artefaktı, gözlemlenebiliyorsa birleştirilmiş bağlamı, seçilen tool çağrısını, onay verilerini, backend istek/yanıtını ve son durumu koruyun. Böylece etki yaratma ile bir eylemin gerçekleştiğine dair halüsinasyon iddiası birbirinden ayrılır.<sup>[[2]](#references)</sup>

### Tool-risk judge içinde policy benzeri metin

Model tabanlı bir tool gate, başka açılardan yararlı sınıflandırma bağlamının içine yerleştirilmiş saldırgan kontrollü metin alabilir. Örneğin LangChain'in deneysel `AutoModeMiddleware` bileşeni, önerilen bir tool çağrısını, argümanlarını, isteğe bağlı bir tool açıklamasını ve en fazla 30 yakın zamandaki mesajı TypeSafe `is_risky` judge'ına gönderir. Döndürülen Noul olasılığı `0.5` veya daha yüksek olduğunda yapılandırılmış tool'ları engeller; listelenmeyen tool'lar bu middleware tarafından sınıflandırılmaz.<sup>[[5]](#references)</sup> TypeSafe ayrıca, durumun veri olarak kullanılması amaçlansa bile durumdaki adversarial metnin sınıflandırmayı etkileyebileceği konusunda uyarır.<sup>[[6]](#references)</sup>

**Sahte politika**, yalnızca bir system message olduğunu iddia etmekten farklıdır. Daha düşük güven düzeyindeki duruma alternatif etiketler veya risk tanımları yerleştirir ve judge'ı bu tanımları geliştirici tarafından belirlenen ölçütler yerine kullanmaya yönlendirir. Datadog'un testinde, kullanıcı tarafından düzenlenebilen `profile_description`, `can_edit:false` ile birlikte tool argümanlarına kopyalandı. Politika benzeri metin, ayrı bir izin kontrolünün herhangi bir değişiklik gerçekleşmeden önce yazma girişimini reddetmesi gerektiği için bunun düşük riskli olduğunu savunuyordu. 40 çalıştırmada ortalama `is_risky` puanı `0.893` değerinden `0.290` değerine düştü; doğrudan role-spoofing karşılaştırmasının ortalaması ise `0.905` oldu. Ortalamanın `0.5` altına düşmesi, her çağrının gate'i geçtiğini kanıtlamaz ve deney, yetkisiz bir yazma işleminin tamamlandığını **göstermemiştir**.<sup>[[7]](#references)</sup>

Bu sınırı test ederken classifier kararını tool'un gerçek yetkilendirme sonucundan ayırın. Düzenlenebilir alanlardan hangilerinin judge'a ulaştığını kontrol edin, önerilen aynı eylemi politika benzeri metinle ve bu metin olmadan karşılaştırın ve son durumu bağımsız olarak doğrulayın. Ayrı bir izin kontrolü, connector'ın service account yetkilerini değil, kimliği doğrulanmış istekte bulunanın yetkilerini kullanmalıdır.<sup>[[7]](#references)</sup> Diğer classifier hata türleri için [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) bölümüne bakın; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) ise farklı bir yönlendirme ve kimlik bilgisi sınırını ele alır.

### Alt agent bağlam yalıtımı

Fork kullanmayan bir Claude Agent SDK alt agent'ı kendi `AgentDefinition.prompt` değerini, görevlendirme prompt'unu ve kullanılabilir tool'larını alır; ancak üst agent'ın system prompt'unu veya konuşmasını almaz. Tanımında `tools` belirtilmezse alt agent'lara sunulan tool'ları devralır; proje `CLAUDE.md` dosyası yine de yüklenebilir. Bu nedenle, alt agent aynı dosya sistemi veya yürütme tool'larını kullanabiliyorsa yalnızca üst agent'a yönelik bir prompt kısıtlaması güvenilir bir sınır değildir.<sup>[[4]](#references)</sup>

Üst agent'ın reddettiği doğrudan bir isteği, adı belirtilmiş bir alt agente devredilen aynı görevle karşılaştırarak sınırı test edin. NCC Group, bir alt agente zararsız bir “layout map” olarak yeniden çerçevelendiğinde reddedilen bir işletim sistemi dosyası listeleme işleminin başarılı olduğunu bildiriyor.<sup>[[3]](#references)</sup>

Yalnızca üst agent'ın son yanıtını değil, alt agent'ın gerçek tool çağrılarını ve etkin tool izin listesini inceleyin; alt agent'ın üst agent'ın erişemeyeceği dosyalara erişip erişmediğini doğrulayın.<sup>[[4]](#references)</sup> Bu, bir guardrail devralma hatasıdır; [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) veya container kaçışının kanıtı değildir.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobil GUI agent'ları: ekrandaki talimatlar ve eylemin yeniden bağlanması

Bir telefon GUI agent'ı, sonraki uygulamalar arası eylemi seçmeden önce her ekran görüntüsünü bir cloud modeline gönderebilir. **Dolaylı görsel injection** test etmek için agent'ın yetkilendirilmiş bir görev sırasında inceleyeceği SMS, e-posta veya sayfaya saldırgan kontrollü metin yerleştirin. Doğrudan görev prompt'unu yalnızca ekran görüntüsünde görünen aynı talimatla karşılaştırın, ardından sonraki eylemi ve yüksek riskli işlem kararını inceleyin. Değerlendirilen asistanda istemci tarafındaki `checkPrompt`, doğrudan görev metnini tarıyordu ancak ekran görüntüsü içeriğine eşdeğer bir filtre uygulamıyordu. Bu, [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md) yönteminin mobil ve uygulamalar arası bir çeşididir; Android bileşen kimlik doğrulamasını aşma yöntemi değildir.<sup>[[9]](#references)</sup>

Yan etkilere yönelik açıklayıcı bir testte, saldırgan kontrollü bir form agent'tan hassas alanları doldurmasını ister ve ardından insandan “upload” düğmesine tıklamasını talep eder; sayfa ise alanlar değişir değişmez doldurulmuş verileri gönderir. İnsan onayı, sayfa kodu tarafından önceden gönderilmiş verileri koruyamaz; agent'ın anlatımını kanıt saymak yerine gerçek gönderimi doğrulayın. Kaynak bunu olası bir örüntü olarak sunar; her asistanın ele geçirildiğinin gösterilmiş kanıtı olarak değil.<sup>[[9]](#references)</sup>

**GUI TOCTOU / eylemin yeniden bağlanması**, ayrı bir hata türüdür: agent `t0` anında gözlemlediği ekrandan bir girdi planlar, ancak girdi `t1` anında enjekte edilmeden önce öndeki arayüz değişir.<sup>[[8]](#references)</sup> `t2` anındaki sonraki ekran görüntüsü, gerçekleşmiş bir eylemi geri alamaz.<sup>[[9]](#references)</sup> Yetkili bir Android testinde yeniden kullanılabilir iş akışı şöyledir:<sup>[[8]](#references)</sup>

1. Hedef kontrolün ekran koordinatlarını belirleyin ve kontrollü bir uygulamada aynı konuma zararsız bir kontrol yerleştirin.
2. Agent kontrolü gözlemleyene kadar bu taşıyıcıyı görünür tutun, ardından gözlem ile eylem arasındaki boşlukta normal bir foreground geçişini tetikleyin.
3. Planlanan dokunuşun yeni uygulamanın kontrolüne gelip gelmediğini kontrol edin ve agent'ın anlatımına güvenmek yerine hedef uygulamadaki son durumu doğrulayın.

Orijinal action-rebinding çalışması bunu, tehlikeli izni olmayan bir uygulamayla gösterir; ayrıca çok adımlı akışlarda geçişin agent'ın görev kurtarma döngüsü üzerinden tekrarlanmasını da anlatır.<sup>[[8]](#references)</sup>

Bu temel yöntemin her asistanda değişmeden çalışacağını **varsaymayın**. Doubao değerlendirmesinde `OpClickUI`, üst düzey Activity değiştiğinde tıklamaları atlıyor; önceki üç adımda `OpOpenApp` göründüğünde ekran görüntülerini karşılaştırıyordu. Bu nedenle tek dokunuşlar, uzun basmalar ve çift dokunuşlar saldırgan kontrollü zamanlama için pek güvenilir değildi. `OpTypeText`, `OpSwipeUI` ve `OpScrollWheelAction` için eşdeğer korumalar yoktu; ancak rapor bunların pratik etkisini daha sınırlı olarak değerlendirdi.<sup>[[9]](#references)</sup>

## Execution: gerçek etkiyi kanıtlayın

Etkilenmeden etkiye giden iki ayrı yol vardır:<sup>[[2]](#references)</sup>

1. **Yeteneğin kötüye kullanılması:** Yetkili tool zaten hedeflenen işlemi gerçekleştirir. Örnek olarak bir tenant'ın kaydını okuyup saldırganın görebildiği bir rapora yazmak, e-posta göndermek, kayıtları değiştirmek, bir dosyayı silmek veya ödeme başlatmak verilebilir. İkincil bir yazılım hatası gerekmez.
2. **Sonraki aşamadaki sink'in istismarı:** Saldırganın yönlendirdiği model çıktısı başka bir bileşen için sözdizimine dönüşür. Veritabanı sorgularında [SQL injection](../pentesting-web/sql-injection/README.md) veya [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrapper'larında [command injection](../pentesting-web/command-injection.md), seçilen URL'lerde [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), dosya işlemlerinde path traversal, template/code evaluator'larında RCE ve nesne parser'larında [unsafe deserialization](../pentesting-web/deserialization/README.md) olup olmadığını inceleyin.

Her aday için şu zinciri kanıtlayın:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Salt okunur bir entegrasyon bile, daha sonraki herhangi bir bileşen okuduğu içeriği yayımlayabiliyorsa istismar edilebilir. Sıradan yanıtların yanı sıra saldırganın kontrolündeki bağlantılar, otomatik görsel getirme, webhook'lar, log'lar, raporlar, sayaçlar, bildirimler ve diğer agent'lara gönderilen mesajlar gibi daha az göze çarpan egress kanallarını da test edin.<sup>[[2]](#references)</sup>

## Eylemlerin hedefler üzerindeki etkisi

Bir eylemi doğruladıktan sonra, ilk görünür etkide durmak yerine etki alanının tamamını değerlendirin:<sup>[[2]](#references)</sup>

- **Veri sızdırma:** sırlar, kullanıcı kayıtları, dahili dosyalar, konuşma verileri veya prompt/context içeriği gözlemlenebilir bir kanal üzerinden dışarı çıkar.
- **Yetkisiz eylem:** agent, saldırganın hedefi doğrultusunda meşru yazma yeteneklerini kullanır.
- **Hizmet engelleme:** yıkıcı araçlar veya tekrarlanan maliyetli işlemler bütünlüğü ya da kullanılabilirliği etkiler.
- **Kalıcılık:** zehirlenmiş bellek, indekslenmiş içerik, güvenilir durum veya çalışma zamanı değişiklikleri, bunlara kaynak olan oturum ya da kaynak kaldırıldıktan sonra da sürer.
- **Yayılma:** güvenilir bir eş, ele geçirilmiş agent'ın mesajını veya paylaşılan durumunu kullanır ve kendi araçlarıyla ve kimlik bilgileriyle eylemi tekrarlar.

Önem derecesi, modelin metninin ne kadar şaşırtıcı göründüğüne değil; erişilebilir verilere, etkin ayrıcalıklara, sink'in istismar edilebilirliğine, egress'e, kalıcılığa ve yayılmaya göre belirlenmelidir.<sup>[[2]](#references)</sup>

## Değerlendirme sırasında doğrulanacak kontroller

Prompt filtreleri ve daha iyi bir sistem prompt'u saldırganın maliyetini artırabilir, ancak yetkilendirme sınırı olarak değerlendirilmemelidir. Aşağıdaki kontrolleri, aynı zinciri doğrudan girdi, dolaylı içerik, bellek, araçlar ve eş agent'lar üzerinden yeniden çalıştırarak doğrulayın:<sup>[[2]](#references)</sup>

- Deterministik bir policy katmanı, **her araç çağrısında** kimliği doğrulanmış kullanıcıyı, tenant'ı, nesneyi, eylemi ve hedefi denetler; model, çağıranın kimliğini belirleyemez veya geçersiz kılamaz.
- Okuma ve yazma yetenekleri ayrı, en az ayrıcalık ilkesine uygun ve kısa ömürlü kimlik bilgileri kullanır; yüksek etkili araçlar yalnızca gerektiğinde kullanıma sunulur ve alınan içerikten hareketle hiçbir zaman otomatik olarak çalıştırılmaz.
- Ağ egress'i ve dahili hedefler, modelin seçtiği URL'lerden bağımsız olarak izin listesine alınır; gerekli olmadıkça çalışma zamanının metadata endpoint'lerine, bağlanmış sırlara ve komşu hizmetlere erişimi engellenir.
- Onay arayüzü, kanonik yapılandırılmış istekten oluşturulur ve serbest biçimli bir model özeti yerine tam argümanları, kimliği, hedefi, etkilenen nesneleri ve yan etkileri gösterir.
- Başarı, hedef sistemden veya kayıt sisteminden doğrulanır. Agent'ın anlatımı, araç çağrısı isteği ya da HTTP yönlendirmesi, iddia edilen durum değişikliğinin kanıtı değildir.
- Bellek ve retrieval girdileri kaynak bilgisini ve güven etiketlerini korur, geçersiz kılınabilir ve sonraki bir eylemde kullanıldıklarında yeniden yetkilendirilir.
- Agent'lar arası mesajların kimliği doğrulanır ve mesajlar yetkisiz istekler olarak ele alınır; bir eşin itibarı veya agent card'ı, alıcı agent'ın araçlarını örtük olarak devretmez.

A2A agent card'ları, görev akışları ve saldırı yüzeyleri için [A2A Protocol Security](AI-A2A-Protocol.md) bölümüne bakın.

## References

- [1] [2026 için OWASP Agentic Applications İlk 10 Listesi](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [AI Agent'lara Saldırı: Hacker'ın Rehberi](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Bir AI Agent'ı Sandbox'ından Çıkarmak Gerçekten Ne Kadar Zor?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK'de Subagent'lar](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode middleware kaynak kodu](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model pürüzlülüğü: düşmanca içerik](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Bir yargıç olarak Jev: Sahte policy, Jev'i nasıl yönlendiriyor?](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Sıfır İzinle Manipülasyon: Büyük Multimodal Model Destekli GUI Agent'larına Güvenebilir miyiz?](https://arxiv.org/html/2601.12349v1)
- [9] [Bir AI Asistanı Hacker'ın Saldırı Zincirinin Parçası Olduğunda | Doubao Phone'un Güvenlik Analizi](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
