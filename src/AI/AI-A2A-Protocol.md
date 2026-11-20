# A2A (Agent2Agent) Protocol Güvenliği

{{#include ../banners/hacktricks-training.md}}

## A2A nedir

A2A (Agent2Agent), bir AI agent'ın başka bir agent'ı keşfetmesini ve HTTP üzerinden ona iş göndermesini sağlayan açık bir protokoldür. MCP, bir agent'ı **araçlara ve verilere** bağlarken A2A, onu genellikle başka bir ekip veya şirkete ait uzak hizmetler olan **diğer agent'lara** bağlar. A2A server, arkasında bir LLM agent bulunan bir web API'sidir. Bu nedenle protokolün kendi nesneleri (agent cards, tasks, push-notification webhooks, extended cards), normal bir API testine özgü authentication, IDOR ve SSRF kontrolleri ekler.<sup>[[1]](#references)[[2]](#references)</sup>

Başlıca bileşenler şunlardır:

- **Agent Card:** Agent'ı tanımlayan bir JSON belgesi: adı, açıklaması, becerileri, hizmet URL'leri, desteklenen taşıma yöntemleri, özellikleri (streaming, push notifications, extended card) ve client'ın kullanması gereken `securitySchemes`. `https://<host>/.well-known/agent-card.json` adresinde yayımlanır. Spec 0.2.x'i izleyen eski kurulumlarda `/.well-known/agent.json` kullanılır.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** İş birimi. Bir message, (server tarafından oluşturulan bir `id` ve `contextId` içeren) bir task oluşturur; client daha sonra bu task'ı okur, iptal eder veya ona abone olur.<sup>[[1]](#references)</sup>
- **Transports:** HTTP üzerinden JSON-RPC 2.0 (streaming için SSE ile), gRPC ve HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** Kimlik bilgileri HTTP header'larına (örneğin `Authorization: Bearer ...`) eklenir; hiçbir zaman JSON-RPC payload'ına konmaz. Agent card hangi scheme'in gerektiğini belirtir.<sup>[[1]](#references)</sup>

Method adları sürümler arasında değiştiğinden her iki kümeyi de deneyin:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| İşlem | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Message gönder | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming gönderimi | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task al | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Task'ları listele | - | `ListTasks` | `GET /tasks` |
| Task'ı iptal et | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification yapılandırması | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec, sürümü seçmek için `A2A-Version` header'ını (veya bir request parametresini) kullanır; bu header olmadan gelen request'ler 0.3 olarak değerlendirilir.<sup>[[1]](#references)</sup>

## Keşif

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Karttan şunları not edin:

- Her `url`: 1.0'da bunlar `supportedInterfaces` altında yer alırken, eski kartlarda üst düzey `url` alanı bulunabilir. Dahili ana bilgisayar adları, staging URL'leri ve alternatif portlar dahil her endpoint'i ve taşıma protokolünü kaydedin.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: agent'ın neler yapabildiğini ve arkasında hangi araçların veya verilerin bulunduğunu gösterir.
- `securitySchemes` / `security`: bunlar boşsa veya yoksa, agent muhtemelen kimlik bilgileri olmadan çağrılmak üzere tasarlanmıştır.
- `capabilities.pushNotifications` ve `capabilities.extendedAgentCard` (0.3'te `supportsAuthenticatedExtendedCard`).

Spec, herkese açık kartta kimlik bilgileri veya dahili uygulama ayrıntılarının bulunmaması gerektiğini belirtir; dolayısıyla herkese açık bir karttaki dahili URL'ler, anahtarlar veya ayrıntılı araç listeleri zaten bir bulgudur.<sup>[[1]](#references)</sup>

### Çok agent'lı bir host'ta Agent Card ad çakışması

Bir kartın `name` alanı, insan tarafından okunabilir bir etikettir; kararlı bir yönlendirme kimliği değildir.<sup>[[1]](#references)[[5]](#references)</sup> Bir host aynı yerel ad altında iki farklı uzak peer kaydederse agent ağacı, oluşturulan araç adı, istemci eşlemesi veya broker rotası, güvenilir peer için tasarlanmış bir görevi diğer peer'a gönderebilir.<sup>[[5]](#references)</sup> Bunun gerçekleşmesi için saldırganın kontrolündeki peer'ın **aynı yönlendirme ad alanına** kabul edilmesi gerekir; internette yinelenen bir kart yayımlamak tek başına yeterli değildir.<sup>[[5]](#references)</sup>

İki kontrolünüzdeki peer ve zararsız bir işaretleyiciyle host'un **kabulden dağıtıma** giden yolunu test edin:<sup>[[5]](#references)</sup>

1. Güvenilir peer'ın kartını, kaynağını ve yerel seçicisini kaydedin. Aynı `name` değerine sahip, ancak URL'si kontrol ettiğiniz bir endpoint'i gösteren ikinci bir peer kaydedin.
2. Güvenilir peer'ı ada göre seçen işlemi tetikleyin. Her iki kayıt sırasını da deneyin; adlar araç tanımlayıcılarına dönüşüyorsa host'un normal ad normalleştirme yöntemini de deneyin. Hangi endpoint'in işaretleyiciyi aldığını ve yanıtı hangi agent'ın döndürdüğünü kaydedin.
3. Yalnızca ikinci kartın adını değiştirip testi tekrarlayın. İkinci endpoint'e yalnızca ad çakışması durumunda ulaşan bir istek, yanlış peer'a yönlendirme olduğunu kanıtlar. Ayrıca herhangi bir hassas bağlamın veya kimlik bilgisinin gerçekten iletilip iletilmediğini ayrı olarak kontrol edin; ad çakışması tek başına kimlik bilgisi veya araç yetkisi aktarımını **kanıtlamaz**.

Çağıran taraf bir kart adını çözümlemek yerine sabit ve kaynağa bağlı bir endpoint'e erişiyorsa bu test uygulanmaz.<sup>[[5]](#references)</sup> Sonraki aşamalardaki kötü amaçlı peer yanıtları ve prompt injection etkisi için [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary) bölümünü izleyin.

## A2A endpoint'lerini test etme

### Kimlik doğrulaması olmadan görev gönderme

Kartta listelenen her `url`'ye, kimlik bilgisi içermeyen minimal bir mesaj gönderin:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Bir `Task` veya `Message` sonucunun `PONG` olması ve card'ın bir security scheme belirtmesi, RPC endpoint'inde authentication uygulanmadığı anlamına gelir (authentication yalnızca UI'da veya card üzerinde uygulanıyor olabilir). Card herhangi bir scheme belirtmiyorsa, agent'ın skills'lerinin neler yapabildiğini kontrol edin: Dahili verileri okuyabilen veya araçları çağırabilen unauthenticated bir agent, bu araçlar için unauthenticated bir API ile aynı riski taşır.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec, server'ın her istekte çağıranın task'a erişip erişemediğini kontrol etmesini ve filtre belirtilmediğinde bile `ListTasks` sonuçlarını çağıranla sınırlandırmasını gerektirir.<sup>[[1]](#references)</sup> İki identity ile test edin (A ve B):

1. A olarak bir task oluşturun ve `id` ile `contextId` değerlerini kaydedin.
2. B olarak (veya hiçbir credentials olmadan), A'nın `id` değeriyle `tasks/get` / `GetTask` çağrısı yapın; ardından parametre belirtmeden `ListTasks` çağrısı yapın.
3. Ayrıca A'nın task'ı üzerinde cancel ve subscribe işlemlerini deneyin ve B olarak A'nın `taskId` veya `contextId` değerini içeren yeni bir message gönderin (bu, B'nin metnini A'nın conversation'ına ekler).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Güvenlik açığı bulunan: B, A'nın geçmişini, artifact'larını veya durumunu alabilir ya da A'nın görevini değiştirebilir. Güvenli: `TaskNotFoundError`; "var ama sana ait değil" ile "yok" durumları arasında fark olmamalıdır.<sup>[[1]](#references)</sup> Task ID'leri genellikle UUID olduğundan, sızabilecekleri yerlere (paylaşılan bağlantılar, log'lar, push notification payload'ları, hata mesajları) bakın.

### Push notification webhook SSRF

`capabilities.pushNotifications` true olduğunda, client agente bir webhook URL'si verir ve agent daha sonra görev güncellemelerini bu URL'ye `POST` istekleriyle gönderir. Spec, agent'ların private range'leri, localhost ve link-local adresleri reddetmesini ve allowlist kullanmasını söyler.<sup>[[1]](#references)</sup> Bir task oluşturun, `url` değeri OAST host'unuza işaret eden bir push notification config kaydedin ve giden istekleri doğrulayın; ardından (yalnızca kapsam izin veriyorsa) `http://127.0.0.1:<port>/` veya `http://169.254.169.254/` gibi dahili hedefleri deneyin. Dahili servisleri haritalamak için hataları ve zamanlamayı karşılaştırın. Agent ayrıca yapılandırılmış authentication header'ını bu isteklere ekler; bu nedenle, başka bir kullanıcının config'inin URL'sini değiştirebildiğinizde bu header'ın saldırganın seçtiği bir host'a gönderilmediğini kontrol edin. Bkz. [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### İkinci bir SSRF giriş noktası olarak File-URL Parts

A2A 1.0, bir mesajın veya artifact'ın `url` içeren bir `Part` olarak file reference taşımasına olanak tanır (0.3 sürümünde `kind: "file"` ve `file.uri` kullanılır).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protocol bu reference'ı taşır; onu fetch etmek A2A SDK'nın gerekliliği değil, uygulamanın davranışıdır.<sup>[[6]](#references)</sup> Bu, yukarıdaki push-notification callback URL'sinden ayrıdır. Her iki yönü de test edin: A2A server'a gönderilen, client tarafından sağlanmış bir file ve daha düşük güven düzeyindeki bir peer'den orchestrator'a döndürülen bir file URL'si.<sup>[[1]](#references)[[6]](#references)</sup>

Yetkili bir 1.0 JSON-RPC endpoint'i için normal text part'ı benzersiz bir OAST path'ine yönlendiren bir URL ile değiştirin ve isteği **hangi component'in** yaptığını kontrol edin:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Yalnızca alıcı bunu dereference ederse, [SSRF workflow](../pentesting-web/ssrf-server-side-request-forgery/) kullanarak kapsam içindeki dahili hedefleri, yönlendirmeleri ve DNS çözümleme değişikliklerini test edin. Geçerli bir `Part` veya başarılı bir görev yanıtı tek başına SSRF olduğunu kanıtlamaz; hedefte isteğin yapıldığını ve alınan içeriğin agent'a ulaşıp ulaşmadığını doğrulayın.<sup>[[6]](#references)</sup>

### Genişletilmiş agent kartına erişim

`GetExtendedAgentCard` kimlik doğrulaması gerektirmeli ve herkese açık karttan daha fazla beceri ve yapılandırma döndürebilir.<sup>[[1]](#references)</sup> Kimlik bilgisi olmadan ve düşük ayrıcalıklı bir kimlikle çağırın; sonucu herkese açık kartla karşılaştırın.

### Push notification yapılandırması ve görev içi kimlik bilgisi sızıntıları

Push notification yapılandırmaları bir webhook URL'sini ve agent'ın bu URL'ye gönderdiği kimlik bilgilerini saklar. Spesifikasyon, her push notification yapılandırma işleminin (oluşturma, alma, listeleme, silme) çağıranın göreve erişme yetkisini doğrulamasını gerektirir.<sup>[[1]](#references)</sup> Bu rotalarda [task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe) bölümündeki iki kimlikli testi tekrarlayın. Başka bir kullanıcının yapılandırmasının okunabilmesi webhook token'ını sızdırır; yazılabilmesi ise o kullanıcının görev güncellemelerini sizin sunucunuza yönlendirir.

Bir agent'ın görev sırasında ek yetkilendirmeye ihtiyacı olduğunda, görev `TASK_STATE_AUTH_REQUIRED` durumuna geçer. İstemci yetkilendirmeyi bant dışı biçimde sağlayabilir; spesifikasyon, bant içi bir mekanizma üzerinde anlaşılmadıkça agent'ların kimlik bilgilerini bant dışı alması gerektiğini belirtir. Bant içi aktarım, bir A2A agent zinciri üzerinden kimlik bilgisi iletebilir ve bu zincirdeki her agent'ın bu bilgiyi görmesine yol açabilir.<sup>[[1]](#references)</sup> Bir orkestratör testinde, kullanıcının tek bir aşağı akış agent'ı için verdiği kimlik bilgisinin mesajlarda, artifact'lerde veya görev geçmişinde görünüp görünmediğini kontrol edin; bunlara diğer agent'lar (veya görev IDOR'u aracılığıyla diğer kullanıcılar) erişebilir.

Agent kartı alanları ve görev sonuçları da çağıran agent için güvenilmeyen girdilerdir. Bunları [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) içindeki indirect prompt injection teknikleriyle ve [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) içindeki agent'lar arası güven kontrolleriyle test edin.



## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Announcing the Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A specification v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A specification v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Agent Name Collision Attacks in Multi-Agent Systems](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK Security Guide](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0 Migration Guide](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
