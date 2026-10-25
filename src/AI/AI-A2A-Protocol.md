# A2A (Agent2Agent) Protocol Güvenliği

{{#include ../banners/hacktricks-training.md}}

## A2A nedir

A2A (Agent2Agent), bir AI agent'ın başka bir agent'ı keşfetmesini ve HTTP üzerinden ona iş göndermesini sağlayan açık bir protokoldür. MCP, bir agent'ı **araçlara ve verilere** bağlar; A2A ise bir agent'ı genellikle başka bir ekip veya şirkete ait uzak hizmetler olan **diğer agent'lara** bağlar. A2A sunucusu, arkasında bir LLM agent'ı bulunan bir web API'sidir. Bu nedenle protokolün kendi nesneleri (agent kartları, görevler, push notification webhook'ları, genişletilmiş kartlar), normal bir API testine özel authentication, IDOR ve SSRF kontrolleri ekler.<sup>[[1]](#references)[[2]](#references)</sup>

Temel bileşenler şunlardır:

- **Agent Card:** agent'ı açıklayan JSON belgesi: adı, açıklaması, yetenekleri, hizmet URL'leri, desteklenen transport'lar, özellikler (streaming, push notification, genişletilmiş kart) ve client'ın kullanması gereken `securitySchemes`. `https://<host>/.well-known/agent-card.json` adresinde yayımlanır. Spec 0.2.x'i izleyen eski dağıtımlarda `/.well-known/agent.json` kullanılır.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** iş birimi. Bir mesaj görev oluşturur (sunucu tarafından oluşturulan bir `id` ve `contextId` ile) ve client daha sonra görevi okur, iptal eder veya göreve abone olur.<sup>[[1]](#references)</sup>
- **Transport'lar:** HTTP üzerinden JSON-RPC 2.0 (streaming için SSE ile), gRPC ve HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** kimlik bilgileri HTTP header'larına konur (örneğin `Authorization: Bearer ...`); asla JSON-RPC payload'ına konmaz. Agent kartı hangi scheme'in gerektiğini belirtir.<sup>[[1]](#references)</sup>

Method adları sürümler arasında değiştiğinden her iki grubu da deneyin:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| İşlem | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Mesaj gönderme | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming mesaj gönderme | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Görevi alma | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Görevleri listeleme | - | `ListTasks` | `GET /tasks` |
| Görevi iptal etme | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification yapılandırması | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Genişletilmiş kart | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec'i sürümü seçmek için `A2A-Version` header'ını (veya bir request parametresini) kullanır; bu header olmadan gelen istekler 0.3 olarak değerlendirilir.<sup>[[1]](#references)</sup>

## Keşif

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Karttan şunları not edin:

- Her `url` (genellikle dahili bir hostname, staging URL’si veya herkese açık sitedekinden farklı bir port).
- `skills`: Agent’ın neler yapabildiğini ve hangi araçların veya verilerin arkasında olduğunu gösterir.
- `securitySchemes` / `security`: Bunlar boşsa veya eksikse, agent muhtemelen kimlik bilgileri olmadan çağrılmak üzere tasarlanmıştır.
- `capabilities.pushNotifications` ve `capabilities.extendedAgentCard` (0.3 sürümünde `supportsAuthenticatedExtendedCard`).

Spec’e göre herkese açık kartta kimlik bilgileri veya dahili uygulama ayrıntıları bulunmamalıdır; bu nedenle herkese açık bir karttaki dahili URL’ler, anahtarlar veya ayrıntılı araç listeleri zaten bir bulgudur.<sup>[[1]](#references)</sup>

## A2A endpoint’lerini test etme

### Kimlik doğrulaması yapılmadan görev gönderimi

Kartta listelenen her `url` adresine hiçbir kimlik bilgisi içermeyen minimal bir mesaj gönderin:

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

A `Task` veya `Message` sonucunun `PONG` dönmesi ve kartta bir security scheme tanımlanmış olması, RPC endpoint'inde kimlik doğrulamanın uygulanmadığı anlamına gelir (kimlik doğrulama yalnızca UI'da veya kartta uygulanıyor olabilir). Kartta herhangi bir scheme tanımlı değilse, agent'ın skill'lerinin neler yapabildiğini kontrol edin: dahili verileri okuyabilen veya araçları çağırabilen kimlik doğrulamasız bir agent, bu araçlar için kimlik doğrulamasız bir API ile aynı şeydir.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spesifikasyon, sunucunun her istekte çağıranın göreve erişip erişemediğini kontrol etmesini ve filtre belirtilmediğinde bile `ListTasks` sonuçlarını çağıranla sınırlandırmasını gerektirir.<sup>[[1]](#references)</sup> Bunu iki kimlikle (A ve B) test edin:

1. A olarak bir görev oluşturun ve `id` ile `contextId` değerlerini kaydedin.
2. B olarak (veya kimlik bilgisi olmadan) A'nın `id` değeriyle `tasks/get` / `GetTask` çağrısı yapın, ardından parametre belirtmeden `ListTasks` çağrısı yapın.
3. Ayrıca A'nın görevinde cancel ve subscribe işlemlerini deneyin ve B olarak A'nın `taskId` veya `contextId` değerini içeren yeni bir mesaj gönderin (bu, B'nin metnini A'nın konuşmasına ekler).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Güvenlik Açığı Bulunan: B, A'nın geçmişini, artifact'larını veya durumunu alabilir ya da A'nın görevini değiştirebilir. Güvenli: `TaskNotFoundError`; "var ama sana ait değil" ile "yok" arasında fark bulunmamalıdır.<sup>[[1]](#references)</sup> Görev ID'leri genellikle UUID olduğundan, sızabilecekleri yerlere (paylaşılan bağlantılar, loglar, push notification payload'ları, hata mesajları) bakın.

### Push notification webhook SSRF

`capabilities.pushNotifications` true olduğunda, istemci ajana bir webhook URL'si verir ve ajan daha sonra görev güncellemelerini bu URL'ye göndermek için `POST` istekleri yapar. Spesifikasyon, ajanların özel aralıkları, localhost ve link-local adresleri reddetmesini ve allowlist kullanmasını söyler.<sup>[[1]](#references)</sup> Bir görev oluşturun, `url` alanı OAST host'unuzu gösteren bir push notification config kaydedin ve giden istekleri doğrulayın; ardından (yalnızca kapsam izin veriyorsa) `http://127.0.0.1:<port>/` veya `http://169.254.169.254/` gibi dahili hedefleri deneyin. Dahili servislerin haritasını çıkarmak için hata mesajlarını ve zamanlamayı karşılaştırın. Ajan ayrıca yapılandırılmış kimlik doğrulama başlığını da bu isteklere ekler; bu nedenle başka bir kullanıcının config'inin URL'sini değiştirebildiğinizde, bu başlığın saldırganın seçtiği bir host'a gönderilmediğini kontrol edin. Bkz. [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Extended agent card erişimi

`GetExtendedAgentCard` kimlik doğrulama gerektirmeli ve herkese açık card'dan daha fazla beceri ve yapılandırma döndürebilir.<sup>[[1]](#references)</sup> Kimlik bilgileri olmadan ve düşük ayrıcalıklı bir kimlikle çağırın, ardından sonucu herkese açık card ile karşılaştırın.

### Push notification config ve görev içi kimlik bilgisi sızıntıları

Push notification config'leri bir webhook URL'si ve ajanın bu URL'ye gönderdiği kimlik bilgilerini saklar. Spesifikasyon, her push notification config işleminin (create, get, list, delete) çağıranın göreve erişme yetkisi olup olmadığını doğrulamasını gerektirir.<sup>[[1]](#references)</sup> Bu rotalarda [task IDOR bölümündeki](#task-idor-tasksget-gettask-cancel-subscribe) iki kimlikli testi tekrarlayın. Başka bir kullanıcının okunabilen config'i bir webhook token'ını sızdırır; yazılabilen config'i ise o kullanıcının görev güncellemelerini sizin host'unuza yönlendirir.

Bir ajan görev sırasında ek yetkilendirmeye ihtiyaç duyduğunda, görevi `TASK_STATE_AUTH_REQUIRED` durumuna geçirir. İstemci, yetkilendirmeyi bant dışı şekilde ayarlayabilir; spesifikasyon, bant içi bir mekanizma üzerinde anlaşılmadıkça ajanların kimlik bilgilerini bant dışı alması gerektiğini söyler. Bant içi aktarım, A2A ajanları zinciri boyunca kimlik bilgisi iletebilir ve bu zincirdeki tüm ajanların kimlik bilgisine erişmesine yol açabilir.<sup>[[1]](#references)</sup> Bir orkestratör testinde, kullanıcının bir alt ajan için verdiği kimlik bilgisinin diğer ajanların (veya görev IDOR'u üzerinden diğer kullanıcıların) okuyabileceği mesajlarda, artifact'larda ya da görev geçmişinde görünüp görünmediğini kontrol edin.

Agent card alanları ve görev sonuçları da çağıran ajan için güvenilmeyen girdilerdir. Bunları [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) içindeki indirect prompt injection teknikleri ve [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) içindeki ajanlar arası güven kontrolleriyle test edin.

## References

- [1] [A2A Protokolü Spesifikasyonu](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Agent2Agent Protokolü'nün (A2A) Duyurusu](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A spesifikasyonu v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A spesifikasyonu v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
