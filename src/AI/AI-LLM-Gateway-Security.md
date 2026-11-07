# LLM Gateway Güven Sınırları

{{#include ../banners/hacktricks-training.md}}

Bir LLM gateway, model yönlendirmesini yönetir ve çoğu zaman provider kimlik bilgilerini saklar; bu nedenle sıradan API çağrısı yapan istemciler yapılandırma veya provider düzeyinde yetki devralmamalıdır. LiteLLM 1.77.7 sürümünde yapılan gateway değerlendirmesi, iki ayrı sınırı ortaya koyuyor: yönetim yapılandırması için UI oturum yetkilendirmesi ve inference için çağıran tarafından sağlanan yönlendirme yapılandırması. Bildirilen sorunlar 1.83.9 sürümünde giderildi.<sup>[[1]](#references)</sup>

## UI route sınıflandırması yetkilendirme değildir

Değerlendirilen LiteLLM sürümünde, UI login anahtarları `litellm-dashboard` takımına aitti. Yetkilendirme, kullanıcının rolünden bağımsız olarak, anahtarın bu takım tanımlayıcısına sahip olmasına göre onu UI token'ı olarak sınıflandırıyordu. UI route kontrolü de allowlist'teki bir önekle başlayan tüm route'ları kabul ediyordu. Sonuç olarak, `/config` girdisi yönetim amaçlı `/config/update` handler'ıyla da eşleşiyordu. Bu handler genel kimlik doğrulaması gerektiriyor, ancak ayrıca `PROXY_ADMIN` rolü aramıyordu; bu nedenle daha düşük yetkili bir UI oturumu yapılandırma yazma erişimi elde edebiliyordu.<sup>[[1]](#references)</sup>

Bu durum, proxy/backend yol normalleştirmesi uyuşmazlığından farklıdır: yetkilendirme kodu ile handler, *aynı* route'un yetki düzeyi konusunda anlaşmazlığa düşer.<sup>[[1]](#references)</sup> Bir gateway'i incelerken token sınıflandırmasını, tam route ve method eşleşmesini ve handler'ın kendi rol kontrolünü karşılaştırın.<sup>[[1]](#references)</sup> İlgili ancak farklı sınırlar için [web API yetkilendirmesi](../pentesting-web/web-api-pentesting.md), [401/403 bypass'ları](../pentesting-web/403-and-401-bypasses.md) ve [proxy önek muafiyetleri](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) bölümlerine bakın.

## Yapılandırma yazma işlemleri yapılandırma deposundan fazlasını etkiler

Aynı LiteLLM yapılandırma güncellemesi, ortam değişkeni değerlerini kabul edip çalışan sürece uyguluyordu. Bir bileşen, `UI_LOGO_PATH` değerini yerel bir `FileResponse` yolu olarak kullanıyor, ancak bu yolun bir logo olduğunu doğrulamıyordu; başka bir bileşen ise SSO dışı login sırasında `UI_USERNAME` ve `UI_PASSWORD` değerlerini okuyup eşleşmeleri durumunda `PROXY_ADMIN` rolü atıyordu. Dolayısıyla yapılandırma yazma izni, aşağı akıştaki bileşene bağlı olarak hem yerel dosya ifşasına hem de yönetici kimliğinin değiştirilmesine yol açabiliyordu. Yanıtın medya türü, sunulan dosyanın bir görsel olduğunu kanıtlamaz.<sup>[[1]](#references)</sup>

Pass-through endpoint yapılandırması da aşağı akıştaki başka bir hedefti. Başlatma işlemi uzak S3/GCS adapter hedeflerini kabul ediyor, Python modüllerini indiriyor ve `importlib`'in `exec_module` işleviyle içe aktarıyordu. Import işlemi, bir adapter örneği kullanılmadan önce üst düzey kodu çalıştırır; yalnızca adapter'ın çağrılmasını kısıtlamak bu çalıştırma sınırını ortadan kaldırmaz. Bunu model dosyası deserialization işlemi olarak değil, yapılandırma denetimli kod yükleme olarak değerlendirin.<sup>[[1]](#references)</sup> Ayrı dosya okuma primitive'i için [dosya dahil etme ve path traversal](../pentesting-web/file-inclusion/) bölümüne bakın.

## İstek başına model yönlendirmesi gateway kimlik bilgilerini sızdırabilir

LiteLLM'in istemci tarafı kimlik bilgisi özelliği, bir LLM isteğinde `user_config` nesnesi kabul ediyordu. Değerlendirilen route, model listesi ve provider `api_base` değeri dahil olmak üzere bu nesneden geçici bir `litellm.Router` oluşturuyordu. Çağıranın kontrolündeki bir provider hedefi, gateway'in giden completion isteğini ve yapılandırılmış provider kimlik doğrulama başlıklarını alabiliyordu. Üst düzey `api_base` veya `api_key` alanlarındaki kısıtlamalar, bu ayrı iç içe yapılandırma yolunu kapsamıyordu. Bu, prompt injection sorunu değil, kimlik bilgileri taşıyan bir SSRF sınırıdır.<sup>[[1]](#references)</sup>

Yetkili bir gateway değerlendirmesinde, her router veya provider istemcisi oluşturabilen yolu (istek başına yapılandırma dahil), normal yapılandırılmış route'ta kullanılan hedef ve kimlik bilgisi politikasıyla karşılaştırın.<sup>[[1]](#references)</sup> [SSRF kılavuzu](../pentesting-web/ssrf-server-side-request-forgery/), sunucu tarafındaki hedef kontrolünü genel olarak ele alır; gateway'e özgü hata ise daha az güvenilir bir istek nesnesinin, ayrıcalıklı giden kimlik bilgileri yeniden kullanılırken hedef seçmesine izin verilmesidir.<sup>[[1]](#references)</sup>

## Guardrail kaydı, yalnızca UI'da uygulanan sandbox'ı aşabilir

Bir gateway'in code-test yolu ile code-registration yolu farklı doğrulama uygulayabilir. LiteLLM'in v1.82.0 öncesi sürümlerinde, UI'daki özel guardrail testi tehlikeli sözdizimini reddediyor ve `__builtins__ = {}` ile çalıştırıyordu; ancak `POST /guardrails`, gönderilen `custom_code` değerini bu kontrollerden hiçbirini yapmadan `exec(compile(...), exec_globals)` ile derliyordu. `__builtins__` bulunmayan bir globals sözlüğüne Python builtins eklediğinden, modül düzeyindeki import ve komutlar **guardrail kaydedildiğinde**, herhangi bir inference çağrısından önce çalışıyordu. Daha sonraki `apply_guardrail` callback'i, depolanmış bir sonucu block reason üzerinden açığa çıkarabiliyordu.<sup>[[2]](#references)[[3]](#references)</sup>

Yetkili bir testte, başarılı bir UI sandbox testinin kayıt işleminin güvenli olduğunu kanıtladığını varsaymak yerine test ve kayıt handler'larını karşılaştırın. Düzeltme öncesi bildirilen istek biçimi şuydu:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

Kayıt endpoint'i, `PROXY_ADMIN` kontrolü olmadığı için sıradan API anahtarlarını da kabul ediyordu. Master key veya JWT/OAuth2 authentication yapılandırılmadığında, düzeltme öncesi auth handler anonim isteklere bile `PROXY_ADMIN` atıyordu. Düzeltme, auth olmayan durumdaki rolü `INTERNAL_USER` olarak değiştirdi, guardrail admin kontrolleri ekledi ve kayıt sırasında builtins öğelerini doğrulayıp kısıtladı. Bu rol ve code-execution sınırları, [MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session) konusundan ayrıdır.<sup>[[2]](#references)[[3]](#references)</sup>

## Admin pass-through rotaları cloud metadata'yı proxy'leyebilir

LiteLLM'in pass-through endpoint özelliği, bir administrator'ın HTTP hedefi yapılandırmasına ve isteğe bağlı olarak alt yollar eklemesine olanak tanır. Yukarıdaki istek başına `user_config` yönlendirme sorunundan farklı olarak, bu özellik **configuration-write authority** gerektirir; özelliğin kendisi administrator'lara güvenmek üzere tasarlanmıştır. Bildirilen deployment'ta hedef, private veya link-local adreslere karşı kontrol edilmiyordu.<sup>[[2]](#references)[[4]](#references)</sup> v1.83.0 öncesinde, `/config/update` endpoint'inde administrator role kontrolü olmadığı için sıradan kimliği doğrulanmış anahtarlar da bu endpoint'e erişebiliyordu; bununla ilişkili configuration-write sınırı için [UI route classification](#ui-route-classification-is-not-authorization) bölümüne bakın.<sup>[[2]](#references)[[6]](#references)</sup>

Bu yetki ve proxy'den EC2 metadata'ya ağ erişimi olduğunda, aşağıdaki gibi bir rota metadata'yı gateway üzerinden açığa çıkarır. `include_subpath` flag'i, `/meta/meta-data/iam/security-credentials/` yolunun `/latest/` altında eşlenmesini sağlar.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF rehberi](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) IMDSv2 token değişimini ele alır; bu route, `PUT` isteğine izin vermeli ve her iki metadata header'ını da iletmelidir.<sup>[[5]](#references)</sup> LiteLLM'in genel pass-through header işleme mekanizması, iletmeden önce `x-pass-` önekini kaldırır; bu nedenle `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` ve `x-pass-X-aws-ec2-metadata-token: <token>` bu header'ları sağlayabilir.<sup>[[2]](#references)[[7]](#references)</sup> Proxy, IMDS'ye erişebilmeli, token yanıtı yapılandırılmış hop limitini aşabilmeli ve token isteği `X-Forwarded-For` içermemelidir.<sup>[[5]](#references)</sup> Gateway'e özgü varyasyon, **admin tarafından kontrol edilen kalıcı route ile istek header'larının aktarılmasıdır**.

## References

- [1] [Check Point Research — LLM Gateway'leri yanlış çalıştığında: LiteLLM bulguları](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Hazırlıksız yakalanmak: LiteLLM'i authentication bypass'tan cloud compromise'a kadar kırmak](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — custom code guardrail'deki kimlik doğrulaması gerektirmeyen RCE ve sandbox escape'i düzeltme](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Pass Through endpoint'leri oluşturma](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Instance Metadata Service Version 2 nasıl çalışır?](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM bildirimi — kısıtlanmamış proxy yapılandırma endpoint'i](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM pass-through header iletme uygulaması](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
