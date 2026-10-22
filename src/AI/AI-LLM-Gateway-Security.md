# LLM Gateway Güven Sınırları

{{#include ../banners/hacktricks-training.md}}

Bir LLM gateway, model yönlendirmesini yönetir ve çoğu zaman sağlayıcı kimlik bilgilerini saklar; bu nedenle sıradan API çağrıları yapan kullanıcılar yapılandırma veya sağlayıcı düzeyindeki yetkileri devralmamalıdır. LiteLLM gateway'inin 1.77.7 sürümünde yapılan değerlendirme, iki ayrı sınırı ortaya koyuyor: yönetim yapılandırması için UI oturumu yetkilendirmesi ve inference için çağıranın sağladığı yönlendirme yapılandırması. Raporlanan sorunlar 1.83.9 sürümünde düzeltildi.<sup>[[1]](#references)</sup>

## UI route sınıflandırması yetkilendirme değildir

Değerlendirilen LiteLLM sürümünde, UI giriş anahtarları `litellm-dashboard` takımına aitti. Yetkilendirme, kullanıcının rolünden bağımsız olarak, takım tanımlayıcısına göre bir anahtarı UI token'ı olarak sınıflandırıyordu. UI route kontrolü de izin verilen bir önekle başlayan her route'u kabul ediyordu. Sonuç olarak, `/config` girdisi yönetim amaçlı `/config/update` handler'ıyla da eşleşiyordu. Bu handler genel kimlik doğrulaması gerektiriyor, ancak ayrıca `PROXY_ADMIN` rolünü zorunlu kılmıyordu; böylece daha düşük yetkili bir UI oturumu, yapılandırmaya yazma erişimi elde ediyordu.<sup>[[1]](#references)</sup>

Bu, proxy/backend yol normalleştirme uyuşmazlığından farklıdır: yetkilendirme kodu ile handler, *aynı* route'un yetkisi konusunda anlaşmazlığa düşer.<sup>[[1]](#references)</sup> Bir gateway'i incelerken token sınıflandırmasını, route ve method eşleştirmesinin tamlığını ve handler'ın kendi rol kontrolünü karşılaştırın.<sup>[[1]](#references)</sup> İlgili ancak farklı sınırlar hakkında bilgi için [web API yetkilendirmesi](../pentesting-web/web-api-pentesting.md), [401/403 atlatmaları](../pentesting-web/403-and-401-bypasses.md) ve [proxy öneki istisnaları](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) sayfalarına bakın.

## Yapılandırma yazma işlemleri yapılandırma deposundan daha fazlasını etkiler

Aynı LiteLLM yapılandırma güncelleme işlemi, ortam değişkeni değerlerini kabul ediyor ve çalışan sürece uyguluyordu. Bir tüketici, `UI_LOGO_PATH` değerini logo olduğunu doğrulamadan `FileResponse` için yerel bir yol olarak kullanıyordu; başka bir tüketici ise SSO dışı giriş sırasında `UI_USERNAME` ve `UI_PASSWORD` değerlerini okuyup eşleşmeleri hâlinde `PROXY_ADMIN` atıyordu. Dolayısıyla yapılandırmaya yazma izni, aşağı akıştaki tüketiciye bağlı olarak hem yerel dosya ifşasına hem de yönetici kimliğinin değiştirilmesine yol açabiliyordu. Yanıtın medya türü, sunulan dosyanın bir görsel olduğunu kanıtlamaz.<sup>[[1]](#references)</sup>

Pass-through endpoint yapılandırması da başka bir aşağı akış hedefiydi. Başlatma işlemi, uzak S3/GCS adapter hedeflerini kabul ediyor, Python modüllerini indiriyor ve `importlib`'in `exec_module` işlevini kullanarak içe aktarıyordu. İçe aktarma, bir adapter örneği kullanılmadan önce üst düzey kodu çalıştırır; yalnızca adapter'ın çağrılmasını kısıtlamak bu yürütme sınırını ortadan kaldırmaz. Bunu model dosyası deserialization işlemi olarak değil, yapılandırma kontrollü kod yükleme olarak değerlendirin.<sup>[[1]](#references)</sup> Ayrı dosya okuma primitive'i için [dosya dahil etme ve path traversal](../pentesting-web/file-inclusion/) sayfasına bakın.

## İstek başına model yönlendirmesi gateway kimlik bilgilerini leak edebilir

LiteLLM'in istemci tarafı kimlik bilgisi özelliği, bir LLM isteğinde `user_config` nesnesi kabul ediyordu. Değerlendirilen route, bu nesneden model listesi ve sağlayıcı `api_base` değeri de dahil olmak üzere geçici bir `litellm.Router` oluşturuyordu. Çağıranın kontrolündeki bir sağlayıcı hedefi, gateway'in giden completion isteğini ve yapılandırılmış sağlayıcı kimlik doğrulama başlıklarını alabiliyordu. Üst düzey `api_base` veya `api_key` alanlarına getirilen kısıtlamalar, bu ayrı iç içe yapılandırma yolunu kapsamıyordu. Bu, prompt injection sorunu değil, kimlik bilgileri taşıyan bir SSRF sınırıdır.<sup>[[1]](#references)</sup>

Yetkili bir gateway değerlendirmesinde, istek başına yapılandırma dahil olmak üzere router veya sağlayıcı istemcisi oluşturabilen her yolu, normal yapılandırılmış route'un kullandığı hedef ve kimlik bilgisi politikasıyla karşılaştırın.<sup>[[1]](#references)</sup> [SSRF kılavuzu](../pentesting-web/ssrf-server-side-request-forgery/) genel sunucu tarafı hedef kontrolünü ele alır; gateway'e özgü hata ise daha az güvenilir bir istek nesnesinin, ayrıcalıklı giden kimlik bilgilerini yeniden kullanırken hedefi seçmesine izin verilmesidir.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — LLM Gateway'leri Hatalı Çalıştığında: LiteLLM'den Bulgular](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
