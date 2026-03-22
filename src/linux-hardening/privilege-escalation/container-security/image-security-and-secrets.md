# İmaj Güvenliği, İmzalama ve Gizli Bilgiler

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Konteyner güvenliği, iş yükü başlatılmadan önce başlar. İmaj, üretime hangi ikili dosyaların, yorumlayıcıların, kütüphanelerin, başlangıç betiklerinin ve gömülü yapılandırmanın ulaşacağını belirler. İmaj arka kapı içeriyorsa, güncel değilse veya içine gizli bilgiler gömülmüş olarak oluşturulmuşsa, sonrasında yapılan çalışma zamanı sertleştirmesi zaten tehlikeye düşmüş bir artefakt üzerinde çalışıyor demektir.

Bu nedenle imaj kökeni, zafiyet taraması, imza doğrulama ve gizli bilgi yönetimi, namespaces ve seccomp ile aynı tartışmanın parçasıdır. Yaşam döngüsünün farklı bir aşamasını korurlar, ancak burada meydana gelen hatalar genellikle çalışma zamanının daha sonra sınırlandırmak zorunda olduğu saldırı yüzeyini belirler.

## İmaj Kayıt Defterleri ve Güven

İmajlar Docker Hub gibi genel kayıt defterlerinden veya bir kuruluş tarafından işletilen özel kayıt defterlerinden gelebilir. Güvenlik sorunu sadece imajın nerede yaşadığı değil, ekibin kökeni ve bütünlüğü tespit edip edemeyeceğidir. Genel kaynaklardan imzalanmamış veya kötü takip edilen imajları çekmek, kötü amaçlı veya değiştirilmiş içeriğin üretime girmesi riskini artırır. Dahili olarak barındırılan kayıt defterlerinin bile net sahiplik, inceleme ve güven politikalarına ihtiyacı vardır.

Docker Content Trust tarihsel olarak imzalı imajları zorunlu kılmak için Notary ve TUF kavramlarını kullanıyordu. Tam ekosistem değişmiş olabilir, ancak kalıcı ders şu ki: imaj kimliği ve bütünlüğü varsayılmamalı, doğrulanabilir olmalıdır.

Örnek tarihsel Docker Content Trust iş akışı:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Bu örneğin amacı her ekibin aynı araçları kullanması gerektiğini göstermek değil; signing ve key management'in soyut teori değil, operasyonel görevler olduğunu vurgulamaktır.

## Zafiyet Taraması

İmaj taraması iki farklı soruyu cevaplamaya yardımcı olur. Birincisi, imaj bilinen zafiyete sahip paketler veya kütüphaneler içeriyor mu? İkincisi, imaj saldırı yüzeyini genişleten gereksiz yazılımlar barındırıyor mu? Debugging araçları, shell'ler, interpreter'lar ve güncelliğini yitirmiş paketlerle dolu bir imaj hem sömürülmesi daha kolay hem de üzerinde düşünülmesi daha zordur.

Sık kullanılan tarayıcı örnekleri şunlardır:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Bu araçlardan elde edilen sonuçlar dikkatle yorumlanmalıdır. Kullanılmayan bir paketteki bir zafiyet, açık bir RCE yolunun taşıdığı riskle aynı değildir; ancak her ikisi de hardening kararları açısından yine de önemlidir.

## Derleme Zamanı Sırlar

Container build pipeline'larındaki en eski hatalardan biri, sırların doğrudan image'e gömülmesi veya sonrasında çevresel değişkenler aracılığıyla geçirilmesidir; bu değişkenler daha sonra `docker inspect`, build log'ları veya kurtarılan katmanlar üzerinden görünür hale gelebilir. Derleme zamanındaki sırlar, image dosya sistemine kopyalanmak yerine derleme sırasında geçici olarak bağlanmalıdır.

BuildKit bu modeli, adanmış derleme zamanı secret yönetimine izin vererek iyileştirdi. Bir sırın bir katmana yazılmasındansa, build adımı onu geçici olarak kullanabilir:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Bu önemlidir çünkü image katmanları kalıcı artefaktlardır. Bir secret committed bir katmana girdiğinde, dosyayı daha sonra başka bir katmanda silmek orijinal açığa çıkarmayı image geçmişinden gerçekten kaldırmaz.

## Çalışma Zamanı Secrets

Çalışan bir workload'un ihtiyaç duyduğu secrets mümkün olduğunca ad hoc yaklaşımlardan, örneğin düz environment variables kullanımından kaçınmalıdır. Volumes, dedicated secret-management integrations, Docker secrets ve Kubernetes Secrets yaygın mekanizmalardır. Bunların hiçbiri tüm riski ortadan kaldırmaz — özellikle attacker zaten workload içinde code execution elde etmişse — ancak yine de credentials'ı kalıcı olarak image içinde depolamaya veya bunları inspection tooling ile rastgele açığa çıkarmaya kıyasla tercih edilirler.

A simple Docker Compose style secret declaration looks like:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Kubernetes'te, Secret objects, projected volumes, service-account tokens ve cloud workload identities daha geniş ve daha güçlü bir model oluşturur; ancak bunlar aynı zamanda host mounts, broad RBAC veya zayıf Pod design yoluyla kazara maruziyet için daha fazla fırsat yaratır.

## Kötüye kullanım

Hedefi incelerken amaç, secrets'in image'e bake edilip edilmediğini, layers'a leaked olup olmadığına veya öngörülebilir runtime konumlarına mounted edilip edilmediğini keşfetmektir:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Bu komutlar üç farklı sorunu ayırt etmeye yardımcı olur: application configuration leaks, image-layer leaks ve runtime-injected secret files. Eğer bir secret `/run/secrets`, bir projected volume veya bir cloud identity token path altında görünürse, bir sonraki adım bunun yalnızca mevcut workload'a mı yoksa çok daha geniş bir control plane'e mi erişim sağladığını anlamaktır.

### Tam Örnek: İmaj Dosya Sisteminde Gömülü Secret

Eğer bir build pipeline `.env` dosyalarını veya credentials'ı final image'e kopyaladıysa, post-exploitation basit hale gelir:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Etkisi uygulamaya bağlıdır, ancak embedded signing keys, JWT secrets veya cloud credentials, container compromise'ını kolayca API compromise'a, lateral movement'e veya trusted application tokens'ın forgery'sine dönüştürebilir.

### Full Example: Build-Time Secret Leakage Check

Endişe image history'nin secret-bearing layer yakalamış olmasıysa:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
## Kontroller

Bu tür bir inceleme yararlıdır çünkü bir secret, nihai dosya sistemi görünümünden silinmiş olsa bile önceki bir katmanda veya build metadata'sında hâlâ kalmış olabilir.

Bu kontroller, image ve secret-handling pipeline'ının çalışma zamanından önce saldırı yüzeyini artırmış olma olasılığını belirlemeye yöneliktir.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- Şüpheli bir build geçmişi kopyalanmış credentials, SSH materyali veya güvensiz build adımlarını açığa çıkarabilir.
- projected volume paths altındaki Secrets, sadece yerel uygulama erişimi değil, cluster veya cloud erişimi sağlayabilir.
- Düz metin credentials içeren çok sayıda konfigürasyon dosyası genellikle image veya deployment modelinin gereğinden fazla trust materyali taşıdığını gösterir.

## Runtime Defaults

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker / BuildKit | Güvenli build-time secret mountlarını destekler, fakat otomatik değildir | Secrets `build` sırasında geçici olarak mount edilebilir; image signing ve scanning açık workflow seçimleri gerektirir | secrets'i image içine kopyalamak, secrets'i `ARG` veya `ENV` ile geçirmek, provenance kontrollerini devre dışı bırakmak |
| Podman / Buildah | OCI-native build'leri ve secret-aware workflow'ları destekler | Güçlü build workflow'ları mevcut, ancak operatörlerin bunları kasıtlı olarak seçmesi gerekir | Containerfiles içine secrets gömmek, geniş build context'leri, build sırasında fazla izinli bind mount'lar |
| Kubernetes | Native Secret objects ve projected volumes | Runtime secret teslimi birinci sınıftır, ancak ifşa RBAC, pod tasarımı ve host mount'larına bağlıdır | gereğinden geniş Secret mount'ları, service-account token kötüye kullanımı, `hostPath` erişimi kubelet-managed volumelere |
| Registries | Integrity zorlanmadıkça isteğe bağlıdır | Hem public hem private registries politika, signing ve admission kararlarına bağlıdır | imzalanmamış image'ları serbestçe çekme, zayıf admission kontrolü, kötü anahtar yönetimi |
{{#include ../../../banners/hacktricks-training.md}}
