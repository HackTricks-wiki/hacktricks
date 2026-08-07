# Image Security, Signing, And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Container security, workload başlatılmadan önce başlar. Image; hangi binary'lerin, interpreter'ların, library'lerin, startup script'lerinin ve gömülü configuration'ın production ortamına ulaşacağını belirler. Image backdoor içeriyorsa, güncel değilse veya içine secret'lar gömülerek build edildiyse, sonrasında uygulanan runtime hardening zaten compromise edilmiş bir artifact üzerinde çalışıyor demektir.

Bu nedenle image provenance, vulnerability scanning, signature verification ve secret handling; namespaces ve seccomp ile aynı konu kapsamında değerlendirilmelidir. Bunlar lifecycle'ın farklı bir aşamasını korur, ancak bu aşamadaki hatalar genellikle runtime'ın daha sonra kontrol altına alması gereken attack surface'i belirler.

## Image Registries And Trust

Image'lar Docker Hub gibi public registry'lerden veya bir organization tarafından işletilen private registry'lerden gelebilir. Güvenlik sorusu yalnızca image'ın nerede bulunduğu değil, ekibin provenance ve integrity'yi doğrulayıp doğrulayamayacağıdır. Public kaynaklardan unsigned veya yeterince takip edilmeyen image'ları pull etmek, malicious veya değiştirilmiş içeriğin production ortamına girme riskini artırır. Internally hosted registry'lerin bile açık bir ownership, review ve trust policy'ye ihtiyacı vardır.

Docker Content Trust, tarihsel olarak signed image'lar gerektirmek için Notary ve TUF kavramlarını kullanıyordu. Ekosistemin kendisi zaman içinde gelişmiş olsa da kalıcı ders hâlâ geçerlidir: image identity ve integrity varsayılmamalı, doğrulanabilir olmalıdır.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Örneğin amacı, her ekibin hâlâ aynı tooling'i kullanması gerektiğini göstermek değil; signing ve key management işlemlerinin soyut bir teori değil, operasyonel görevler olduğunu vurgulamaktır.

## Zafiyet Taraması

Image scanning iki farklı soruya yanıt vermeye yardımcı olur. İlk olarak, image bilinen zafiyetlere sahip package veya library'ler içeriyor mu? İkinci olarak, image attack surface'i genişleten gereksiz software taşıyor mu? Debugging tool'ları, shell'ler, interpreter'lar ve stale package'lerle dolu bir image hem exploit edilmesi daha kolaydır hem de hakkında değerlendirme yapmak daha zordur.

Yaygın olarak kullanılan scanner örnekleri şunlardır:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Bu araçlardan elde edilen sonuçlar dikkatle yorumlanmalıdır. Kullanılmayan bir paketteki güvenlik açığının riski, dışarıya açık bir RCE yolunun riskiyle aynı değildir; ancak her ikisi de hardening kararları açısından hâlâ önemlidir.

## Build-Time Secrets

Container build pipeline'larındaki en eski hatalardan biri, secret'ları doğrudan image'a gömmek veya bunları daha sonra `docker inspect`, build log'ları ya da geri kazanılan layer'lar üzerinden görünür hâle gelen environment variable'lar aracılığıyla geçirmektir. Build-time secret'lar, image filesystem'ına kopyalanmak yerine build sırasında geçici olarak mount edilmelidir.

BuildKit, build-time secret'ların özel olarak yönetilmesine izin vererek bu modeli geliştirdi. Bir secret'ı bir layer'a yazmak yerine, build step secret'ı geçici olarak kullanabilir:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Bu önemlidir, çünkü image katmanları kalıcı artifact'lerdir. Bir secret committed bir katmana girdikten sonra, dosyayı daha sonraki başka bir katmanda silmek, image history içindeki ilk disclosure'ı gerçekten kaldırmaz.

## Runtime Secrets

Çalışan bir workload'un ihtiyaç duyduğu secret'lar da mümkün olduğunda plain environment variables gibi ad hoc pattern'lerden kaçınmalıdır. Volumes, dedicated secret-management integrations, Docker secrets ve Kubernetes Secrets yaygın mekanizmalardır. Bunların hiçbiri tüm riski ortadan kaldırmaz; özellikle attacker workload içinde zaten code execution elde etmişse. Ancak yine de credential'ları kalıcı olarak image içinde depolamaya veya inspection tooling aracılığıyla gelişigüzel şekilde açığa çıkarmaya kıyasla daha iyi seçeneklerdir.

Basit bir Docker Compose style secret declaration şu şekilde görünür:
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
Kubernetes'te Secret nesneleri, projected volume'lar, service-account token'ları ve cloud workload identity'leri daha geniş ve güçlü bir model oluşturur; ancak host mount'ları, geniş RBAC yetkileri veya zayıf Pod tasarımı nedeniyle kazara exposure yaşanması için daha fazla fırsat da yaratırlar.

## Kötüye Kullanım

Bir hedefi incelerken amaç, secret'ların image içine gömülüp gömülmediğini, katmanlara leak edilip edilmediğini veya öngörülebilir runtime konumlarına mount edilip edilmediğini keşfetmektir:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Bu komutlar üç farklı sorunu birbirinden ayırmaya yardımcı olur: application configuration leak'leri, image-layer leak'leri ve runtime tarafından enjekte edilen secret dosyaları. Bir secret `/run/secrets` altında, projected volume içinde veya bir cloud identity token path'inde görünüyorsa sonraki adım, bunun yalnızca mevcut workload'a mı yoksa çok daha geniş bir control plane'e mi erişim sağladığını anlamaktır.

### Full Example: Embedded Secret In Image Filesystem

Bir build pipeline `.env` dosyalarını veya kimlik bilgilerini final image'a kopyaladıysa, post-exploitation basitleşir:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Etki uygulamaya bağlıdır; ancak gömülü imzalama anahtarları, JWT secrets veya cloud credentials, container compromise durumunu kolayca API compromise, lateral movement ya da trusted application token'larının forgery'sine dönüştürebilir.

### Full Example: Build-Time Secret Leak Check

Endişe, image history'nin secret içeren bir layer'ı yakalamış olmasıysa:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Bu tür bir inceleme yararlıdır; çünkü bir secret, son dosya sistemi görünümünden silinmiş olsa bile daha önceki bir katmanda veya build metadata içinde kalmış olabilir.

## Kontroller

Bu kontroller, image ve secret-handling pipeline'ının runtime öncesinde attack surface'i artırmış olma ihtimalini belirlemeyi amaçlar.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Burada ilginç olanlar:

- Şüpheli bir build geçmişi; kopyalanmış kimlik bilgilerini, SSH materyalini veya güvenli olmayan build adımlarını ortaya çıkarabilir.
- Projected volume yollarındaki secrets, yalnızca yerel uygulama erişimine değil, cluster veya cloud erişimine de yol açabilir.
- Plaintext kimlik bilgileri içeren çok sayıdaki configuration dosyası, genellikle image veya deployment modelinin gereğinden fazla trust materyali taşıdığını gösterir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker / BuildKit | Güvenli build-time secret mount'larını destekler, ancak bunları otomatik olarak etkinleştirmez | Secret'lar `build` sırasında geçici olarak mount edilebilir; image signing ve scanning için açıkça belirlenmiş workflow seçimleri gerekir | secret'ları image içine kopyalamak, secret'ları `ARG` veya `ENV` ile geçirmek, provenance kontrollerini devre dışı bırakmak |
| Podman / Buildah | OCI-native build'leri ve secret-aware workflow'ları destekler | Güçlü build workflow'ları kullanılabilir, ancak operatörlerin bunları yine de bilinçli olarak seçmesi gerekir | secret'ları Containerfile'lara gömmek, geniş build context'leri kullanmak, build sırasında izinleri geniş bind mount'lar kullanmak |
| Kubernetes | Native Secret nesneleri ve projected volume'lar | Runtime secret delivery birinci sınıf bir özelliktir, ancak exposure RBAC'ye, pod tasarımına ve host mount'larına bağlıdır | aşırı geniş Secret mount'ları, service-account token'larının kötüye kullanılması, kubelet tarafından yönetilen volume'lara `hostPath` erişimi |
| Registries | Zorunlu tutulmadığı sürece integrity isteğe bağlıdır | Public ve private registries; policy, signing ve admission kararlarına bağlıdır | unsigned image'ları serbestçe çekmek, zayıf admission control, yetersiz key management |

{{#include ../../../banners/hacktricks-training.md}}
