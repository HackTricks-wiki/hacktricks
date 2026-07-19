# Image Security, Signing, And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Image Registries And Trust

Container security, workload başlatılmadan önce başlar. Image; hangi binary'lerin, interpreter'ların, library'lerin, startup script'lerinin ve embedded configuration'ın production ortamına ulaşacağını belirler. Image backdoored veya stale ise ya da içine secret'lar gömülerek build edilmişse, sonrasında uygulanan runtime hardening zaten compromise edilmiş bir artifact üzerinde çalışıyordur.

Bu nedenle image provenance, vulnerability scanning, signature verification ve secret handling; namespaces ve seccomp ile aynı kapsamda ele alınmalıdır. Bunlar lifecycle'ın farklı bir aşamasını korur, ancak buradaki hatalar çoğu zaman runtime'ın daha sonra sınırlamak zorunda kalacağı attack surface'i belirler.

## Image Registries And Trust

Image'lar Docker Hub gibi public registry'lerden veya bir kuruluş tarafından işletilen private registry'lerden gelebilir. Güvenlik sorusu yalnızca image'ın nerede bulunduğu değil, ekibin provenance ve integrity'yi doğrulayıp doğrulayamayacağıdır. Public kaynaklardan unsigned veya yetersiz şekilde takip edilen image'ları pull etmek, malicious veya tampered content'in production'a girme riskini artırır. Dahili olarak barındırılan registry'lerin bile açık bir ownership, review ve trust policy'sine ihtiyacı vardır.

Docker Content Trust, geçmişte signed image'lar gerektirmek için Notary ve TUF kavramlarını kullanıyordu. Ekosistemin kendisi zaman içinde gelişti, ancak kalıcı ders hâlâ geçerlidir: image identity ve integrity varsayılmak yerine doğrulanabilir olmalıdır.

Historical Docker Content Trust workflow örneği:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Örneğin amacı, her ekibin hâlâ aynı tooling'i kullanması gerektiğini göstermek değil; signing ve key management işlemlerinin soyut bir teori değil, operasyonel görevler olduğunu vurgulamaktır.

## Vulnerability Scanning

Image scanning iki farklı soruyu yanıtlamaya yardımcı olur. İlk olarak, image bilinen güvenlik açığı bulunan package veya library'ler içeriyor mu? İkinci olarak, image attack surface'i genişleten gereksiz software taşıyor mu? Debugging tool'ları, shell'ler, interpreter'lar ve güncelliğini yitirmiş package'lerle dolu bir image hem exploit edilmesi daha kolaydır hem de değerlendirilmesi daha zordur.

Yaygın olarak kullanılan scanner örnekleri şunlardır:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Bu araçlardan elde edilen sonuçlar dikkatle yorumlanmalıdır. Kullanılmayan bir package içindeki vulnerability, exposed bir RCE path ile aynı risk düzeyine sahip değildir; ancak her ikisi de hardening kararları açısından hâlâ önemlidir.

## Build-Time Secrets

Container build pipeline'larındaki en eski hatalardan biri, secret'ları doğrudan image içine gömmek veya daha sonra `docker inspect`, build log'ları ya da kurtarılmış layer'lar üzerinden görünür hâle gelen environment variable'lar aracılığıyla aktarmaktır. Build-time secret'lar, image filesystem'ına kopyalanmak yerine build sırasında geçici olarak mount edilmelidir.

BuildKit, özel build-time secret yönetimine izin vererek bu modeli geliştirdi. Bir secret'ı bir layer'a yazmak yerine build adımı secret'ı geçici olarak kullanabilir:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Bu önemlidir, çünkü image katmanları kalıcı artifact'lerdir. Bir secret commit edilmiş bir katmana girdikten sonra, dosyanın daha sonraki bir katmanda silinmesi image geçmişindeki ilk disclosure'ı gerçekten ortadan kaldırmaz.

## Runtime Secret'ları

Çalışan bir workload tarafından ihtiyaç duyulan secret'lar da mümkün olduğunda plain environment variable gibi gelişigüzel yöntemlerden kaçınmalıdır. Volumes, özel secret-management integrations, Docker secrets ve Kubernetes Secrets yaygın mekanizmalardır. Bunların hiçbiri tüm riski ortadan kaldırmaz; özellikle attacker workload içinde zaten code execution elde etmişse. Ancak yine de credential'ları kalıcı olarak image içinde depolamaya veya inspection tooling aracılığıyla dikkatsizce açığa çıkarmaya kıyasla tercih edilirler.

Basit bir Docker Compose tarzı secret bildirimi şu şekilde görünür:
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
Kubernetes'te Secret objects, projected volumes, service-account tokens ve cloud workload identities daha geniş ve güçlü bir model oluşturur; ancak host mounts, geniş RBAC veya zayıf Pod tasarımı nedeniyle yanlışlıkla exposure yaşanması için daha fazla fırsat da yaratır.

## Kötüye Kullanım

Bir target incelenirken amaç, secrets'ların image içine gömülüp gömülmediğini, layer'lara leak olup olmadığını veya öngörülebilir runtime konumlarına mount edilip edilmediğini keşfetmektir:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Bu komutlar üç farklı sorunu ayırt etmeye yardımcı olur: application configuration leak'leri, image-layer leak'leri ve runtime tarafından enjekte edilen secret dosyaları. Bir secret `/run/secrets` altında, projected volume içinde veya bir cloud identity token path'inde görünüyorsa sonraki adım, bunun yalnızca mevcut workload'a mı yoksa çok daha geniş bir control plane'e mi erişim sağladığını anlamaktır.

### Full Example: Embedded Secret In Image Filesystem

Bir build pipeline `.env` dosyalarını veya credential'ları final image'a kopyaladıysa post-exploitation basitleşir:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Etki uygulamaya bağlıdır; ancak gömülü signing key'ler, JWT secrets veya cloud credentials, container compromise durumunu kolayca API compromise, lateral movement ya da trusted application token'larının forgery'sine dönüştürebilir.

### Build-Time Secret Leakage Check: Tam Örnek

Endişe, image history'nin secret içeren bir layer'ı yakalamış olmasıysa:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Bu tür bir inceleme faydalıdır; çünkü bir secret, final filesystem görünümünden silinmiş olsa bile önceki bir layer'da veya build metadata içinde kalmış olabilir.

## Kontroller

Bu kontroller, image ve secret-handling pipeline'ının runtime öncesinde attack surface'i artırmış olma olasılığını belirlemeyi amaçlar.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Burada ilginç olan nedir:

- Şüpheli bir build geçmişi, kopyalanmış kimlik bilgilerini, SSH materyalini veya güvenli olmayan build adımlarını ortaya çıkarabilir.
- Projected volume path'leri altındaki sırlar yalnızca yerel uygulama erişimine değil, cluster veya cloud erişimine de yol açabilir.
- Çok sayıda plaintext kimlik bilgisi içeren configuration dosyası, genellikle image'ın veya deployment modelinin gerekenden daha fazla trust materyali taşıdığını gösterir.

## Runtime Defaults

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker / BuildKit | Güvenli build-time secret mount'larını destekler, ancak bunlar otomatik olarak etkin değildir | Secret'lar `build` sırasında geçici olarak mount edilebilir; image signing ve scanning için açıkça workflow seçenekleri belirlenmelidir | secret'ları image'a kopyalamak, secret'ları `ARG` veya `ENV` ile geçirmek, provenance kontrollerini devre dışı bırakmak |
| Podman / Buildah | OCI-native build'leri ve secret-aware workflow'ları destekler | Güçlü build workflow'ları mevcuttur, ancak operatörlerin bunları yine de bilinçli olarak seçmesi gerekir | secret'ları Containerfile'lara gömmek, geniş build context'leri, build sırasında izinleri geniş bind mount'lar |
| Kubernetes | Native Secret object'leri ve projected volume'lar | Runtime secret teslimi first-class'tır, ancak exposure RBAC, pod tasarımı ve host mount'larına bağlıdır | aşırı geniş Secret mount'ları, service-account token misuse, kubelet tarafından yönetilen volume'lara `hostPath` erişimi |
| Registries | Enforce edilmediği sürece integrity isteğe bağlıdır | Hem public hem de private registry'ler policy, signing ve admission kararlarına bağlıdır | unsigned image'ları serbestçe çekmek, zayıf admission control, yetersiz key management |
{{#include ../../../banners/hacktricks-training.md}}
