# Görüntü Güvenliği, İmzalama ve Gizli Bilgiler

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Konteyner güvenliği, iş yükü başlatılmadan önce başlar. Görüntü, üretime hangi ikili dosyaların, yorumlayıcıların, kütüphanelerin, başlatma betiklerinin ve gömülü yapılandırmanın ulaşacağını belirler. Görüntü arka kapılı (backdoored), güncelliğini yitirmiş (stale) veya içine gizli veriler gömülmüş şekilde oluşturulmuşsa, sonraki çalışma zamanı sertleştirmesi (runtime hardening) zaten kompromize olmuş bir artefakt üzerinde çalışıyor olur.

Bu yüzden görüntü kaynağı (provenance), zafiyet taraması (vulnerability scanning), imza doğrulama (signature verification) ve gizli bilgi yönetimi (secret handling) namespaces ve seccomp ile aynı tartışmanın parçası olmalıdır. Bunlar yaşam döngüsünün farklı bir aşamasını korurlar, ancak burada yaşanan hatalar genellikle çalışma zamanının daha sonra sınırlamak zorunda kaldığı saldırı yüzeyini belirler.

## Görüntü Kayıtları ve Güven

Görüntüler Docker Hub gibi herkese açık kayıt depolarından veya bir organizasyon tarafından işletilen özel kayıt depolarından gelebilir. Güvenlik sorunu yalnızca görüntünün nerede barındırıldığı değil, ekibin kökeni (provenance) ve bütünlüğü teyit edip edemeyeceğidir. İmzalanmamış veya zayıf takip edilen görüntüleri halka açık kaynaklardan çekmek, kötü amaçlı veya değiştirilmiş içeriğin üretime girmesi riskini artırır. Dahili olarak barındırılan kayıt depolarının bile net sahiplik, inceleme ve güven politikalarına ihtiyacı vardır.

Docker Content Trust tarihsel olarak Notary ve TUF kavramlarını kullanarak imzalanmış görüntüleri zorunlu kıldı. Ekosistem zaman içinde evrildi, ancak kalıcı ders şu: görüntü kimliği ve bütünlüğü varsayılmamalı, doğrulanabilir olmalıdır.

Örnek tarihsel Docker Content Trust iş akışı:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Örneğin amacı, her ekibin hâlâ aynı araçları kullanması gerektiğini söylemek değil; imzalama ve anahtar yönetiminin soyut bir teori değil, operasyonel görevler olduğudur.

## Güvenlik Açığı Taraması

İmaj taraması iki farklı soruyu yanıtlamaya yardımcı olur. Birincisi, imaj bilinen güvenlik açığı bulunan paketler veya kütüphaneler içeriyor mu? İkincisi, imaj saldırı yüzeyini genişleten gereksiz yazılımlar barındırıyor mu? Hata ayıklama araçları, shell'ler, yorumlayıcılar ve güncelliğini yitirmiş paketlerle dolu bir imaj hem sömürülmesi daha kolaydır hem de üzerinde düşünülmesi daha zordur.

Sık kullanılan tarayıcı örnekleri şunlardır:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Bu araçlardan elde edilen sonuçlar dikkatle yorumlanmalıdır. Kullanılmayan bir paketteki bir zafiyet, açığa çıkmış bir RCE yoluyla aynı risk seviyesinde değildir; ancak her ikisi de sertleştirme kararları açısından önemlidir.

## Derleme Zamanı Sırları

Konteyner derleme pipeline'larındaki en eski hatalardan biri, sırları doğrudan imaja gömmek veya daha sonra `docker inspect`, build logları veya kurtarılan katmanlar aracılığıyla görünür hale gelen ortam değişkenleriyle aktarmaktır. Derleme zamanındaki sırlar, imajın dosya sistemine kopyalanmak yerine derleme sırasında geçici olarak monte edilmelidir.

BuildKit bu modeli, özel derleme-zamanı sır yönetimine izin vererek geliştirdi. Bir sır katmana yazılmak yerine, derleme adımı onu geçici olarak tüketebilir:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Bu önemlidir çünkü imaj katmanları kalıcı nesnelerdir. Bir gizli bilgi commit edilmiş bir katmana girdiğinde, daha sonra başka bir katmanda dosyayı silmek imaj geçmişindeki asıl ifşayı gerçekten ortadan kaldırmaz.

## Çalışma Zamanı Sırları

Çalışan bir iş yükünün ihtiyaç duyduğu gizli bilgiler, mümkün olduğunda basit ortam değişkenleri gibi ad hoc yaklaşımlardan kaçınmalıdır. Volumes, özel gizli yönetimi entegrasyonları, Docker secrets ve Kubernetes Secrets yaygın mekanizmalardır. Hiçbiri tüm riski ortadan kaldırmaz — özellikle saldırgan zaten iş yükünde kod çalıştırma yetkisine sahipse — ancak yine de kimlik bilgilerini kalıcı olarak imajda saklamaya veya onları inceleme araçları aracılığıyla rastgele ortaya çıkarmaya tercih edilir.

Basit bir Docker Compose tarzı secret bildirimi şöyle görünür:
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
Kubernetes'te, Secret objects, projected volumes, service-account tokens ve cloud workload identities daha geniş ve daha güçlü bir model oluşturur, ancak host mounts, broad RBAC veya zayıf Pod tasarımı yoluyla kazara maruz kalma için daha fazla fırsat da yaratırlar.

## Kötüye Kullanım

Hedefi incelerken amaç, secrets'in image'a gömülüp gömülmediğini, layers içine leaked olup olmadığına veya öngörülebilir runtime lokasyonlarına mounted edilip edilmediğine karar vermektir:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Bu komutlar üç farklı sorunu ayırt etmeye yardımcı olur: uygulama yapılandırması leaks, image-layer leaks ve runtime-injected secret dosyaları. Eğer bir secret `/run/secrets`, bir projected volume veya bir cloud identity token path altında görünüyorsa, sonraki adım bunun yalnızca mevcut iş yüküne mi yoksa çok daha geniş bir control plane'e mi erişim sağladığını anlamaktır.

### Tam Örnek: Image Filesystem İçine Gömülü Secret

Eğer bir build pipeline `.env` dosyalarını veya kimlik bilgilerini son image'a kopyaladıysa, post-exploitation basit hale gelir:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Etki uygulamaya bağlıdır; ancak gömülü signing keys, JWT secrets veya cloud credentials, container compromise'ını kolayca API compromise, lateral movement veya trusted application tokens'ın forgery'sine dönüştürebilir.

### Full Example: Build-Time Secret Leakage Check

Eğer endişe image history'nin secret-bearing layer yakaladığı yönündeyse:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Bu tür bir inceleme faydalıdır çünkü bir secret, nihai filesystem görünümünden silinmiş olabilir, ancak önceki bir layer'da veya build metadata içinde hâlâ kalmış olabilir.

## Checks

Bu kontroller, image ve secret-handling pipeline'ın runtime öncesinde attack surface'ı artırmış olma olasılığını belirlemeye yöneliktir.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- Şüpheli bir build geçmişi, kopyalanmış kimlik bilgilerini, SSH materyallerini veya güvensiz build adımlarını ortaya çıkarabilir.
- Projected volume yolları altındaki Secrets, yalnızca yerel uygulama erişimi değil, cluster veya bulut erişimine de yol açabilir.
- Plaintext kimlik bilgileri içeren çok sayıda yapılandırma dosyası genellikle image veya deployment modelinin gerektiğinden fazla güven malzemesi taşıdığını gösterir.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Güvenli build-zamanı secret mountlarını destekler, ancak otomatik olarak yapılmaz | Secrets `build` sırasında geçici olarak mount edilebilir; image imzalama ve tarama için açık workflow seçimleri gerekir | secrets'i image içine kopyalama, secrets'i `ARG` veya `ENV` ile geçirme, provenance kontrollerini devre dışı bırakma |
| Podman / Buildah | OCI-native build'ları ve secret-aware iş akışlarını destekler | Güçlü build iş akışları mevcut, ancak operatörler bunları kasıtlı olarak seçmelidir | secrets'i Containerfile'lara gömme, geniş build context'leri, build sırasında gevşek bind mount'lar |
| Kubernetes | Native Secret objeleri ve projected volumes | Runtime secret teslimatı birinci sınıftır, ancak maruziyet RBAC, pod tasarımı ve host mount'larına bağlıdır | aşırı geniş Secret mount'ları, service-account token kötü kullanımı, kubelet-managed volümlerine `hostPath` erişimi |
| Registries | Bütünlük, uygulanmadıkça isteğe bağlıdır | Hem public hem private registries politika, imzalama ve admission kararlarına bağlıdır | imzasız image'ları serbestçe çekme, zayıf admission kontrolü, kötü anahtar yönetimi |
