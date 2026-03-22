# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

UTS namespace, işlem tarafından görülen **hostname** ve **NIS domain name**'i izole eder. İlk bakışta bu, mount, PID veya user namespaces ile karşılaştırıldığında önemsiz görünebilir, ancak bir container'ın kendi host'uymuş gibi görünmesini sağlayan unsurlardan biridir. Namespace içinde, workload o namespace'e yerel olan ve makineye global olmayan bir hostname'i görebilir ve bazen değiştirebilir.

Tek başına, bu genellikle bir breakout hikayesinin merkezi olmaz. Ancak host UTS namespace paylaşıldığında, yeterli ayrıcalığa sahip bir süreç host kimliğiyle ilgili ayarları etkileyebilir; bu operasyonel olarak ve zaman zaman güvenlik açısından önem taşıyabilir.

## Lab

Aşağıdaki komutla bir UTS namespace oluşturabilirsiniz:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Hostname değişikliği o namespace'e yerel kalır ve ana makinenin genel adını değiştirmez. Bu, izolasyon özelliğinin basit ama etkili bir gösterimidir.

## Çalışma Zamanı Kullanımı

Normal konteynerler izole bir UTS namespace'i alır. Docker ve Podman `--uts=host` ile host UTS namespace'ine katılabilir ve benzer host-paylaşım desenleri diğer runtime'larda ve orkestrasyon sistemlerinde de ortaya çıkabilir. Ancak çoğu zaman, özel UTS izolasyonu normal konteyner kurulumunun bir parçasıdır ve operatörün çok fazla ilgilenmesini gerektirmez.

## Güvenlik Etkisi

UTS namespace genellikle paylaşılması en tehlikeli olan olmayabilir, ancak yine de konteyner sınırının bütünlüğüne katkıda bulunur. Eğer host UTS namespace'i açığa çıkarsa ve süreç gerekli ayrıcalıklara sahipse, ana makinenin hostname ile ilgili bilgilerini değiştirebilir. Bu, izleme, loglama, işletme varsayımlarını veya ana makine kimlik verilerine dayanarak güven kararları veren betikleri etkileyebilir.

## Kötüye Kullanım

Eğer host UTS namespace'i paylaşılıyorsa, pratik soru sürecin bunları sadece okumak yerine ana makine kimlik ayarlarını değiştirip değiştiremeyeceğidir:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Eğer container ayrıca gerekli privilege'a sahipse, hostname'in değiştirilebildiğini test edin:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Bu esasen tam bir escape'ten ziyade bütünlük ve operasyonel etkiyle ilgili bir sorundur; yine de container'ın host-genel bir özelliği doğrudan etkileyebileceğini gösterir.

Etkiler:

- host kimliği tahrifi
- hostname'e güvenen logların, izleme veya otomasyonun yanıltılması
- genellikle tek başına tam bir escape değildir; başka zayıflıklarla birleşmedikçe

Docker tarzı ortamlarda, host tarafında işe yarayan bir tespit deseni şudur:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` gösteren Containers, host UTS namespace'ini paylaşıyor ve eğer `sethostname()` veya `setdomainname()` çağırmalarına izin veren yeteneklere sahipse, daha dikkatli incelenmelidir.

## Checks

Bu komutlar, workload'un kendi hostname görünümüne sahip olup olmadığını ya da host UTS namespace'ini paylaşıp paylaşmadığını görmek için yeterlidir.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Burada ilginç olanlar:

- Namespace identifiers ile bir host process'in eşleşmesi host UTS sharing göstergesi olabilir.
- Hostname'i değiştirmek container'ın kendisinden fazlasını etkiliyorsa, workload host identity üzerinde olması gerekenden daha fazla etkiye sahiptir.
- Bu genellikle PID, mount veya user namespace sorunlarına göre daha düşük öncelikli bir bulgudur, ancak yine de process'in gerçekten ne kadar izole olduğunu doğrular.

Çoğu ortamda UTS namespace, destekleyici bir izolasyon katmanı olarak düşünülmelidir. Bir breakout'ta nadiren ilk takip ettiğiniz şeydir, ancak yine de container view'in genel tutarlılığı ve güvenliğinin bir parçasıdır.
{{#include ../../../../../banners/hacktricks-training.md}}
