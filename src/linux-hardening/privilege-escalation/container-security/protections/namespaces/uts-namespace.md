# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

UTS namespace, işlemin gördüğü **ana makine adını** ve **NIS alan adını** izole eder. İlk bakışta mount, PID veya user namespace'lerine kıyasla önemsiz görünebilir; ancak bu, bir container'ın kendi ana makinesiymiş gibi görünmesini sağlayan unsurlardan biridir. Namespace içinde iş yükü, makine genelinde geçerli olmayan, o namespace'e yerel bir ana makine adını görebilir ve bazen değiştirebilir.

Kendi başına bu genellikle bir breakout hikayesinin ana unsuru değildir. Ancak host UTS namespace paylaşıldığında, yeterli ayrıcalığa sahip bir süreç host kimliğiyle ilgili ayarları etkileyebilir; bu operasyonel açıdan ve zaman zaman güvenlik açısından önem taşıyabilir.

## Lab

Bir UTS namespace oluşturabilirsiniz:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Hostname değişikliği yalnızca o namespace içinde kalır ve host'un genel hostname'ini değiştirmez. Bu, izolasyon özelliğinin basit ama etkili bir örneğidir.

## Çalışma Zamanı Kullanımı

Normal container'lar izole bir UTS namespace'e sahiptir. Docker ve Podman `--uts=host` aracılığıyla host UTS namespace'ine katılabilir ve benzer host-paylaşım modelleri diğer runtime'larda ve orkestrasyon sistemlerinde de görülebilir. Ancak çoğu durumda, özel UTS izolasyonu normal container yapılandırmasının bir parçasıdır ve operatörün fazla dikkatini gerektirmez.

## Güvenlik Etkisi

UTS namespace paylaşılması genellikle en tehlikeli olan olmasa da, yine de container sınırının bütünlüğüne katkıda bulunur. Eğer host UTS namespace'i açığa çıkarsa ve süreç gerekli ayrıcalıklara sahipse, host ile ilgili hostname bilgilerini değiştirebilir. Bu durum izleme, loglama, operasyonel varsayımlar veya host kimlik verilerine dayalı güven kararları veren script'leri etkileyebilir.

## Kötüye Kullanım

Host UTS namespace'i paylaşılıyorsa, pratik soru sürecin bunları sadece okumak yerine host kimlik ayarlarını değiştirebilme yeteneğidir:
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
Bu öncelikle tam bir escape'ten ziyade bir bütünlük ve operasyonel etki sorunudur, ancak container'ın doğrudan bir host-global özelliği etkileyebileceğini gösterir.

Etkiler:

- host kimlik tahrifatı
- hostname'e güvenen logları, monitoring'i veya otomasyonu yanıltmak
- genellikle tek başına tam bir escape değildir; diğer zayıflıklarla birleşmediği sürece

Docker-style ortamlarda, faydalı bir host-side tespit deseni şudur:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` gösteren konteynerler host UTS namespace'ini paylaşıyor ve eğer `sethostname()` veya `setdomainname()` çağırmalarına izin veren capabilities'e sahipseler daha dikkatli incelenmelidir.

## Kontroller

Bu komutlar, workload'un kendi hostname görünümüne sahip olup olmadığını veya host UTS namespace'ini paylaşıp paylaşmadığını görmek için yeterlidir.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Burada ilginç olanlar:

- Namespace tanımlayıcılarının bir host process ile eşleşmesi host UTS paylaşımına işaret edebilir.
- Hostname değişikliğinin container'ın kendisinden fazlasını etkilemesi durumunda, workload host kimliği üzerinde olması gerekenden daha fazla etkiye sahiptir.
- Bu genellikle PID, mount veya user namespace sorunlarına kıyasla daha düşük öncelikli bir bulgudur, fakat yine de process'in gerçekten ne kadar izole olduğunu doğrular.

Çoğu ortamda, UTS namespace en iyi destekleyici bir izolasyon katmanı olarak düşünülmelidir. Bir breakout sırasında nadiren peşine düştüğünüz ilk şeydir, ancak yine de container görünümünün genel tutarlılığının ve güvenliğinin bir parçasıdır.
