# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

UTS namespace, process tarafından görülen **hostname** ve **NIS domain name** değerlerini izole eder. İlk bakışta bu, mount, PID veya user namespaces ile karşılaştırıldığında önemsiz görünebilir; ancak bir container'ın kendi host'u gibi görünmesini sağlayan unsurlardan biridir. Namespace içinde workload, makine genelinde geçerli olmak yerine yalnızca o namespace'e ait olan bir hostname'i görebilir ve bazen değiştirebilir.

Tek başına bu özellik genellikle bir breakout senaryosunun merkezinde yer almaz. Ancak host UTS namespace paylaşıldığında, yeterli ayrıcalıklara sahip bir process host kimliğiyle ilgili ayarları etkileyebilir; bu durum operasyonel açıdan, bazen de security açısından önemli olabilir.

## Laboratuvar

Şu komutla bir UTS namespace oluşturabilirsiniz:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Hostname değişikliği yalnızca bu namespace içinde geçerli olur ve host'un global hostname'ini değiştirmez. Bu, izolasyon özelliğinin basit ancak etkili bir gösterimidir.

## Runtime Kullanımı

Normal container'lar izole bir UTS namespace alır. Docker ve Podman, `--uts=host` aracılığıyla host UTS namespace'ine katılabilir; benzer host paylaşım modelleri diğer runtime'larda ve orchestration sistemlerinde de görülebilir. Ancak çoğu zaman private UTS isolation, normal container kurulumunun bir parçasıdır ve operatörün çok az ilgisini gerektirir.

## Security Etkisi

UTS namespace genellikle paylaşılması en tehlikeli namespace olmasa da container sınırının bütünlüğüne katkıda bulunur. Host UTS namespace'i açığa çıkarsa ve process gerekli privileges'a sahipse host hostname ile ilgili bilgileri değiştirebilir. Bu durum monitoring, logging, operasyonel varsayımlar veya host identity verilerine dayanarak trust kararları veren script'leri etkileyebilir.

## Kötüye Kullanım

Host UTS namespace'i paylaşılmışsa pratik soru, process'in yalnızca host identity ayarlarını okuyup okuyamadığı değil, bunları değiştirip değiştiremediğidir:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Container gerekli ayrıcalığa da sahipse, hostname'in değiştirilip değiştirilemeyeceğini test edin:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Bu, tam bir escape'ten ziyade öncelikle bir bütünlük ve operasyonel etki sorunudur; ancak container'ın host genelindeki bir özelliği doğrudan etkileyebildiğini yine de gösterir.

Impact:

- host kimliğinin değiştirilmesi
- hostname'e güvenen logların, monitoring sistemlerinin veya otomasyonun karışması
- başka zayıflıklarla birleştirilmediği sürece genellikle tek başına tam bir escape değildir

Docker tarzı ortamlarda, host tarafında kullanılabilecek yararlı bir detection pattern şudur:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` gösteren container'lar host UTS namespace'ini paylaşır ve `sethostname()` veya `setdomainname()` çağırmalarına izin veren capabilities'lere de sahiplerse daha dikkatli incelenmelidir.

## Kontroller

Bu komutlar, workload'un kendi hostname görünümüne sahip olup olmadığını veya host UTS namespace'ini paylaşıp paylaşmadığını görmek için yeterlidir.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Burada ilginç olanlar:

- Namespace identifier'larının bir host process'iyle eşleşmesi, host UTS paylaşımına işaret edebilir.
- Hostname'i değiştirmek yalnızca container'ın kendisini değil, daha geniş bir alanı etkiliyorsa workload'un host kimliği üzerinde olması gerekenden daha fazla etkisi vardır.
- Bu genellikle PID, mount veya user namespace sorunlarına kıyasla daha düşük öncelikli bir bulgudur; ancak process'in gerçekte ne kadar izole olduğunu yine de doğrular.

Çoğu ortamda UTS namespace, destekleyici bir isolation katmanı olarak düşünülmelidir. Bir breakout sırasında nadiren ilk incelenen konudur; ancak container görünümünün genel tutarlılığının ve güvenliğinin hâlâ bir parçasıdır.
{{#include ../../../../../banners/hacktricks-training.md}}
