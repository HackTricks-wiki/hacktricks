# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

UTS namespace, process tarafından görülen **hostname** ve **NIS domain name** değerlerini izole eder. İlk bakışta bu, mount, PID veya user namespace'leriyle karşılaştırıldığında önemsiz görünebilir; ancak bir container'ın kendi host'u gibi görünmesini sağlayan unsurlardan biridir. Namespace içinde workload, makine genelinde global olmak yerine bu namespace'e yerel olan bir hostname'i görebilir ve bazen değiştirebilir.

Tek başına bu genellikle bir breakout senaryosunun merkezinde yer almaz. Ancak host UTS namespace'i paylaşıldığında, yeterli ayrıcalıklara sahip bir process host identity ile ilgili ayarları etkileyebilir; bu durum operasyonel açıdan ve zaman zaman güvenlik açısından önem taşıyabilir.

## Lab

Şu komutla bir UTS namespace oluşturabilirsiniz:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Hostname değişikliği yalnızca o namespace içinde yerel kalır ve host'un global hostname değerini değiştirmez. Bu, isolation özelliğinin basit ancak etkili bir gösterimidir.

## Runtime Kullanımı

Normal container'lar izole bir UTS namespace alır. Docker ve Podman, `--uts=host` aracılığıyla host UTS namespace'ine katılabilir; benzer host paylaşım kalıpları diğer runtime'larda ve orchestration sistemlerinde de görülebilir. Ancak çoğu zaman private UTS isolation, normal container kurulumunun bir parçasıdır ve operatörün çok az ilgilenmesini gerektirir.

## Güvenlik Etkisi

UTS namespace genellikle paylaşılması en tehlikeli namespace olmasa da container sınırının bütünlüğüne katkıda bulunur. Host UTS namespace'i açığa çıkarılmışsa ve process gerekli ayrıcalıklara sahipse host'un hostname ile ilgili bilgilerini değiştirebilir. Bu durum monitoring, logging, operasyonel varsayımları veya host identity verilerine dayanarak trust kararları veren script'leri etkileyebilir.

## Kötüye Kullanım

Host UTS namespace'i paylaşılmışsa pratik soru, process'in host identity ayarlarını yalnızca okuyup okuyamadığı değil, bunları değiştirip değiştiremeyeceğidir:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Container gerekli ayrıcalığa da sahipse, hostname'in değiştirilebilip değiştirilemeyeceğini test edin:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Bu, tam bir escape yerine öncelikle bir bütünlük ve operasyonel etki sorunudur; ancak container'ın host genelindeki bir özelliği doğrudan etkileyebildiğini yine de gösterir.

Etki:

- host kimliği üzerinde tampering
- hostname'e güvenen loglar, monitoring veya automation süreçlerinde karışıklık
- diğer zayıflıklarla birleştirilmediği sürece genellikle tek başına tam bir escape değildir

Docker-style ortamlarda, host tarafında kullanılabilecek yararlı bir detection pattern şöyledir:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host` gösteren container'lar host UTS namespace'ini paylaşır ve `sethostname()` veya `setdomainname()` çağırmalarına izin veren capability'lere de sahiplerse daha dikkatli incelenmelidir.

## Checks

Bu komutlar, workload'un kendine ait bir hostname görünümüne sahip olup olmadığını veya host UTS namespace'ini paylaşıp paylaşmadığını görmek için yeterlidir.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
What is interesting here:

- Eşleşen namespace identifiers, bir host process ile birlikte host UTS paylaşımına işaret edebilir.
- hostname'i değiştirmek container'ın kendisinden fazlasını etkiliyorsa workload, host identity üzerinde olması gerekenden daha fazla etkiye sahiptir.
- Bu genellikle PID, mount veya user namespace sorunlarına kıyasla daha düşük öncelikli bir bulgudur; ancak process'in gerçekte ne kadar izole olduğunu yine de doğrular.

Çoğu ortamda UTS namespace, destekleyici bir isolation katmanı olarak düşünülmelidir. Bir breakout sırasında nadiren ilk incelenen şeydir; ancak container görünümünün genel tutarlılığının ve güvenliğinin yine de bir parçasıdır.

{{#include ../../../../../banners/hacktricks-training.md}}
