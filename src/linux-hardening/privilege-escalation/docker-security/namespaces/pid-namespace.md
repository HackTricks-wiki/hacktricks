# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

PID (Süreç Tanımlayıcısı) namespace, Linux çekirdeğinde bir özellik olup süreç izolasyonu sağlar; bir grup sürecin kendi benzersiz PID setine sahip olmasına izin vererek diğer namespace'lerdeki PID'lerden ayrı tutar. Bu, süreç izolasyonunun güvenlik ve kaynak yönetimi için kritik olduğu konteynerleştirme (containerization) durumlarında özellikle kullanışlıdır.

Yeni bir PID namespace oluşturulduğunda, o namespace'deki ilk sürece PID 1 atanır. Bu süreç yeni namespace'in "init" süreci olur ve namespace içindeki diğer süreçleri yönetmekten sorumludur. Namespace içinde oluşturulan her sonraki süreç, o namespace içinde benzersiz bir PID'e sahip olur ve bu PID'ler diğer namespace'lerdeki PID'lerden bağımsızdır.

Bir PID namespace içindeki bir sürecin bakış açısından, yalnızca aynı namespace içindeki diğer süreçleri görebilir. Diğer namespace'lerdeki süreçlerin farkında değildir ve onlarla geleneksel süreç yönetim araçlarıyla (ör. `kill`, `wait`, vb.) etkileşime giremez. Bu, süreçlerin birbirine müdahale etmesini önlemeye yardımcı olan bir izolasyon düzeyi sağlar.

### Nasıl çalışır:

1. Yeni bir süreç oluşturulduğunda (ör. `clone()` system call kullanılarak), süreç yeni veya mevcut bir PID namespace'e atanabilir. **Yeni bir namespace oluşturulursa, süreç o namespace'in "init" süreci olur.**
2. **Kernel**, yeni namespace içindeki PID'lerle üst namespace'teki karşılık gelen PID'ler arasında **bir eşleme** tutar (yani yeni namespace'in oluşturulduğu namespace). Bu eşleme, farklı namespace'lerdeki süreçler arasında sinyal gönderimi gibi durumlarda PID'leri gerektiğinde **çekirdeğin çevirmesine** olanak tanır.
3. **Bir PID namespace içindeki süreçler yalnızca aynı namespace içindeki diğer süreçleri görebilir ve onlarla etkileşime girebilir.** Diğer namespace'lerdeki süreçlerin farkında değillerdir ve PID'leri kendi namespace'leri içinde benzersizdir.
4. Bir **PID namespace yok edildiğinde** (ör. namespace'in "init" süreci sona erdiğinde), **o namespace içindeki tüm süreçler sonlandırılır.** Bu, namespace ile ilişkilendirilmiş tüm kaynakların düzgün şekilde temizlenmesini sağlar.

## Lab:

### Farklı Namespace'ler Oluşturma

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

`--mount-proc` parametresini kullanarak yeni bir `/proc` dosya sistemi örneğini mount ettiğinizde, yeni mount namespace'inin o namespace'e özgü süreç bilgilerine ilişkin **doğru ve izole bir görünüm** sağlamasını temin edersiniz.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Process'inizin hangi namespace'te olduğunu kontrol edin
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tüm PID namespaces'lerini bulun
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
İlk (varsayılan) PID namespace'inden root kullanıcısı tüm süreçleri görebilir, hatta yeni PID namespace'lerindeki süreçleri bile; bu yüzden tüm PID namespace'lerini görebiliyoruz.

### PID namespace içine girme
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **başka bir süreç PID namespace'ine sadece root iseniz girebilirsiniz**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Son İstismar Notları

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 allowed attackers that control container images or `runc exec` workloads to replace the container-side `/dev/null` just before the runtime masked sensitive procfs entries. When the race succeeds, `/dev/null` can be turned into a symlink pointing at any host path (for example `/proc/sys/kernel/core_pattern`), so the new container PID namespace suddenly inherits read/write access to host-global procfs knobs even though it never left its own namespace. Once `core_pattern` or `/proc/sysrq-trigger` is writable, generating a coredump or triggering SysRq yields code execution or denial of service in the host PID namespace.

Pratik iş akışı:

1. İstediğiniz host yoluna işaret eden bir linkle `/dev/null`'ü değiştiren bir rootfs'e sahip bir OCI bundle oluşturun (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Düzeltme uygulanmadan önce container'ı başlatın, böylece runc host procfs hedefini link'in üzerine bind-mount eder.
3. Container namespace'i içinde, artık açığa çıkan procfs dosyasına yazın (ör. `core_pattern`'i bir reverse shell helper'a yönlendirin) ve host kernelinin helper'ınızı PID 1 bağlamında çalıştırmaya zorlamak için herhangi bir süreci çökertin.

You can quickly audit whether a bundle is masking the right files before starting it:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Eğer runtime, beklediğiniz bir masking girdisine sahip değilse (veya `/dev/null` kaybolduğu için onu atlıyorsa), container'ı potansiyel host PID görünürlüğüne sahip olarak değerlendirin.

### Namespace enjeksiyonu `insject` ile

NCC Group’ün `insject`'i, hedef programın geç bir aşamasına (varsayılan `main`) hook yapan ve `execve()` sonrasında bir dizi `setns()` çağrısı yapan bir LD_PRELOAD payload olarak yüklenir. Bu, host'tan (veya başka bir container'dan) kurbanın PID namespace'ine runtime başlatıldıktan *sonra* eklemenize izin verir; böylece container dosya sistemine ikili dosyalar kopyalamadan `/proc/<pid>` görünümünü korursunuz. `insject` PID namespace'e katılmayı fork edene kadar erteleyebildiği için, bir thread'i host namespace'te (CAP_SYS_PTRACE ile) tutarken diğer bir thread'in hedef PID namespace'te çalışmasını sağlayabilir; bu da güçlü debugging veya offensive primitives oluşturur.

Örnek kullanım:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
namespace injection'ı kötüye kullanırken veya savunurken dikkat edilmesi gerekenler:

- `-S/--strict` kullanın; böylece threads zaten mevcutsa veya namespace join'leri başarısız olursa `insject`'in abort etmesini zorlayın; aksi takdirde host ve container PID alanları arasında kısmen taşınmış threads bırakabilirsiniz.
- writable host file descriptors tutan araçları asla attach etmeyin, eğer mount namespace'e de join etmezseniz — aksi halde PID namespace içindeki herhangi bir process helper'ınızı ptrace edip bu descriptors'ları yeniden kullanarak host kaynaklarına müdahale edebilir.

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
