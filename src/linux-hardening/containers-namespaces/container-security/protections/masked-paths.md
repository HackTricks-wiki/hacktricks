# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths, özellikle kernel ile etkileşim kuran hassas dosya sistemi konumlarını üzerlerine bind-mount uygulayarak veya başka yollarla erişilemez hale getirerek container içinden gizleyen runtime korumalarıdır. Amaç, özellikle procfs içinde, normal uygulamaların ihtiyaç duymadığı arayüzlerle bir workload'un doğrudan etkileşime girmesini engellemektir.

Bu önemlidir çünkü birçok container escape ve host'u etkileyen teknik, `/proc` veya `/sys` altındaki özel dosyaları okumak ya da yazmakla başlar. Bu konumlar maskelenirse attacker, container içinde code execution elde ettikten sonra bile kernel control surface'in kullanılabilir bir bölümüne doğrudan erişimini kaybeder.

## Operation

Runtimes genellikle aşağıdaki gibi seçili paths'leri maskeler:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Kesin liste runtime'a ve host yapılandırmasına bağlıdır. Önemli nokta, host üzerinde hâlâ mevcut olsa bile path'in container açısından erişilemez hale gelmesi veya değiştirilmesidir.

## Lab

Docker tarafından sunulan masked-path yapılandırmasını inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
İş yükü içindeki gerçek mount davranışını inceleyin:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking ana isolation boundary'yi oluşturmaz, ancak yüksek değerli birkaç post-exploitation hedefini ortadan kaldırır. Masking olmadan, ele geçirilmiş bir container kernel durumunu inceleyebilir, hassas process veya keying bilgilerini okuyabilir ya da uygulamaya hiçbir zaman görünür olmaması gereken procfs/sysfs nesneleriyle etkileşime girebilir.

## Misconfigurations

Ana hata, kolaylık veya debugging amacıyla geniş path sınıflarının unmask edilmesidir. Podman'da bu, `--security-opt unmask=ALL` veya hedefli unmasking şeklinde görülebilir. Kubernetes'te aşırı geniş proc exposure, `procMount: Unmasked` aracılığıyla ortaya çıkabilir. Bir diğer ciddi sorun, host `/proc` veya `/sys` path'lerini bind mount üzerinden expose etmektir; bu, reduced container view fikrini tamamen bypass eder.

## Abuse

Masking zayıfsa veya mevcut değilse, doğrudan erişilebilen hassas procfs/sysfs path'lerini belirleyerek başlayın:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Sözde maskelenmiş bir path erişilebilirse, dikkatlice inceleyin:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Bu komutların ortaya çıkarabilecekleri:

- `/proc/timer_list`, host timer ve scheduler verilerini açığa çıkarabilir. Bu çoğunlukla bir reconnaissance primitive'idir; ancak container'ın normalde gizlenen kernel-facing bilgileri okuyabildiğini doğrular.
- `/proc/keys` çok daha hassastır. Host yapılandırmasına bağlı olarak kernel keyring subsystem'ini kullanan host servisleri arasındaki keyring girdilerini, key açıklamalarını ve ilişkileri açığa çıkarabilir.
- `/sys/firmware`, boot mode, firmware arayüzleri ve host fingerprinting için yararlı olan platform ayrıntılarının belirlenmesine yardımcı olur; ayrıca workload'un host-level state'i görüp görmediğinin anlaşılmasını sağlar.
- `/proc/config.gz`, çalışan kernel yapılandırmasını açığa çıkarabilir. Bu, public kernel exploit ön koşullarıyla eşleştirme yapmak veya belirli bir özelliğe neden erişilebildiğini anlamak için değerlidir.
- `/proc/sched_debug`, scheduler state'i açığa çıkarır ve çoğu zaman PID namespace'in ilgisiz process bilgilerini tamamen gizlemesi gerektiği yönündeki sezgisel beklentiyi boşa çıkarır.

İlginç sonuçlar arasında bu dosyalardan doğrudan okumalar yapılabilmesi, verilerin kısıtlanmış bir container görünümüne değil host'a ait olduğuna dair kanıtlar veya varsayılan olarak genellikle maskelenen diğer procfs/sysfs konumlarına erişim bulunur.

## Checks

Bu kontrollerin amacı, runtime'ın hangi yolları kasıtlı olarak gizlediğini ve mevcut workload'un hâlâ azaltılmış bir kernel-facing filesystem görüp görmediğini belirlemektir.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Burada ilginç olan nedir:

- Hardened runtime'larda uzun bir masked-path listesi normaldir.
- Hassas procfs girdilerinde masking bulunmaması daha yakından incelenmelidir.
- Hassas bir path erişilebilirse ve container'da ayrıca güçlü capabilities veya geniş mounts varsa, exposure daha önemlidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, varsayılan bir masked path listesi tanımlar | host proc/sys mounts'larını açığa çıkarma, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, manuel olarak unmask edilmediği sürece varsayılan masked paths uygular | `--security-opt unmask=ALL`, hedefli unmasking, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları proc exposure'ı zayıflatmadığı sürece temel runtime'ın masking davranışını kullanır | `procMount: Unmasked`, privileged workload pattern'leri, geniş host mounts |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Genellikle üzerine yazılmadığı sürece OCI/runtime masked paths uygular | doğrudan runtime config değişiklikleri, aynı Kubernetes zayıflatma yolları |

Masked paths genellikle varsayılan olarak mevcuttur. Temel operasyonel sorun runtime'da bulunmamaları değil, protection'ı geçersiz kılan kasıtlı unmasking veya host bind mounts kullanılmasıdır.

{{#include ../../../../banners/hacktricks-training.md}}
