# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths, özellikle hassas kernel'e yönelik dosya sistemi konumlarını, üzerlerine bind-mount yaparak veya başka yollarla erişilemez hâle getirerek container'dan gizleyen çalışma zamanı korumalarıdır. Amaç, özellikle procfs içinde, normal uygulamaların ihtiyaç duymadığı arayüzlerle bir workload'un doğrudan etkileşime girmesini önlemektir.

Bu önemlidir; çünkü birçok container escape ve host'u etkileyen teknik, `/proc` veya `/sys` altındaki özel dosyaları okumak ya da yazmakla başlar. Bu konumlar maskelenmişse, attacker container içinde code execution elde ettikten sonra bile kernel kontrol yüzeyinin kullanışlı bir bölümüne doğrudan erişimini kaybeder.

## Operation

Runtimes genellikle aşağıdaki gibi seçili yolları maskeler:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Kesin liste runtime'a ve host yapılandırmasına bağlıdır. Önemli olan, host üzerinde hâlâ mevcut olsa bile path'in container'ın bakış açısından erişilemez hâle gelmesi veya değiştirilmesidir.

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
## Güvenlik Etkisi

Maskeleme, ana isolation boundary'i oluşturmaz; ancak yüksek değerli post-exploitation hedeflerinin birkaçını ortadan kaldırır. Maskeleme olmadan, ele geçirilmiş bir container kernel durumunu inceleyebilir, hassas process veya keying bilgilerini okuyabilir ya da uygulamaya hiçbir zaman görünür olmaması gereken procfs/sysfs nesneleriyle etkileşime girebilir.

## Yanlış Yapılandırmalar

En yaygın hata, kolaylık veya debugging amacıyla geniş path sınıflarının unmask edilmesidir. Podman'da bu durum `--security-opt unmask=ALL` veya hedefli unmasking kullanımı şeklinde görülebilir. Kubernetes'te aşırı geniş proc erişimi `procMount: Unmasked` üzerinden ortaya çıkabilir. Bir diğer ciddi sorun ise host `/proc` veya `/sys` dizinlerinin bind mount aracılığıyla açığa çıkarılmasıdır; bu, reduced container view fikrini tamamen devre dışı bırakır.

## Abuse

Masking zayıfsa veya yoksa, doğrudan erişilebilen hassas procfs/sysfs path'lerini belirleyerek başlayın:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Sözde maskelenmiş bir yol erişilebilirse, dikkatlice inceleyin:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Bu komutlar neleri ortaya çıkarabilir:

- `/proc/timer_list`, host timer ve scheduler verilerini açığa çıkarabilir. Bu çoğunlukla bir reconnaissance primitive'dir; ancak container'ın normalde gizlenen kernel'e yönelik bilgileri okuyabildiğini doğrular.
- `/proc/keys` çok daha hassastır. Host yapılandırmasına bağlı olarak keyring girdilerini, key açıklamalarını ve kernel keyring subsystem'ini kullanan host servisleri arasındaki ilişkileri açığa çıkarabilir.
- `/sys/firmware`, host fingerprinting ve workload'un host-level state görüp görmediğini anlamak için yararlı olan boot mode, firmware interface'leri ve platform ayrıntılarını belirlemeye yardımcı olur.
- `/proc/config.gz`, çalışan kernel yapılandırmasını açığa çıkarabilir. Bu, public kernel exploit ön koşullarını eşleştirmek veya belirli bir feature'ın neden erişilebilir olduğunu anlamak için değerlidir.
- `/proc/sched_debug`, scheduler state'i açığa çıkarır ve çoğu zaman PID namespace'in ilgisiz process bilgilerini tamamen gizlemesi gerektiğine dair sezgisel beklentiyi geçersiz kılar.

İlginç sonuçlar arasında bu dosyalardan doğrudan okuma yapılabilmesi, verilerin kısıtlanmış bir container görünümüne değil host'a ait olduğuna dair kanıtlar veya varsayılan olarak genellikle maskelenen diğer procfs/sysfs konumlarına erişim bulunur.

## Kontroller

Bu kontrollerin amacı, runtime'ın hangi path'leri kasıtlı olarak gizlediğini ve mevcut workload'un hâlâ kernel'e yönelik azaltılmış bir filesystem görüp görmediğini belirlemektir.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Burada ilgi çekici olanlar:

- Uzun bir maskelenmiş yol listesi, hardened runtime'larda normaldir.
- Hassas procfs girdilerinde maskelemenin eksik olması daha yakından incelenmelidir.
- Hassas bir yola erişilebiliyor ve container aynı zamanda güçlü yetkilere veya geniş mount'lara sahipse, bu maruziyet daha önemlidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, varsayılan bir maskelenmiş yol listesi tanımlar | host proc/sys mount'larını açığa çıkarma, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, manuel olarak unmask edilmediği sürece varsayılan maskelenmiş yolları uygular | `--security-opt unmask=ALL`, hedefli unmasking, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları proc maruziyetini zayıflatmadığı sürece altta yatan runtime'ın maskeleme davranışını kullanır | `procMount: Unmasked`, privileged workload kalıpları, geniş host mount'ları |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Üzerinde değişiklik yapılmadığı sürece genellikle OCI/runtime maskelenmiş yollarını uygular | doğrudan runtime yapılandırması değişiklikleri, aynı Kubernetes zayıflatma yolları |

Maskelenmiş yollar genellikle varsayılan olarak mevcuttur. Temel operasyonel sorun, runtime'da bulunmamaları değil; kasıtlı unmasking veya korumayı geçersiz kılan host bind mount'larıdır.
{{#include ../../../../banners/hacktricks-training.md}}
