# Maskelenmiş Yollar

{{#include ../../../../banners/hacktricks-training.md}}

Maskelenmiş yollar, özellikle kernel'e bakan hassas dosya sistemi konumlarını konteynerden gizleyen, bind-mount yaparak veya başka şekilde erişilemez kılan runtime korumalarıdır. Amaç, özellikle procfs içinde, sıradan uygulamaların ihtiyaç duymadığı arayüzlerle bir iş yükünün doğrudan etkileşime girmesini engellemektir.

Bu önemlidir çünkü birçok container kaçışı ve ana makinayı etkileyen teknik, `/proc` veya `/sys` altındaki özel dosyaları okuyup/yazarak başlar. Bu konumlar maskelenmişse, saldırgan konteyner içinde kod yürütme yetkisi elde etse bile kernel kontrol yüzeyinin yararlı bir bölümüne doğrudan erişimini kaybeder.

## İşleyiş

Runtimeler genellikle şu gibi seçili yolları maskeler:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Kesin liste runtime'a ve ana makinenin yapılandırmasına bağlıdır. Önemli özellik, yolun ana makinede hâlâ mevcut olmasına rağmen konteyner açısından erişilemez veya yerine başka bir şey konmuş gibi görünmesidir.

## Laboratuvar

Docker tarafından açığa çıkarılan masked-path yapılandırmasını inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
İş yükü içindeki gerçek mount davranışını inceleyin:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Güvenlik Etkisi

Maskeleme ana izolasyon sınırını oluşturmaz, ancak birkaç yüksek değerli post-exploitation hedefini ortadan kaldırır. Maskeleme yoksa, ele geçirilmiş bir konteyner çekirdek durumunu inceleyebilir, hassas süreç veya anahtar bilgilerini okuyabilir veya uygulamaya asla görünmemesi gereken procfs/sysfs nesneleriyle etkileşime girebilir.

## Yanlış Yapılandırmalar

Ana hata, kolaylık veya hata ayıklama amacıyla geniş kapsamlı yol kategorilerinin maskelemesini kaldırmaktır. Podman'da bu `--security-opt unmask=ALL` veya hedeflenmiş maske kaldırma şeklinde görülebilir. Kubernetes'te, aşırı geniş proc açığa çıkışı `procMount: Unmasked` ile ortaya çıkabilir. Diğer ciddi bir sorun ise host `/proc` veya `/sys`'i bind mount ile açığa çıkarmaktır; bu, azaltılmış bir konteyner görünümü fikrini tamamen baypas eder.

## Kötüye Kullanım

Eğer maskeleme zayıfsa veya yoksa, önce hangi hassas procfs/sysfs yollarının doğrudan erişilebilir olduğunu belirlemekle başlayın:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Eğer sözde masked path erişilebiliyorsa, dikkatle inceleyin:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` host timer ve scheduler verilerini açığa çıkarabilir. Bu çoğunlukla bir reconnaissance primitive olup, container'ın normalde gizlenen kernel-facing bilgileri okuyabildiğini doğrular.
- `/proc/keys` çok daha hassastır. Host yapılandırmasına bağlı olarak, keyring girdilerini, key açıklamalarını ve kernel keyring subsystem'ını kullanan host servisleri arasındaki ilişkileri açığa çıkarabilir.
- `/sys/firmware` boot modunu, firmware arayüzlerini ve host fingerprinting için yararlı olan platform detaylarını tespit etmeye yardımcı olur; ayrıca workload'un host-level state'i görüp görmediğini anlamak için yararlıdır.
- `/proc/config.gz` çalışan kernel yapılandırmasını açığa çıkarabilir; bu, public kernel exploit önkoşullarını eşleştirmek veya belirli bir özelliğin neden erişilebilir olduğunu anlamak için değerlidir.
- `/proc/sched_debug` scheduler durumunu açığa çıkarır ve genellikle PID namespace'in ilgisiz process bilgilerini tamamen gizleyeceği yönündeki sezgisel beklentiyi atlatır.

İlginç bulgular arasında bu dosyalardan doğrudan okuma, verinin kısıtlı bir container görünümüne değil host'a ait olduğuna dair kanıtlar veya varsayılan olarak genellikle maskelenen diğer procfs/sysfs konumlarına erişim yer alır.

## Checks

Bu kontrollerin amacı, runtime'ın hangi yolları kasıtlı olarak gizlediğini ve mevcut workload'un hâlâ azaltılmış bir kernel-facing filesystem'i görüp görmediğini belirlemektir.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Burada ilginç olanlar:

- Sertleştirilmiş runtime'larda uzun bir maskelenmiş yol listesi normaldir.
- Hassas procfs girdilerinde maskelenmenin eksik olması daha yakından incelenmeyi gerektirir.
- Eğer bir hassas yol erişilebilir durumdaysa ve container ayrıca güçlü capabilities veya geniş mounts'a sahipse, maruz kalmanın önemi artar.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker varsayılan bir maskelenmiş yol listesi tanımlar | host proc/sys mount'larının açılması, `--privileged` |
| Podman | Enabled by default | Podman, elle maskeleri kaldırılmadıkça varsayılan maskelenmiş yolları uygular | `--security-opt unmask=ALL`, hedefli unmasking, `--privileged` |
| Kubernetes | Inherits runtime defaults | Pod ayarları proc maruziyetini zayıflatmadıkça alttaki runtime'ın maskeleme davranışını kullanır | `procMount: Unmasked`, privileged workload pattern'leri, geniş host mount'ları |
| containerd / CRI-O under Kubernetes | Runtime default | Genellikle üzerine yazılmadıkça OCI/runtime maskelenmiş yollarını uygular | doğrudan runtime yapılandırma değişiklikleri, aynı Kubernetes zayıflatma yolları |

Maskelenmiş yollar genellikle varsayılan olarak mevcuttur. Ana operasyonel sorun runtime'dan yok olmaları değil; kasıtlı olarak maskelerin kaldırılması veya korumayı geçersiz kılan host bind mount'larıdır.
