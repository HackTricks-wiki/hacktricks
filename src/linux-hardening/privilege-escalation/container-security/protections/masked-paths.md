# Maskelenmiş Yollar

{{#include ../../../../banners/hacktricks-training.md}}

Maskelenmiş yollar, özellikle hassas kernel-e bakan dosya sistemi konumlarını container'dan gizleyen, bunların üzerine bind-mount yaparak veya başka şekilde erişilemez hâle getirerek çalışan zaman korumalarıdır. Amaç, bir workload'un sıradan uygulamaların ihtiyaç duymadığı arayüzlerle (özellikle procfs içinde) doğrudan etkileşime girmesini engellemektir.

Bu önemlidir çünkü birçok container escape ve host'u etkileyen teknik, `/proc` veya `/sys` altındaki özel dosyaları okumak veya yazmakla başlar. Bu konumlar maskelenmişse, saldırgan container içinde code execution elde etmiş olsa bile kernel kontrol yüzeyinin kullanışlı bir bölümüne doğrudan erişimini kaybeder.

## İşleyiş

Runtimes genellikle şu yolları maskeler:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Tam liste runtime ve host yapılandırmasına bağlıdır. Önemli özellik, yolun host'ta hâlâ mevcut olmasına rağmen container açısından erişilemez veya değiştirilmiş hâle gelmesidir.

## Lab

Docker tarafından açığa çıkarılan masked-path yapılandırmasını inceleyin:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
İş yükü içindeki gerçek mount davranışını inceleyin:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Maskeleme ana izolasyon sınırını oluşturmaz, ancak birkaç yüksek değerli post-exploitation hedefini ortadan kaldırır. Maskeleme yoksa, ele geçirilmiş bir container kernel durumunu inceleyebilir, hassas süreç veya anahtar bilgilerini okuyabilir veya uygulamaya asla görünmemesi gereken procfs/sysfs nesneleri ile etkileşime girebilir.

## Misconfigurations

Temel hata, kolaylık veya hata ayıklama için geniş path sınıflarının maskesinin kaldırılmasıdır. Podman'da bu `--security-opt unmask=ALL` veya hedefli unmasking şeklinde görünebilir. Kubernetes'te aşırı geniş proc açığa çıkışı `procMount: Unmasked` ile ortaya çıkabilir. Bir diğer ciddi sorun ise host `/proc` veya `/sys`'i bind mount ile açığa çıkarmaktır; bu, azaltılmış bir container görünümü fikrini tamamen baypas eder.

## Abuse

Maskeleme zayıf veya yoksa, doğrudan erişilebilen hangi hassas procfs/sysfs yollarının olduğunu belirlemekle başlayın:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Sözde maskelenmiş bir yol erişilebiliyorsa, dikkatle inceleyin:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` ana makinenin timer ve scheduler verilerini açığa çıkarabilir. Bu çoğunlukla bir reconnaissance primitive olmakla birlikte, container'ın normalde gizlenen kernel-facing bilgileri okuyabildiğini doğrular.
- `/proc/keys` çok daha hassastır. Ana makinenin yapılandırmasına bağlı olarak keyring entries, key descriptions ve kernel keyring subsystem'ini kullanan host servisler arasındaki ilişkileri ortaya çıkarabilir.
- `/sys/firmware` boot modunu, firmware interfaces ve platform detaylarını tanımlamaya yardımcı olur; bunlar host fingerprinting ve workload'ın host-level state görüp görmediğini anlamak için faydalıdır.
- `/proc/config.gz` çalışan kernel yapılandırmasını açığa çıkarabilir; bu, public kernel exploit prerequisites ile eşleştirme yapmak veya belirli bir özelliğin neden erişilebilir olduğunu anlamak için değerlidir.
- `/proc/sched_debug` scheduler durumunu açığa çıkarır ve sıklıkla PID namespace'in ilgisiz process bilgilerini tamamen gizleyeceği yönündeki sezgisel beklentiyi atlatır.

İlginç sonuçlar, bu dosyalardan doğrudan okumalar, verinin kısıtlı bir container görünümüne değil ana makineye ait olduğuna dair kanıtlar veya varsayılan olarak sıklıkla maskelenen diğer procfs/sysfs konumlarına erişim içerir.

## Kontroller

Bu kontrollerin amacı, runtime'ın hangi yolları kasıtlı olarak gizlediğini ve mevcut workload'ın hâlâ azaltılmış bir kernel-facing dosya sistemini görüp görmediğini belirlemektir.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Burada ilginç olanlar:

- Uzun bir maskelenmiş yol listesi sertleştirilmiş runtime'larda normaldir.
- Hassas procfs girdilerinde maskelenmenin eksikliği daha yakından incelenmeyi hak eder.
- Eğer hassas bir yol erişilebilirse ve container ayrıca güçlü capabilities veya geniş mounts'a sahipse, maruziyet daha önemli hale gelir.

## Çalışma zamanı varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, varsayılan bir maskelenmiş yol listesi tanımlar | host proc/sys mount'larını açma, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, elle unmask yapılmadıkça varsayılan maskelenmiş yolları uygular | `--security-opt unmask=ALL`, hedefe yönelik unmask, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Alttaki runtime'ın maskelenme davranışını kullanır; Pod ayarları proc maruziyetini zayıflatmadıkça | `procMount: Unmasked`, privileged workload desenleri, geniş host mount'ları |
| containerd / CRI-O under Kubernetes | Runtime varsayılanı | Genellikle üzerine yazılmadıkça OCI/runtime maskelenmiş yollarını uygular | doğrudan runtime yapılandırma değişiklikleri, aynı Kubernetes zayıflatma yolları |

Maskelenmiş yollar genellikle varsayılan olarak mevcuttur. Asıl operasyonel sorun runtime'da yok olmaları değil; kasıtlı unmask edilmesi veya host bind mount'larının korumayı geçersiz kılmasıdır.
{{#include ../../../../banners/hacktricks-training.md}}
