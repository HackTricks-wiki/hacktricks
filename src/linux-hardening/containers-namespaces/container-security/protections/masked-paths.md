# Maskelenmiş Yollar

{{#include ../../../../banners/hacktricks-training.md}}

Maskelenmiş yollar, özellikle hassas ve kernel ile etkileşimli dosya sistemi konumlarını üzerlerine bind mount yaparak veya başka yollarla erişilemez hâle getirerek container'dan gizleyen çalışma zamanı korumalarıdır. OCI runtime specification, `maskedPaths` değerini container içinde okunamaması gereken mutlak yollar olarak tanımlar. <sup>[[1]](#references)</sup>

Bu önemlidir çünkü birçok container escape ve host'u etkileyen teknik, `/proc` veya `/sys` altındaki özel dosyaları okumak ya da yazmakla başlar. Bu konumlar maskelenmişse saldırgan, container içinde kod yürütme yetkisi kazandıktan sonra bile kernel'in denetim yüzeyinin kullanışlı bir bölümüne doğrudan erişemez.

## İşleyiş

Runtime'lar genellikle şu tür seçili yolları maskeler:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Kesin liste, runtime'a ve host yapılandırmasına bağlıdır. Önemli olan, host üzerinde hâlâ mevcut olmasına rağmen yolun container açısından erişilemez hâle gelmesi veya başka bir şeyle değiştirilmesidir.

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

Listelenen bir yol mutlaka okunabilir değildir: runc bir dosyayı `/dev/null` bind mount ile, bir dizini ise salt okunur boş bir tmpfs ile maskeleyebilir. Yalnızca `ls` komutunun başarılı olup olmadığına değil, tam mountpoint'e bakın. <sup>[[4]](#references)</sup>

## Güvenlik Etkisi

Maskeleme temel izolasyon sınırını oluşturmaz, ancak post-exploitation sırasında hedef olabilecek, değeri yüksek birçok noktayı ortadan kaldırır. Maskeleme olmadığında, ele geçirilmiş bir container kernel durumunu inceleyebilir, hassas işlem veya keying bilgilerini okuyabilir ya da uygulamaya asla görünür olmaması gereken procfs/sysfs nesneleriyle etkileşim kurabilir.

## Yanlış Yapılandırmalar

En yaygın hata, kolaylık veya hata ayıklama amacıyla geniş yol sınıflarının maskesini kaldırmaktır. Podman'da bu, `--security-opt unmask=ALL` veya belirli yolların maskesini kaldırma biçiminde görülebilir. <sup>[[2]](#references)</sup> Kubernetes'te proc'un gereğinden geniş biçimde kullanıma açılması `procMount: Unmasked` ile görülebilir; güncel Kubernetes bu ayar için `spec.hostUsers: false` (bir user namespace) olmasını gerektirirken, 1.12–1.29 sürümleri bu gerekliliği uygulamıyordu. <sup>[[3]](#references)</sup> Diğer ciddi bir sorun ise host `/proc` veya `/sys` dizinini bind mount ile kullanıma açmaktır; bu, container görünümünü daraltma fikrini tamamen geçersiz kılar.

## Kötüye Kullanım

Maskeleme zayıfsa veya yoksa, hangi hassas procfs/sysfs yollarına doğrudan erişilebildiğini belirleyerek başlayın:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Maskelendiği varsayılan bir yola erişilebiliyorsa, dikkatlice inceleyin:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Bu komutların ortaya çıkarabilecekleri:

- `/proc/timer_list`, ana makinenin zamanlayıcı ve zamanlayıcı planlayıcı verilerini açığa çıkarabilir. Bu çoğunlukla bir keşif aracıdır, ancak container'ın normalde gizli olan çekirdek düzeyindeki bilgilere erişebildiğini doğrular.
- `/proc/keys`, yalnızca okuyucunun **view** iznine sahip olduğu anahtarların meta verilerini, LSM denetimlerine tabi olarak listeler. Anahtar türlerini ve açıklamalarını açığa çıkarabilir, ancak anahtar yüklerini dökmez. <sup>[[6]](#references)</sup>
- `/sys/firmware`, ana makine parmak izi çıkarmak ve iş yükünün ana makine düzeyindeki durumu görüp görmediğini anlamak için faydalı olan önyükleme modunu, firmware arayüzlerini ve platform ayrıntılarını belirlemeye yardımcı olur.
- `/proc/config.gz`, çalışan çekirdeğin yapılandırmasını açığa çıkarabilir; bu da herkese açık çekirdek exploit'lerinin önkoşullarını eşleştirmek veya belirli bir özelliğin neden erişilebilir olduğunu anlamak açısından değerlidir.
- `/proc/sched_debug`, zamanlayıcı durumunu açığa çıkarır ve PID namespace'in ilgisiz süreç bilgilerini tamamen gizlemesi gerektiğine dair sezgisel beklentiyi çoğu zaman boşa çıkarır.

Dikkat çekici sonuçlar arasında bu dosyalardan doğrudan veri okunabilmesi, verilerin kısıtlanmış bir container görünümüne değil ana makineye ait olduğunun anlaşılması veya varsayılan olarak genellikle maskelenen diğer procfs/sysfs konumlarına erişilebilmesi yer alır.

### Container başlatılırken maske kaynağı yarışı

Güvenlik açığı bulunan runc uygulamalarında dosya maskeleri, container'ın `/dev/null` inode'una bağlıdır. Paralel BuildKit adımları da dahil olmak üzere paylaşılan mount'larla eşzamanlı container'lar oluşturabilen bir saldırgan, runc bunu maskelenmiş procfs dosyalarının üzerine bind etmeden önce `/dev/null`'ı kaldırarak bir race yaratabilir. Ardından runtime, eksik **kaynağı**, maske hedefi yokmuş gibi değerlendirir ve bu dosya maskelerini sessizce atlar. Hata, runtime kurulumu sırasında oluşan bir race'e bağlıdır; başlatma sonrasında `/dev/null`'ı kaldırmak, önceden uygulanmış bir maskeyi geri almaz. <sup>[[4]](#references)</sup>

Kontrollü bir testten sonra, istenen maske listesini yeni container içindeki tam mount noktalarıyla karşılaştırın. <sup>[[4]](#references)</sup> `findmnt -M`, üst bir mount'a geri dönmek yerine belirtilen mount noktasını denetler; `findmnt` yoksa `/proc/self/mountinfo` içeriğini inceleyin. <sup>[[5]](#references)</sup> `ls` komutunun başarılı olması veya `cat` komutunun boş çıktı vermesi, maskenin bulunmadığını kanıtlamaz. <sup>[[4]](#references)</sup>

Yeni container'daki istenen maskeleri tam mount noktalarıyla karşılaştırmak için [aşağıdaki kontrolleri](#checks) kullanın.

Atlanan bir dosya maskesi, normal izinler ve LSM politikası izin veriyorsa procfs verilerini açığa çıkarabilir. Ancak bu, tek başına `/proc/sys` dizinini yazılabilir hale **getirmez**: bu, ayrı bir [read-only-paths](read-only-paths.md) denetimidir. Bind mount'u yazılabilir bir procfs hedefine yönlendirebilen farklı `/dev/null` symlink değiştirme durumu, [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs) bölümünde ele alınmıştır. <sup>[[4]](#references)</sup>

## Kontroller

Bu kontrollerin amacı, runtime'ın hangi yolları kasıtlı olarak gizlediğini ve mevcut iş yükünün hâlâ çekirdek düzeyindeki dosya sisteminin kısıtlanmış bir görünümünü görüp görmediğini belirlemektir.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Kesin bir mount kontrolü kullanın; çünkü maskelenmiş bir dosya hâlâ mevcut olabilir ve `/dev/null` üzerinden yapılan bir okuma boş sonuç döndürebilir. Bir mountpoint'in bulunmaması, tek başına okunabilir host verisinin kanıtı değil, araştırılması gereken bir bulgudur. <sup>[[4]](#references)[[5]](#references)</sup>

Burada dikkat çekenler:

- Uzun bir maskelenmiş yol listesi, harden edilmiş runtime'larda normaldir.
- Hassas procfs girdilerinde maskelemenin eksik olması daha yakından incelenmelidir.
- Hassas bir yola erişilebiliyorsa ve container'da güçlü capabilities veya geniş mount'lar da varsa, bu maruziyet daha önemlidir.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Sık görülen manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin | Docker, varsayılan bir maskelenmiş yol listesi tanımlar | host proc/sys mount'larını açığa çıkarma, `--privileged` |
| Podman | Varsayılan olarak etkin | Podman, manuel olarak maskeleme kaldırılmadıkça varsayılan maskelenmiş yolları uygular | `--security-opt unmask=ALL`, belirli yolların maskesini kaldırma, `--privileged` |
| Kubernetes | Runtime varsayılanlarını devralır | Pod ayarları proc maruziyetini zayıflatmadıkça alttaki runtime'ın maskeleme davranışını kullanır | `procMount: Unmasked` (mevcut sürümlerde `hostUsers: false` gerektirir), ayrıcalıklı workload kalıpları, geniş host mount'ları |
| Kubernetes altında containerd / CRI-O | Runtime varsayılanı | Üzerine yazılmadıkça genellikle OCI/runtime maskelenmiş yollarını uygular | doğrudan runtime yapılandırma değişiklikleri, aynı Kubernetes zayıflatma yolları |

Maskelenmiş yollar genellikle varsayılan olarak mevcuttur. Operasyonel açıdan temel sorun runtime'da bulunmamaları değil, maskelemenin kasıtlı olarak kaldırılması veya korumayı etkisiz kılan host bind mount'larıdır.

## References

- [1] [Open Container Initiative - Linux container yapılandırması: Maskelenmiş Yollar](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman belgeleri - `podman run` güvenlik seçenekleri](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes Belgeleri - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc güvenlik duyurusu: masked-path mount kaynak yarışı](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) kılavuzu](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) kılavuzu](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
