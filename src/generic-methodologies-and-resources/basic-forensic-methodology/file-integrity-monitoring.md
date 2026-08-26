# Dosya Bütünlüğü İzleme

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Bir baseline, bir sistemin belirli bölümlerinin anlık görüntüsünü alarak **gelecekteki bir durumla karşılaştırıp değişiklikleri öne çıkarmayı** içerir.

Örneğin, hangi dosyaların değiştirildiğini tespit edebilmek için dosya sistemindeki her dosyanın hash değerini hesaplayıp depolayabilirsiniz.\
Bu işlem, oluşturulan kullanıcı hesapları, çalışan process'ler, çalışan servisler ve fazla ya da hiç değişmemesi gereken diğer unsurlar için de yapılabilir.

**Kullanışlı bir baseline** genellikle yalnızca bir digest depolamaz: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçilen extended attribute'lar da takip edilmeye değerdir.<sup>[[4]](#references)</sup> Saldırgan avlama perspektifinden bu yaklaşım, içerik hash'i ilk değişen unsur olmasa bile **yalnızca izinlerin değiştirilmesini**, **atomic file replacement** işlemlerini ve **değiştirilmiş service/unit dosyaları üzerinden persistence** kullanımını tespit etmeye yardımcı olur.

### File Integrity Monitoring

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri takip ederek IT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. Genellikle şunları birleştirir:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve cryptographic checksum'ları (`SHA-256` veya daha iyisi tercih edilir) depolayın.
2. **Real-time bildirimler:** **Hangi dosyanın ne zaman değiştiğini ve ideal olarak hangi process/user tarafından değiştirildiğini** öğrenmek için OS-native file event'lerine abone olun.
3. **Periyodik yeniden tarama:** Reboot'lar, kaybolan event'ler, agent kesintileri veya kasıtlı anti-forensic activity sonrasında güveni yeniden oluşturun.

Threat hunting için FIM, genellikle aşağıdaki gibi **yüksek değerli path'lere** odaklandığında daha kullanışlıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` unit'leri, cron konumları, SSH materyalleri, PAM modülleri, web root'ları
- Windows persistence konumları, servis binary'leri, scheduled task dosyaları, startup klasörleri
- Container writable layer'ları ve bind-mounted secret/configuration dosyaları

## Real-Time Backends & Blind Spots

### Linux

Collection backend önemlidir:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: kullanımı kolay ve yaygındır, ancak watch limit'leri tükenebilir ve bazı edge case'ler kaçırılabilir.
- **`auditd` / audit framework**: **dosyayı kimin değiştirdiğini** (login UID, process ID ve process name) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM stack'lerinde event'leri zenginleştirmek ve yalnızca `inotify` deployment'larının bazı operasyonel zorluklarını azaltmak için kullanılan daha yeni seçeneklerdir.

Bazı pratik sorunlar:<sup>[[1]](#references)[[5]](#references)</sup>

- Bir program `write temp -> rename` ile bir dosyayı **değiştirirse**, doğrudan dosyanın izlenmesi artık kullanışlı olmayabilir. Yalnızca dosyayı değil, **parent directory'yi izleyin**.
- `inotify` tabanlı collector'lar **çok büyük directory tree'lerinde**, **hard-link activity** sırasında veya **izlenen bir dosya silindikten** sonra event'leri kaçırabilir ya da performans kaybı yaşayabilir.
- Recursive watch set'leri çok büyük olduğunda `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` değerleri çok düşükse işlemler sessizce başarısız olabilir.
- `inotify` tabanlı monitoring için network filesystem'lar bir blind spot'tur; çünkü remote değişiklikler raporlanmaz.

AIDE ile örnek baseline + verification:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Saldırgan kalıcılık yollarına odaklanan örnek `osquery` FIM yapılandırması:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Yalnızca yol düzeyindeki değişiklikler yerine **process attribution** gerekiyorsa `osquery` `process_file_events` veya Wazuh `whodata` mode gibi audit destekli telemetriyi tercih edin.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetrisi FIM değildir

Modern Linux'ta `openat(2)`, `write(2)` veya diğer syscall giriş noktalarını izlemek, ortaya çıkan filesystem operation'ı izlemekle **eşdeğer değildir**. 2025 tarihli **Curing** proof of concept'i, file ve network request'lerini `io_uring` üzerinden kuyruğa aldı; bu nedenle yalnızca ilgili operation başına syscall girişlerine bağlı ürünler veya policy'ler process telemetrisini kaybetti. Aynı testlerde path-scoped bir FIM bileşeni file modification'larını yine de gözlemledi; bu durum bir **hook-placement blind spot** olduğunu, permission bypass veya her FIM backend'ini etkisiz kılma yöntemi olmadığını gösterir.<sup>[[10]](#references)</sup>

Bir sensörü doğrularken aynı canary'yi birkaç farklı yöntemle değiştirin: normal `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomic replacement ve `io_uring`. Yalnızca final hash drift'inin tespit edilip edilmediğini değil, event'in sorumlu process'i, container/cgroup'u, namespace-visible path'i, inode'u ve rename pair'i koruyup korumadığını da kontrol edin. Periodic scan mismatch'inin ardından gerçek zamanlı event'in eksik olması, **telemetry loss** olarak ele alınmalı; rutin ve açıklanamayan bir değişiklik olarak değerlendirilmemelidir.<sup>[[10]](#references)[[11]](#references)</sup>

eBPF tabanlı monitoring için syscall-entry probe listesinden ziyade yaygın kernel enforcement point'lerini tercih edin. Örneğin Tetragon'un file-access policy'si ordinary I/O, `sendfile`, `copy_file_range`, AIO ve `io_uring` kapsamı için `security_file_permission` kullanır; memory mapping'lerini `security_mmap_file`, size change'lerini ise `security_path_truncate` ile ayrıca kapsar. Bu durum, tek bir hook'un neden nadiren tam kapsam sağladığını da gösterir.<sup>[[11]](#references)</sup>

### Windows

Windows'ta FIM'i **change journal**'larını **high-signal process/file telemetry** ile birleştirdiğinizde daha güçlü hale gelir:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal**, file change'leri için volume başına kalıcı bir log sağlar.
- **Sysmon Event ID 11**, file creation/overwrite işlemleri için kullanışlıdır.
- **Sysmon Event ID 2**, **timestomping** tespitine yardımcı olur.
- **Sysmon Event ID 15**, `Zone.Identifier` veya hidden payload stream'leri gibi **named alternate data streams (ADS)** için kullanışlıdır.

Hızlı USN triage örnekleri:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Daha derin **timestamp manipulation**, **ADS abuse** ve **USN tampering** fikirleri için [Anti-Forensic Techniques](anti-forensic-techniques.md) sayfasına bakın.

### Container'lar

Container FIM, gerçek yazma yolunu sıklıkla gözden kaçırır. Docker `overlay2` ile container filesystem, salt okunur image `lowerdir` katmanlarını yazılabilir bir **upper layer** (`upperdir`/`diff`) ile birleştirir ve image dosyalarına yapılan yazma işlemleri bu upper layer'a kopyalanır.<sup>[[8]](#references)</sup> Bu nedenle:

- Yalnızca kısa ömürlü bir container **içindeki** yolları izlemek, container yeniden oluşturulduktan sonraki değişiklikleri gözden kaçırabilir.
- Yazılabilir katmanı destekleyen **host path**'i veya ilgili bind-mounted volume'u izlemek çoğu zaman daha kullanışlıdır.
- Image katmanlarındaki FIM, çalışan container filesystem'ındaki FIM'den farklıdır.

## Saldırgan Odaklı Hunting Notları

- **service definitions** ve **task schedulers**'ı binary'ler kadar dikkatli izleyin. Saldırganlar genellikle `/bin/sshd`'yi patch'lemek yerine bir unit file'ı, cron entry'yi veya task XML'ini değiştirerek persistence elde eder.
- Tek başına bir content hash yeterli değildir. Birçok compromise ilk olarak **owner/mode/xattr/ACL drift** şeklinde ortaya çıkar.
- Olgun bir intrusion'dan şüpheleniyorsanız ikisini de yapın: yeni etkinlikler için **real-time FIM** ve güvenilir medyadan alınan bir **cold baseline comparison**.
- Saldırgan root veya kernel execution elde ettiyse FIM agent'ını ve veritabanını güvenilmeyen olarak değerlendirin. Log'ları ve baseline'ları mümkün olduğunda uzakta veya salt okunur medyada saklayın.<sup>[[4]](#references)</sup>

## Araçlar

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery ile File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux'ı izleme: Bir file integrity monitoring kullanım senaryosu (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck ve whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit Bypasses Linux Security Tools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Filename access: covering synchronous, asynchronous, mapped, and truncation paths (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
