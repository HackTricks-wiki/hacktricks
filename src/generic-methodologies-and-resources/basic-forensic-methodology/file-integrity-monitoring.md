# Dosya Bütünlüğü İzleme

## Baseline

Bir baseline, bir sistemin belirli bölümlerinin anlık görüntüsünü alarak **gelecekteki durumla karşılaştırıp değişiklikleri öne çıkarmayı** içerir.

Örneğin, hangi dosyaların değiştirildiğini belirleyebilmek için dosya sistemindeki her dosyanın hash değerini hesaplayıp saklayabilirsiniz.\
Bu işlem, oluşturulan kullanıcı hesapları, çalışan process'ler, çalışan servisler ve fazla ya da hiç değişmemesi gereken diğer her şey için de yapılabilir.

**Kullanışlı bir baseline** genellikle yalnızca bir digest saklamaz: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçili extended attributes da takip edilmeye değerdir.<sup>[[4]](#references)</sup> Bir saldırgan avcılığı perspektifinden bu, içerik hash'i ilk değişen şey olmasa bile **yalnızca izinlerin değiştirilmesini**, **atomic file replacement** işlemlerini ve **değiştirilmiş service/unit dosyaları üzerinden persistence** yöntemlerini tespit etmeye yardımcı olur.

### Dosya Bütünlüğü İzleme

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri takip ederek IT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. Genellikle şunları birleştirir:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve cryptographic checksum'ları (tercihen `SHA-256` veya daha iyisini) saklayın.
2. **Real-time bildirimler:** **Hangi dosyanın, ne zaman ve ideal olarak hangi process/user tarafından değiştirildiğini** öğrenmek için OS-native file event'lerine abone olun.
3. **Periyodik yeniden tarama:** Reboot'lar, kaybolan event'ler, agent kesintileri veya kasıtlı anti-forensic faaliyetlerden sonra güveni yeniden oluşturun.

Threat hunting için FIM, genellikle aşağıdaki gibi **yüksek değerli path'lere** odaklandığında daha kullanışlıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` unit'leri, cron konumları, SSH materyalleri, PAM modülleri, web root'ları
- Windows persistence konumları, servis binary'leri, scheduled task dosyaları, startup klasörleri
- Container writable layer'ları ve bind-mounted secret/configuration'lar

## Real-Time Backends & Blind Spots

### Linux

Collection backend önemlidir:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: kolay ve yaygındır, ancak watch limit'leri tükenebilir ve bazı edge case'ler gözden kaçabilir.
- **`auditd` / audit framework**: **dosyayı kimin değiştirdiğini** (login UID, process ID ve process name) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM stack'lerinde event'leri zenginleştirmek ve düz `inotify` deployment'larının bazı operasyonel sorunlarını azaltmak için kullanılan daha yeni seçeneklerdir.

Bazı pratik sorunlar:<sup>[[1]](#references)[[5]](#references)</sup>

- Bir program `write temp -> rename` ile bir dosyayı **değiştirirse**, dosyanın kendisini izlemek artık işe yaramayabilir. Yalnızca dosyayı değil, **parent directory'yi izleyin**.
- `inotify` tabanlı collector'lar **çok büyük directory tree'lerinde**, **hard-link faaliyetlerinde** veya **izlenen bir dosya silindikten** sonra event'leri kaçırabilir ya da performansları düşebilir.
- `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` değerleri çok düşükse çok büyük recursive watch set'leri sessizce başarısız olabilir.
- `inotify` tabanlı monitoring için network filesystem'ler bir blind spot'tur; çünkü remote değişiklikler bildirilmez.

AIDE ile baseline + verification örneği:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Saldırgan kalıcılığı yollarına odaklanan örnek `osquery` FIM yapılandırması:<sup>[[1]](#references)</sup>
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
Yalnızca path-level değişiklikler yerine **process attribution** gerekiyorsa `osquery` `process_file_events` veya Wazuh `whodata` mode gibi audit destekli telemetry kullanın.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Windows'ta FIM'i **change journals** ile **yüksek sinyalli process/file telemetry**'yi birleştirdiğinizde daha güçlü hale gelir:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal**, dosya değişikliklerinin volume başına kalıcı bir günlüğünü sağlar.
- **Sysmon Event ID 11**, dosya oluşturma/üzerine yazma işlemleri için kullanışlıdır.
- **Sysmon Event ID 2**, **timestomping** tespitine yardımcı olur.
- **Sysmon Event ID 15**, `Zone.Identifier` veya gizli payload stream'leri gibi **named alternate data streams (ADS)** için kullanışlıdır.

Hızlı USN triage örnekleri:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Daha derin **timestamp manipulation**, **ADS abuse** ve **USN tampering** fikirleri için [Anti-Forensic Techniques](anti-forensic-techniques.md) sayfasına bakın.

### Containers

Container FIM çoğu zaman gerçek yazma yolunu gözden kaçırır. Docker `overlay2` ile container dosya sistemi, salt okunur image `lowerdir` katmanlarını yazılabilir bir **üst katmanla** (`upperdir`/`diff`) birleştirir ve image dosyalarına yapılan yazma işlemleri bu üst katmana kopyalanır.<sup>[[8]](#references)</sup> Bu nedenle:

- Yalnızca kısa ömürlü bir container **içindeki** yolların izlenmesi, container yeniden oluşturulduktan sonraki değişiklikleri gözden kaçırabilir.
- Yazılabilir katmanı destekleyen **host yolunun** veya ilgili bind-mounted volume'ün izlenmesi genellikle daha yararlıdır.
- Image katmanlarındaki FIM, çalışan container dosya sistemindeki FIM'den farklıdır.

## Saldırgan Odaklı Avcılık Notları

- **Service definitions** ve **task schedulers**'ı binary'ler kadar dikkatli izleyin. Saldırganlar genellikle `/bin/sshd` üzerinde değişiklik yapmak yerine bir unit file, cron girdisi veya task XML'ini değiştirerek persistence elde eder.
- Yalnızca content hash yeterli değildir. Birçok compromise ilk olarak **owner/mode/xattr/ACL drift** şeklinde ortaya çıkar.
- Olgun bir intrusion'dan şüpheleniyorsanız ikisini de yapın: yeni etkinlikler için **real-time FIM** ve güvenilir medyadan alınan bir **cold baseline comparison**.
- Saldırgan root veya kernel execution elde ettiyse FIM agent'ını ve veritabanını güvenilmeyen olarak değerlendirin. Log'ları ve baseline'ları mümkün olduğunda uzaktan veya salt okunur medyada saklayın.<sup>[[4]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
