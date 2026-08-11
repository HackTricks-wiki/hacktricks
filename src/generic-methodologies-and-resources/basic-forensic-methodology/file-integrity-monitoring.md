# Dosya Bütünlüğü İzleme

{{#include ../../banners/hacktricks-training.md}}

## Temel Durum

Bir temel durum, bir sistemin belirli bölümlerinin anlık görüntüsünü alarak **gelecekteki durumla karşılaştırıp değişiklikleri belirginleştirmekten** oluşur.

Örneğin, hangi dosyaların değiştirildiğini öğrenebilmek için dosya sistemindeki her dosyanın hash değerini hesaplayıp saklayabilirsiniz.\
Bu işlem; oluşturulan kullanıcı hesapları, çalışan işlemler, çalışan servisler ve fazla ya da hiç değişmemesi gereken diğer her şey için de yapılabilir.

**Kullanışlı bir temel durum** genellikle yalnızca bir özetten fazlasını saklar: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçili extended attributes da takip edilmeye değerdir.<sup>[[4]](#references)</sup> Saldırgan avcılığı açısından bu, içerik hash'i ilk değişen şey olmasa bile **yalnızca izinlere yönelik kurcalamayı**, **atomic file replacement** işlemlerini ve **değiştirilmiş servis/unit dosyaları üzerinden kalıcılığı** tespit etmeye yardımcı olur.

### Dosya Bütünlüğü İzleme

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri takip ederek IT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. Genellikle şunları birleştirir:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Temel durum karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve kriptografik checksum'ları (tercihen `SHA-256` veya daha iyisini) saklayın.
2. **Gerçek zamanlı bildirimler:** **Hangi dosyanın, ne zaman ve ideal olarak hangi işlem/kullanıcı tarafından değiştirildiğini** öğrenmek için işletim sisteminin yerel dosya olaylarına abone olun.
3. **Periyodik yeniden tarama:** Reboot'lar, kaybolan olaylar, agent kesintileri veya kasıtlı anti-forensic activity sonrasında güveni yeniden oluşturun.

Threat hunting için FIM genellikle aşağıdaki gibi **yüksek değerli path'lere** odaklandığında daha kullanışlıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron konumları, SSH materyalleri, PAM modülleri, web root'ları
- Windows persistence konumları, servis binary'leri, scheduled task dosyaları, startup klasörleri
- Container writable layer'ları ve bind-mounted secret/configuration dosyaları

## Gerçek Zamanlı Backend'ler ve Kör Noktalar

### Linux

Collection backend önemlidir:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: kolay ve yaygındır, ancak watch limit'leri tükenebilir ve bazı edge case'ler kaçırılabilir.
- **`auditd` / audit framework**: **dosyayı kimin değiştirdiğini** (login UID, process ID ve process name) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM stack'lerinde event'leri zenginleştirmek ve düz `inotify` deployment'larının bazı operasyonel zorluklarını azaltmak için kullanılan daha yeni seçeneklerdir.

Bazı pratik sorunlar:<sup>[[1]](#references)[[5]](#references)</sup>

- Bir program `write temp -> rename` ile bir dosyayı **değiştirirse**, yalnızca dosyanın kendisini izlemek kullanışsız hale gelebilir. Yalnızca dosyayı değil, **parent directory'yi izleyin**.
- `inotify` tabanlı collector'lar **çok büyük directory tree'lerinde**, **hard-link activity** sırasında veya **izlenen bir dosya silindikten** sonra olayları kaçırabilir ya da performans kaybı yaşayabilir.
- `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` değerleri çok düşükse çok büyük recursive watch set'leri sessizce başarısız olabilir.
- `inotify` tabanlı monitoring için network filesystem'ler bir kör noktadır; çünkü remote değişiklikler bildirilmez.

AIDE ile temel durum oluşturma + doğrulama örneği:<sup>[[4]](#references)</sup>
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
Yalnızca path-level changes yerine **process attribution** gerekiyorsa `osquery` `process_file_events` veya Wazuh `whodata` mode gibi audit-backed telemetry kullanmayı tercih edin.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Windows'ta FIM, **change journals** ile **high-signal process/file telemetry** birleştirildiğinde daha güçlü olur:<sup>[[6]](#references)[[7]](#references)</sup>

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
Daha derin **timestamp manipulation**, **ADS abuse** ve **USN tampering** fikirleri için [Anti-Forensic Techniques](anti-forensic-techniques.md) bölümüne bakın.

### Containers

Container FIM genellikle gerçek yazma yolunu gözden kaçırır. Docker `overlay2` ile container dosya sistemi, salt okunur image `lowerdir` katmanlarını yazılabilir bir **upper layer** (`upperdir`/`diff`) ile birleştirir ve image dosyalarına yapılan yazma işlemleri bu upper layer'a kopyalanır.<sup>[[8]](#references)</sup> Bu nedenle:

- Yalnızca kısa ömürlü bir container'ın **içindeki** yolları izlemek, container yeniden oluşturulduktan sonraki değişiklikleri gözden kaçırabilir.
- Yazılabilir katmanın arkasındaki **host path**'i veya ilgili bind-mounted volume'ü izlemek genellikle daha faydalıdır.
- Image katmanlarındaki FIM, çalışan container dosya sistemindeki FIM'den farklıdır.

## Attacker-Oriented Hunting Notes

- **Service definitions** ve **task schedulers**'ı binary'ler kadar dikkatli izleyin. Attackers genellikle `/bin/sshd`'yi patch'lemek yerine bir unit file, cron entry veya task XML'ini değiştirerek persistence elde eder.
- Yalnızca content hash yeterli değildir. Birçok compromise ilk olarak **owner/mode/xattr/ACL drift** şeklinde ortaya çıkar.
- Mature bir intrusion'dan şüpheleniyorsanız ikisini de yapın: yeni etkinlikler için **real-time FIM** ve trusted media'dan alınan bir **cold baseline comparison**.
- Attacker root veya kernel execution elde etmişse FIM agent'ını ve veritabanını untrusted kabul edin. Log'ları ve baseline'ları mümkün olduğunda uzaktan veya salt okunur media üzerinde saklayın.<sup>[[4]](#references)</sup>

## Tools

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
