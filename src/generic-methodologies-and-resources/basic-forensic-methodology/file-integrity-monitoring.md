# Dosya Bütünlüğü İzleme

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Bir baseline, bir sistemin belirli bölümlerinin anlık görüntüsünü alarak **gelecekteki durumla karşılaştırıp değişiklikleri öne çıkarmayı** içerir.

Örneğin, hangi dosyaların değiştirildiğini tespit edebilmek için dosya sistemindeki her dosyanın hash değerini hesaplayıp saklayabilirsiniz.\
Bu işlem, oluşturulan kullanıcı hesapları, çalışan process'ler, çalışan servisler ve fazla ya da hiç değişmemesi gereken diğer unsurlar için de yapılabilir.

**Kullanışlı bir baseline** genellikle yalnızca bir digest saklamaz: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçilen extended attributes da takip edilmeye değerdir. Attacker-hunting açısından bu, içerik hash'i değişen ilk şey olmasa bile **yalnızca izinlerin değiştirilmesini**, **atomic file replacement** işlemlerini ve **değiştirilmiş servis/unit dosyaları üzerinden persistence** durumlarını tespit etmeye yardımcı olur.

### File Integrity Monitoring

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri takip ederek IT ortamlarını ve verileri koruyan kritik bir security tekniğidir. Genellikle şunları birleştirir:

1. **Baseline karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve cryptographic checksum'ları (tercihen `SHA-256` veya daha iyisi) saklayın.
2. **Real-time bildirimler:** **Hangi dosyanın ne zaman değiştiğini ve ideal olarak hangi process/kullanıcının dosyaya dokunduğunu** öğrenmek için OS-native file event'lerine abone olun.
3. **Periyodik yeniden tarama:** Reboot'lar, kaybolan event'ler, agent kesintileri veya kasıtlı anti-forensic activity sonrasında güveni yeniden oluşturun.

Threat hunting için FIM, genellikle aşağıdaki gibi **yüksek değerli path'lere** odaklandığında daha kullanışlıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` unit'leri, cron konumları, SSH materyalleri, PAM modülleri, web root'ları
- Windows persistence konumları, servis binary'leri, scheduled task dosyaları, startup klasörleri
- Container writable layer'ları ve bind-mounted secret/configuration dosyaları

## Real-Time Backend'ler ve Blind Spot'lar

### Linux

Collection backend'i önemlidir:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: kullanımı kolay ve yaygındır ancak watch limit'leri tüketilebilir ve bazı edge case'ler gözden kaçabilir.
- **`auditd` / audit framework**: **dosyayı kimin değiştirdiğini** (`auid`, process, pid, executable) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM stack'leri tarafından event'leri zenginleştirmek ve plain `inotify` deployment'larının operasyonel yükünü azaltmak için kullanılan daha yeni seçeneklerdir.

Bazı pratik sorunlar:<sup>[[1]](#references)</sup>

- Bir program `write temp -> rename` ile bir dosyayı **değiştirirse**, dosyanın kendisini izlemek artık işe yaramayabilir. Yalnızca dosyayı değil, **parent directory'yi izleyin**.
- `inotify` tabanlı collector'lar **çok büyük directory tree'lerinde**, **hard-link activity** sırasında veya **izlenen bir dosya silindikten** sonra event'leri kaçırabilir ya da performans kaybı yaşayabilir.
- `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` değerleri çok düşükse çok büyük recursive watch set'leri sessizce başarısız olabilir.
- Network filesystem'ler düşük gürültülü monitoring için genellikle kötü FIM hedefleridir.

AIDE ile baseline + verification örneği:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Saldırganın persistence yollarına odaklanan örnek `osquery` FIM yapılandırması:<sup>[[1]](#references)</sup>
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
Yalnızca path-level değişiklikler yerine **process attribution** gerekiyorsa `osquery` `process_file_events` veya Wazuh `whodata` mode gibi audit-backed telemetry kullanmayı tercih edin.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows'ta FIM'i **change journals** ile **high-signal process/file telemetry** birleştirerek daha güçlü hâle getirebilirsiniz:

- **NTFS USN Journal**, dosya değişikliklerinin volume başına kalıcı bir günlüğünü sağlar.
- **Sysmon Event ID 11**, dosya oluşturma/üzerine yazma işlemleri için kullanışlıdır.
- **Sysmon Event ID 2**, **timestomping** tespitine yardımcı olur.
- **Sysmon Event ID 15**, `Zone.Identifier` veya gizli payload stream'leri gibi **named alternate data streams (ADS)** için kullanışlıdır.

Hızlı USN triage örnekleri:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Daha derin **timestamp manipulation**, **ADS abuse** ve **USN tampering** fikirleri için [Anti-Forensic Techniques](anti-forensic-techniques.md) bölümüne bakın.

### Containers

Container FIM çoğu zaman gerçek yazma yolunu gözden kaçırır. Docker `overlay2` ile değişiklikler salt okunur image katmanlarına değil, container'ın **writable upper layer**'ına (`upperdir`/`diff`) kaydedilir. Bu nedenle:

- Yalnızca kısa ömürlü bir container'ın **içindeki** yolları izlemek, container yeniden oluşturulduktan sonraki değişiklikleri gözden kaçırabilir.
- **Host path**'i izlemek; yani writable layer'ı destekleyen yolu veya ilgili bind-mounted volume'ü izlemek genellikle daha kullanışlıdır.
- Image katmanları üzerindeki FIM, çalışan container filesystem'i üzerindeki FIM'den farklıdır.

## Attacker-Oriented Hunting Notes

- **Service definitions** ve **task schedulers**'ı binary'ler kadar dikkatli izleyin. Attackers çoğu zaman `/bin/sshd`'yi patch'lemek yerine bir unit file, cron entry veya task XML'ini değiştirerek persistence elde eder.
- Tek başına bir content hash yeterli değildir. Birçok compromise ilk olarak **owner/mode/xattr/ACL drift** şeklinde ortaya çıkar.
- Mature bir intrusion'dan şüpheleniyorsanız ikisini de yapın: yeni activity için **real-time FIM** ve trusted media'dan alınan bir **cold baseline comparison**.
- Attacker root veya kernel execution elde ettiyse FIM agent'ının, database'inin ve hatta event source'unun tamper edilebileceğini varsayın. Log'ları ve baseline'ları mümkün olduğunda remote olarak veya read-only media üzerinde saklayın.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
