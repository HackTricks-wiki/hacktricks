# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline, bir sistemin belirli bölümlerinin anlık görüntüsünü alarak **gelecekteki durumla karşılaştırıp değişiklikleri vurgulamaktan** oluşur.

Örneğin, hangi dosyaların değiştirildiğini tespit edebilmek için dosya sistemindeki her dosyanın hash değerini hesaplayıp saklayabilirsiniz.\
Bu işlem, oluşturulan kullanıcı hesapları, çalışan process'ler, çalışan servisler ve fazla ya da hiç değişmemesi gereken diğer unsurlar için de yapılabilir.

**Kullanışlı bir baseline** genellikle yalnızca bir digest saklamaz: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçili extended attribute'lar da takip edilmeye değerdir. Saldırgan avcılığı açısından bu; içerik hash'inin değişmesi ilk belirti olmasa bile **yalnızca izinlerin değiştirilmesini**, **atomic file replacement** işlemlerini ve **değiştirilmiş service/unit dosyaları üzerinden persistence** kullanımını tespit etmeye yardımcı olur.

### File Integrity Monitoring

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri takip ederek IT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. Genellikle şunları birleştirir:

1. **Baseline karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve kriptografik checksum'ları (`SHA-256` veya daha iyisini tercih edin) saklayın.
2. **Gerçek zamanlı bildirimler:** **Hangi dosyanın, ne zaman ve ideal olarak hangi process/user tarafından değiştirildiğini** öğrenmek için OS-native file event'lerine abone olun.
3. **Periyodik yeniden tarama:** Reboot'lar, kaybolan event'ler, agent kesintileri veya kasıtlı anti-forensic activity sonrasında güveni yeniden oluşturun.

Threat hunting için FIM, genellikle aşağıdakiler gibi **yüksek değerli path'lere** odaklandığında daha kullanışlıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` unit'leri, cron konumları, SSH materyalleri, PAM modülleri, web root'ları
- Windows persistence konumları, service binary'leri, scheduled task dosyaları, startup klasörleri
- Container writable layer'ları ve bind-mounted secret/configuration'lar

## Real-Time Backends & Blind Spots

### Linux

Collection backend önemlidir:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: kolay ve yaygındır, ancak watch limit'leri tüketilebilir ve bazı edge case'ler kaçırılır.
- **`auditd` / audit framework**: **dosyayı kimin değiştirdiğini** (`auid`, process, pid, executable) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM stack'lerinde event'leri zenginleştirmek ve yalnızca `inotify` deployment'larının bazı operasyonel sorunlarını azaltmak için kullanılan daha yeni seçeneklerdir.

Bazı pratik sorunlar:<sup>[[1]](#references)</sup>

- Bir program `write temp -> rename` ile bir dosyayı **değiştirirse**, dosyanın kendisini izlemek artık işe yaramayabilir. Yalnızca dosyayı değil, **parent directory'yi izleyin**.
- `inotify` tabanlı collector'lar **çok büyük directory tree'lerinde**, **hard-link activity** sırasında veya **izlenen bir dosya silindikten** sonra event'leri kaçırabilir ya da performansları düşebilir.
- `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` değerleri çok düşükse, çok büyük recursive watch set'leri sessizce başarısız olabilir.
- Network filesystem'ler, düşük gürültülü monitoring için genellikle kötü FIM hedefleridir.

AIDE ile örnek baseline + verification:
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
Yalnızca path-level değişiklikler yerine **process attribution** gerekiyorsa `osquery` `process_file_events` veya Wazuh `whodata` mode gibi audit destekli telemetry kullanmayı tercih edin.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows'ta FIM, **change journals** ile **high-signal process/file telemetry** birlikte kullanıldığında daha güçlüdür:

- **NTFS USN Journal**, dosya değişikliklerinin volume başına kalıcı bir log'unu sağlar.
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

Container FIM çoğu zaman gerçek yazma yolunu gözden kaçırır. Docker `overlay2` ile değişiklikler salt okunur image layer'larına değil, container'ın **writable upper layer**'ına (`upperdir`/`diff`) kaydedilir. Bu nedenle:

- Yalnızca kısa ömürlü bir container'ın **içindeki** yolları izlemek, container yeniden oluşturulduktan sonraki değişiklikleri gözden kaçırabilir.
- **Host path** üzerinde writable layer'ı destekleyen yolu veya ilgili bind-mounted volume'ü izlemek çoğu zaman daha kullanışlıdır.
- Image layer'ları üzerindeki FIM, çalışan container filesystem'i üzerindeki FIM'den farklıdır.

## Attacker-Oriented Hunting Notes

- **Service definitions** ve **task schedulers**'ı binary'ler kadar dikkatli takip edin. Saldırganlar çoğu zaman `/bin/sshd` dosyasına patch uygulamak yerine bir unit file, cron entry veya task XML'i değiştirerek persistence elde eder.
- Tek başına bir content hash yeterli değildir. Birçok compromise ilk olarak **owner/mode/xattr/ACL drift** şeklinde ortaya çıkar.
- Mature bir intrusion'dan şüpheleniyorsanız ikisini de yapın: yeni activity için **real-time FIM** ve trusted media'dan bir **cold baseline comparison**.
- Saldırganın root veya kernel execution yetkisi varsa FIM agent'ının, veritabanının ve hatta event source'un değiştirilebileceğini varsayın. Log'ları ve baseline'ları mümkün olduğunda uzaktan veya read-only media üzerinde saklayın.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery ile File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux'ı Tracing: Bir file integrity monitoring kullanım senaryosu (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck ve whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
