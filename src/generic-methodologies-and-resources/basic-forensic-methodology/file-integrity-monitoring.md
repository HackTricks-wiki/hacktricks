# Dosya Bütünlüğü İzleme

{{#include ../../banners/hacktricks-training.md}}

## Temel durum

Bir temel durum, sistemin belirli bölümlerinin bir anlık görüntüsünün alınmasını ve **gelecekteki bir durumla karşılaştırılarak değişikliklerin vurgulanmasını** içerir.

Örneğin, hangi dosyaların değiştirildiğini tespit edebilmek için dosya sistemindeki her dosyanın hash'ini hesaplayıp saklayabilirsiniz.\
Bu, oluşturulan kullanıcı hesapları, çalışan işlemler, çalışan servisler ve çok değişmemesi gereken veya hiç değişmemesi gereken diğer öğeler için de yapılabilir.

Bir **kullanışlı temel durum**, genellikle sadece bir özetten daha fazlasını saklar: izinler, sahip, grup, zaman damgaları, inode, symlink hedefi, ACL'ler ve seçilmiş genişletilmiş öznitelikler de izlemeye değerdir. Saldırgan avcılığı açısından bu, içerik hash'i ilk değişen şey olmasa bile **yalnızca izinlerle oynama**, **atomik dosya değiştirme** ve **değiştirilmiş servis/unit dosyaları üzerinden kalıcılık** gibi durumları tespit etmeye yardımcı olur.

### File Integrity Monitoring

File Integrity Monitoring (FIM), dosyalardaki değişiklikleri izleyerek BT ortamlarını ve verileri koruyan kritik bir güvenlik tekniğidir. Genellikle şu öğeleri birleştirir:

1. **Temel durum karşılaştırması:** Gelecekteki karşılaştırmalar için metadata ve kriptografik checksum'ları saklayın (`SHA-256` veya daha iyisi tercih edilir).
2. **Gerçek zamanlı bildirimler:** Hangi dosyanın, ne zaman ve ideal olarak hangi süreç/kullanıcı tarafından değiştirildiğini bilmek için OS-native dosya olaylarına abone olun.
3. **Periyodik yeniden tarama:** Yeniden başlatmalardan, düşen olaylardan, agent kesintilerinden veya kasıtlı anti-adli faaliyetlerden sonra güveni yeniden inşa edin.

Tehdit avcılığı için, FIM genellikle şu gibi **yüksek öncelikli yollar** üzerinde odaklandığında daha faydalıdır:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Gerçek Zamanlı Arka Uçlar & Kör Noktalar

### Linux

Toplama altyapısı önemlidir:

- **`inotify` / `fsnotify`**: kolay ve yaygın, ancak watch limitleri tükenebilir ve bazı kenar durumlar atlanır.
- **`auditd` / audit framework`**: **dosyayı kimin değiştirdiğini** (`auid`, process, pid, executable) bilmeniz gerektiğinde daha iyidir.
- **`eBPF` / `kprobes`**: modern FIM yığınlarının olayları zenginleştirmek ve düz `inotify` dağıtımlarının operasyonel bazı zorluklarını azaltmak için kullandığı daha yeni seçeneklerdir.

Bazı pratik tuzaklar:

- Bir program dosyayı `write temp -> rename` ile **değiştirirse**, dosyanın kendisini izlemek kullanışlılığı yitirebilir. **Sadece dosyayı değil ebeveyn dizini izle**.
- `inotify`-tabanlı toplayıcılar **büyük dizin ağaçlarında**, **hard-link etkinliğinde** veya bir **izlenen dosya silindikten sonra** kaçırabilir veya bozulabilir.
- Çok büyük özyinelemeli watch set'leri, `fs.inotify.max_user_watches`, `max_user_instances` veya `max_queued_events` çok düşükse sessizce başarısız olabilir.
- Ağ dosya sistemleri, düşük-gürültülü izleme için genellikle kötü FIM hedefleridir.

AIDE ile örnek temel durum ve doğrulama:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Saldırgan kalıcılık yollarına odaklanan örnek `osquery` FIM yapılandırması:
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
Eğer yalnızca yol düzeyindeki değişiklikler yerine **proses kaynak ataması** gerekiyorsa, `osquery` `process_file_events` veya Wazuh `whodata` modu gibi denetim tabanlı telemetriyi tercih edin.

### Windows

Windows'ta, **değişiklik günlükleri** ile **yüksek sinyal veren işlem/dosya telemetrisi**'ni birleştirdiğinizde FIM daha güçlü olur:

- **NTFS USN Journal**, dosya değişikliklerinin her birim için kalıcı bir günlük kaydını sağlar.
- **Sysmon Event ID 11**, dosya oluşturma/üstüne yazma için yararlıdır.
- **Sysmon Event ID 2**, **timestomping**'i tespit etmeye yardımcı olur.
- **Sysmon Event ID 15**, `Zone.Identifier` veya gizli payload akışları gibi **named alternate data streams (ADS)** için faydalıdır.

Hızlı USN triage örnekleri:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Daha derin anti-adli fikirler için **timestamp manipulation**, **ADS abuse**, ve **USN tampering** konularına bakın: [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Konteynerler

Konteyner FIM genellikle gerçek yazma yolunu kaçırır. Docker `overlay2` ile değişiklikler, salt okunur imaj katmanlarına değil, konteynerin **yazılabilir üst katmanına** (`upperdir`/`diff`) işlenir. Bu nedenle:

- Kısa ömürlü bir konteynerin içinden **yalnızca** yolları izlemek, konteyner yeniden oluşturulduktan sonra yapılan değişiklikleri kaçırabilir.
- Yazılabilir katmanı destekleyen ana makine yolunu veya ilgili bind-mounted volume'u izlemek genellikle daha faydalıdır.
- İmaj katmanları üzerinde yapılan FIM, çalışan konteyner dosya sistemi üzerindeki FIM'den farklıdır.

## Saldırgana Yönelik Avlama Notları

- **service definitions** ve **task schedulers**'ı ikili dosyalar kadar dikkatle izleyin. Saldırganlar genellikle `/bin/sshd`'yi yama yapmak yerine bir unit file'ı, cron entry'yi veya task XML'i değiştirerek kalıcılık sağlarlar.
- Yalnızca içerik hash'i yeterli değildir. Birçok ihlal önce **owner/mode/xattr/ACL drift** olarak ortaya çıkar.
- Olgun bir ihlalden şüpheleniyorsanız, her ikisini yapın: yeni aktiviteler için **real-time FIM** ve güvenilir medyadan alınmış bir **cold baseline comparison**.
- Saldırganın root veya kernel düzeyinde kod çalıştırabildiğinden şüpheleniyorsanız, FIM agent'ının, veritabanının ve hatta olay kaynağının değiştirilebileceğini varsayın. Kayıtları ve baseline'ları mümkünse uzakta veya salt okunur medyada saklayın.

## Araçlar

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referanslar

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
