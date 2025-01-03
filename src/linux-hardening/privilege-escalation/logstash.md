{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash, **logları toplamak, dönüştürmek ve iletmek** için **pipeline** olarak bilinen bir sistem kullanır. Bu pipeline'lar **giriş**, **filtre** ve **çıkış** aşamalarından oluşur. Logstash'ın ele geçirilmiş bir makinede çalışması ilginç bir durum ortaya çıkarır.

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
Bu dosya, **.conf** dosyalarının, pipeline yapılandırmalarını içeren yerini ortaya koymaktadır. **Elasticsearch output module** kullanıldığında, **pipelines**'in genellikle **Elasticsearch kimlik bilgilerini** içerdiği yaygındır; bu kimlik bilgileri, Logstash'ın Elasticsearch'e veri yazma gereksinimi nedeniyle genellikle geniş yetkilere sahiptir. Yapılandırma yollarındaki joker karakterler, Logstash'ın belirlenen dizindeki tüm eşleşen pipeline'ları çalıştırmasına olanak tanır.

### Yazılabilir Pipeline'lar ile Yetki Yükseltme

Yetki yükseltme girişiminde bulunmak için, öncelikle Logstash hizmetinin çalıştığı kullanıcıyı belirleyin, genellikle **logstash** kullanıcısıdır. Aşağıdaki kriterlerden **birini** karşıladığınızdan emin olun:

- Bir pipeline **.conf** dosyasına **yazma erişiminiz** var **veya**
- **/etc/logstash/pipelines.yml** dosyası bir joker karakter kullanıyor ve hedef klasöre yazabiliyorsunuz

Ayrıca, **birini** karşılamanız gereken bu koşullardan biri de şudur:

- Logstash hizmetini yeniden başlatma yeteneği **veya**
- **/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarı var

Yapılandırmada bir joker karakter verildiğinde, bu joker karakterle eşleşen bir dosya oluşturmak, komut yürütmeye olanak tanır. Örneğin:
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
Burada, **interval** yürütme sıklığını saniye cinsinden belirler. Verilen örnekte, **whoami** komutu her 120 saniyede bir çalışır ve çıktısı **/tmp/output.log** dosyasına yönlendirilir.

**/etc/logstash/logstash.yml** dosyasında **config.reload.automatic: true** ayarı ile Logstash, yeni veya değiştirilmiş boru hattı yapılandırmalarını otomatik olarak algılayacak ve uygulayacaktır; yeniden başlatmaya gerek kalmadan. Eğer bir joker karakter yoksa, mevcut yapılandırmalarda değişiklikler yapılabilir, ancak kesintileri önlemek için dikkatli olunması önerilir.

## References

{{#include ../../banners/hacktricks-training.md}}
