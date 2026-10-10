# Phishing'i Tespit Etme

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Bir phishing girişimini tespit etmek için **günümüzde kullanılan phishing tekniklerini anlamak önemlidir**. Bu yazının üst sayfasında bu bilgileri bulabilirsiniz; dolayısıyla bugün hangi tekniklerin kullanıldığından haberdar değilseniz üst sayfaya gidip en azından o bölümü okumanızı öneririm.

Bu yazı, **saldırganların bir şekilde kurbanın domain adını taklit etmeye veya kullanmaya çalışacağı** fikrine dayanır. Domain adınız `example.com` ise ve herhangi bir nedenle `youwonthelottery.com` gibi tamamen farklı bir domain adı kullanılarak phishing saldırısına uğruyorsanız bu teknikler bunu ortaya çıkarmaz.

## Domain adı varyasyonları

E-posta içinde **benzer bir domain adı** kullanacak **phishing** girişimlerini **ortaya çıkarmak** oldukça **kolaydır**.\
Bir saldırganın kullanabileceği en olası phishing adlarının listesini **oluşturup** bunların **kayıtlı olup olmadığını** veya bunlardan herhangi birini kullanan bir **IP** bulunup bulunmadığını kontrol etmek yeterlidir.

### Şüpheli domain'leri bulma

Bu amaçla aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Her ikisi de kullanımda olup olmadıklarını kontrol etmek için aday domain'leri çözümler.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

İpucu: Aday bir liste oluşturursanız, saldırgan domain'i kaydetmeden önce kullanıcıların yazım hatası içeren bir adrese erişmeye çalıştığını tespit etmek için bu listeyi DNS resolver log'larınıza da aktarın; böylece kurum içinden gelen **NXDOMAIN sorgularını** algılayabilirsiniz. Politikanız izin veriyorsa bu domain'leri sinkhole'a yönlendirin veya önceden engelleyin.

### Bitflipping

**Kısa bir açıklama için üst sayfaya bakın; Windows.com bitsquatting araştırmasının ilk kaynağı için [Remy Hax'in yazısına](https://remyhax.xyz/posts/bitsquatting-windows/) ve [BleepingComputer'ın haberine](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) bakın**.<sup>[[1]](#references)[[2]](#references)</sup>

Örneğin, microsoft.com domain'inde 1 bitlik bir değişiklik, onu _windnws.com._ biçimine dönüştürebilir.\
**Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek için kurbanla ilgili mümkün olduğunca çok bit-flipping domain'i kaydedebilir**.<sup>[[1]](#references)[[2]](#references)</sup>

**Olası tüm bit-flipping domain adları da izlenmelidir.**

Homoglyph/IDN benzerlerini de (ör. Latin/Kiril karakterlerini karıştırma) hesaba katmanız gerekiyorsa şuraya bakın:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Temel kontroller

Olası şüpheli domain adlarının listesini oluşturduktan sonra, bunların HTTP ve HTTPS portlarını kontrol ederek kurbanın domain'indeki birine benzeyen bir login formu kullanıp kullanmadıklarını görmelisiniz.\
Ayrıca 3333 portunun açık olup olmadığını ve bir `gophish` örneğinin çalışıp çalışmadığını kontrol edebilirsiniz.\
Bulunan şüpheli domain'lerin her birinin ne kadar eski olduğunu bilmek de yararlıdır; domain ne kadar yeniyse risk o kadar yüksektir.\
Şüpheli HTTP ve/veya HTTPS web sayfalarının **ekran görüntülerini** alarak şüpheli olup olmadıklarını görebilir, şüpheli olmaları durumunda **daha yakından incelemek için erişebilirsiniz**.

### Gelişmiş kontroller

Bir adım daha ileri gitmek istiyorsanız bu şüpheli domain'leri izleyip ara sıra (her gün mü? bu yalnızca birkaç saniye/dakika sürer) yenilerini aramanızı öneririm. İlgili IP'lerin açık **portlarını** kontrol etmeli, `gophish` örneklerini veya benzer araçları aramalı (evet, saldırganlar da hata yapar) ve kurbanın web sayfalarındaki login form'larını kopyalayıp kopyalamadıklarını görmek için şüpheli domain ve subdomain'lerin HTTP ve HTTPS web sayfalarını izlemelisiniz.\
Bunu **otomatikleştirmek** için kurbanın domain'lerindeki login form'larının bir listesini oluşturmanızı, şüpheli web sayfalarını spider ile taramanızı ve şüpheli domain'lerde bulunan her login form'unu `ssdeep` gibi bir araç kullanarak kurbanın domain'indeki her login form'uyla karşılaştırmanızı öneririm.\
Şüpheli domain'lerdeki login form'larını bulduysanız, **sahte kimlik bilgileri göndermeyi** deneyebilir ve sizi kurbanın domain'ine yönlendirip yönlendirmediğini **kontrol edebilirsiniz**.

---

### Favicon ve web fingerprint'leriyle avlama (Shodan/Censys)

Birçok phishing kiti, taklit ettikleri markanın favicon'larını yeniden kullanır. Shodan, base64 ile kodlanmış favicon verisinin hash'ini MurmurHash3 ile alırken Censys kendi favicon hash alanlarını sunar.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan ile uyumlu bir hash oluşturup bunun üzerinden arama yapabilirsiniz:

Python örneği (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Shodan'da sorgulayın: `http.favicon.hash:309020573`
- Araçlarla: Hash'leri hesaplamak ve Shodan dork'ları oluşturmak için favfreak gibi topluluk araçlarına göz atın.<sup>[[16]](#references)</sup>

Notlar
- Favicon'lar yeniden kullanılır; eşleşmeleri ipucu olarak değerlendirin ve harekete geçmeden önce içeriği ve sertifikaları doğrulayın.
- Daha iyi hassasiyet için domain yaşı ve anahtar kelime sezgisel yöntemleriyle birleştirin.

### URL telemetrisinde avlanma (urlscan.io)

`urlscan.io`, gönderilen URL'lerin geçmiş ekran görüntülerini, DOM'unu, isteklerini ve TLS meta verilerini saklar. Marka suistimali ve klon siteleri araştırabilirsiniz:<sup>[[8]](#references)</sup>

Örnek sorgular (UI veya API):
- Meşru domain'lerinizi hariç tutarak benzerlerini bulun: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Varlıklarınıza hotlink veren siteleri bulun: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Sonuçları yakın tarihtekilerle sınırlayın: `AND date:>now-7d` ekleyin

API örneği:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

JSON'dan şunlara göre pivot yapın:
- Benzer alan adlarına ait çok yeni sertifikaları tespit etmek için `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`
- Bulguları CT izlemeyle ilişkilendirmek için `certstream-suspicious` gibi `task.source` değerleri

### RDAP üzerinden alan adı yaşı (komut dosyasıyla kullanılabilir)

RDAP, makine tarafından okunabilir kayıt olayları döndürür. **Yeni kaydedilmiş alan adlarını (NRD'ler)** işaretlemek için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Alan adlarını kayıt yaşı aralıklarıyla (ör. <7 gün, <30 gün) etiketleyerek iş akışınızı zenginleştirin ve önceliklendirmeyi buna göre yapın.

### AiTM altyapısını tespit etmek için TLS/JAx parmak izleri

Kimlik bilgilerini çalmaya yönelik phishing saldırılarında oturum token'larını çalmak için **Adversary-in-the-Middle (AiTM)** reverse proxy'leri (ör. Evilginx) kullanılabilir.<sup>[[11]](#references)</sup> Ağ tarafında tespitler ekleyebilirsiniz:

- Egress trafiğinde TLS/HTTP parmak izlerini (JA3/JA4/JA4S/JA4H) kaydedin. Bazı Evilginx derlemelerinin tutarlı JA4 istemci/sunucu değerleri kullandığı gözlemlenmiştir. Bilinen kötü parmak izleri için uyarı oluşturun, ancak bunları yalnızca zayıf bir sinyal olarak değerlendirin ve her zaman içerik ve alan adı istihbaratıyla doğrulayın.<sup>[[12]](#references)</sup>
- CT veya urlscan aracılığıyla keşfedilen benzer görünümlü sunucular için TLS sertifika meta verilerini (veren, SAN sayısı, wildcard kullanımı, geçerlilik) proaktif olarak kaydedin ve DNS yaşı ile coğrafi konum bilgileriyle ilişkilendirin.

> Not: Parmak izlerini tek başına engelleme gerekçesi olarak değil, zenginleştirme amacıyla değerlendirin; framework'ler gelişir, parmak izleri rastgeleleştirilebilir veya gizlenebilir.

### Anahtar kelimeler içeren alan adları

Üst sayfada ayrıca, **kurbanın alan adını daha büyük bir alan adının içine yerleştirme** tekniğinden de bahsediliyor (ör. paypal.com için paypal-financial.com).

#### Certificate Transparency

Certificate Transparency (CT) günlükleri sertifika kimliklerini açığa çıkarır. Bu nedenle Subject veya SAN adlarında marka anahtar kelimelerini aramak, benzer görünümlü alan adlarını ortaya çıkarabilir (örneğin, `paypal-financial.com` için bir sertifikada `paypal` anahtar kelimesi bulunur). Gerekirse sonuçları düzenlenme tarihine ve CA'ya göre filtreleyin; anahtar kelime eşleşmeleri yanlış pozitif olabileceğinden adayları doğrulayın.<sup>[[13]](#references)</sup>

Patrik Hudak'ın özgün [phishing alan adlarını avlama yazısı](https://0xpatrik.com/phishing-domains/), Let's Encrypt gibi sertifika tarihi ve veren filtreleri de dahil olmak üzere, Censys'teki bu iş akışını gösteriyor.<sup>[[13]](#references)</sup>

![Benzer görünümlü alan adlarını belirlemek için kullanılan Censys sertifika arama sonuçları](<../../images/image (1115).png>)

Anahtar kelime aramak ve sonuçları tarihe ve CA'ya göre filtrelemek için ücretsiz [**crt.sh**](https://crt.sh) hizmetini de kullanabilirsiniz.<sup>[[13]](#references)</sup>

![Şüpheli sertifika kimlikleri için crt.sh anahtar kelime araması](<../../images/image (519).png>)

Matching Identities alanı, gerçek alan adındaki kimliklerle şüpheli alan adlarındaki kimlikleri karşılaştırmaya yardımcı olabilir; ancak eşleşmeleri kanıt değil, araştırma ipucu olarak değerlendirin.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067), CT güncellemelerini neredeyse gerçek zamanlı olarak aktarır; [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) ise bu akışı kullanarak şüpheli sertifika adlarına puan verir.<sup>[[14]](#references)[[15]](#references)</sup>

Pratik ipucu: CT sonuçlarını incelerken NRD'lere, güvenilmeyen/bilinmeyen kayıt operatörlerine, gizlilik proxy'si kullanan WHOIS kayıtlarına ve `NotBefore` zamanı çok yakın olan sertifikalara öncelik verin. Gürültüyü azaltmak için sahip olduğunuz alan adları/markalar için bir izin listesi tutun.

#### **Yeni alan adları**

İkinci bir seçenek, TLD'ye göre yeni kaydedilen alan adlarını (örneğin [Whoxy](https://www.whoxy.com/newly-registered-domains/) aracılığıyla) toplayıp marka anahtar kelimelerine göre filtrelemektir. Bu yöntem, anahtar kelimenin kayıtlı alan adında bulunmadığı durumlarda alt alan adlarında barındırılan phishing saldırılarını kaçırır.<sup>[[13]](#references)</sup>

Ek sezgisel yöntem: belirli **dosya uzantısı biçimindeki TLD'leri** (ör. `.zip`, `.mov`) uyarılarda daha şüpheli değerlendirin. Bunlar oltalama mesajlarında sıklıkla dosya adlarıyla karıştırılır; daha isabetli sonuçlar için TLD sinyalini marka anahtar kelimeleri ve NRD yaşıyla birleştirin.

## References

- [1] [Remy Hax – Windows.com'da Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Bit flipping ile Microsoft'un windows.com trafiğini ele geçirme](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Derinlemesine inceleme: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 belgeleri](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property veri kümesi](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API başvuru kılavuzu](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol yardım sayfası](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol için JSON yanıtları](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token taktikleri: Bulut token hırsızlığını önleme, tespit etme ve buna müdahale etme](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ ağ parmak izi oluşturma](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing'i bulma: Araçlar ve teknikler](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream'i tanıtıyoruz](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
