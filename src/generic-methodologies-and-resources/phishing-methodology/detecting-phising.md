# Phishing Tespit Etme

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Bir phishing girişimini tespit etmek için **günümüzde kullanılan phishing tekniklerini anlamak** önemlidir. Bu gönderinin üst sayfasında bu bilgileri bulabilirsiniz; dolayısıyla bugün hangi tekniklerin kullanıldığından haberdar değilseniz üst sayfaya gitmenizi ve en azından ilgili bölümü okumanızı öneririm.

Bu gönderi, **saldırganların bir şekilde kurbanın domain adını taklit etmeye veya kullanmaya çalışacağı** fikrine dayanır. Domain'inizin adı `example.com` ise ve herhangi bir nedenle `youwonthelottery.com` gibi tamamen farklı bir domain adı kullanılarak phish edildiyseniz, bu teknikler bunu ortaya çıkarmayacaktır.

## Domain adı varyasyonları

E-posta içinde **benzer bir domain** adı kullanacak **phishing** girişimlerini **ortaya çıkarmak** oldukça **kolaydır**.\
Bir saldırganın kullanabileceği **en olası phishing adlarının bir listesini oluşturmak** ve bunların **kayıtlı olup olmadığını kontrol etmek** veya yalnızca bunlardan herhangi birini kullanan bir **IP** olup olmadığını kontrol etmek yeterlidir.

### Şüpheli domain'leri bulma

Bu amaçla aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Her ikisi de kullanımda olup olmadıklarını kontrol etmek için aday domain'leri çözümler.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

İpucu: Bir aday listesi oluşturursanız, saldırgan domain'i gerçekten kaydetmeden önce kullanıcıların bir typo'ya erişmeye çalıştığını tespit etmek için bu listeyi DNS resolver log'larınıza da aktarın (**kurumunuzun içinden gelen NXDOMAIN sorguları**). Politika izin veriyorsa bu domain'leri sinkhole edin veya önceden engelleyin.

### Bitflipping

**Kısa bir açıklama için üst sayfaya; birincil Windows.com bitsquatting araştırması için [Remy Hax'in yazısına](https://remyhax.xyz/posts/bitsquatting-windows/) ve [BleepingComputer'ın raporuna](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) bakın**.<sup>[[1]](#references)[[2]](#references)</sup>

Örneğin, microsoft.com domain'inde 1 bitlik bir değişiklik, domain'i _windnws.com._ biçimine dönüştürebilir.\
**Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek için kurbanla ilişkili mümkün olduğunca çok bit-flipping domain'i kaydedebilir**.<sup>[[1]](#references)[[2]](#references)</sup>

**Olası tüm bit-flipping domain adları da izlenmelidir.**

Homoglyph/IDN benzerlerini de (örneğin Latin/Kiril karakterlerinin karıştırılması) dikkate almanız gerekiyorsa şuraya bakın:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Temel kontroller

Olası şüpheli domain adlarının bir listesini oluşturduktan sonra, bunları (özellikle HTTP ve HTTPS portlarını) **kurbanın domain'indekilere benzer bir login formu kullanıp kullanmadıklarını görmek** için **kontrol etmelisiniz**.\
Ayrıca 3333 portunun açık olup olmadığını ve bir `gophish` instance'ının çalışıp çalışmadığını kontrol edebilirsiniz.\
**Tespit edilen her şüpheli domain'in ne kadar eski olduğunu** bilmek de ilginçtir; domain ne kadar yeniyse risk o kadar yüksektir.\
Şüpheli HTTP ve/veya HTTPS web sayfasının **ekran görüntülerini** alarak şüpheli olup olmadığını görebilir ve bu durumda **daha derinlemesine incelemek için erişebilirsiniz**.

### Gelişmiş kontroller

Bir adım daha ileri gitmek istiyorsanız, **bu şüpheli domain'leri izleyip zaman zaman yenilerini aramanızı** (her gün mü? yalnızca birkaç saniye/dakika sürer) öneririm. Ayrıca ilgili IP'lerin açık **portlarını kontrol etmeli** ve **`gophish` veya benzer araçların instance'larını aramalısınız** (evet, saldırganlar da hata yapar); ayrıca kurbanın web sayfalarındaki login formlarından herhangi birini kopyalayıp kopyalamadıklarını görmek için **şüpheli domain'lerin ve subdomain'lerin HTTP ve HTTPS web sayfalarını izlemelisiniz**.\
Bunu **otomatikleştirmek** için kurbanın domain'lerindeki login formlarının bir listesini oluşturmanızı, şüpheli web sayfalarını spider'lamanızı ve şüpheli domain'lerde bulunan her login formunu `ssdeep` gibi bir araç kullanarak kurbanın domain'indeki her login formuyla karşılaştırmanızı öneririm.\
Şüpheli domain'lerin login formlarını tespit ettiyseniz, **sahte kimlik bilgileri göndermeyi** ve **sizi kurbanın domain'ine yönlendirip yönlendirmediğini kontrol etmeyi** deneyebilirsiniz.

---

### Favicon ve web fingerprint'leriyle avcılık (Shodan/Censys)

Birçok phishing kiti, taklit ettikleri markaların favicon'larını yeniden kullanır. Shodan, base64 ile encode edilmiş favicon verilerini MurmurHash3 ile hash'ler; Censys ise kendi favicon hash alanlarını sunar.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan uyumlu bir hash oluşturabilir ve bunun üzerinden pivot edebilirsiniz:

Python örneği (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan'ı sorgulayın: `http.favicon.hash:309020573`
- Tooling ile: hash'leri hesaplamak ve Shodan dork'ları oluşturmak için favfreak gibi community tools'lara göz atın.<sup>[[16]](#references)</sup>

Notlar
- Favicon'lar yeniden kullanılır; eşleşmeleri lead olarak değerlendirin ve işlem yapmadan önce içeriği ve sertifikaları doğrulayın.
- Daha iyi hassasiyet için domain-age ve keyword heuristics'i birleştirin.

### URL telemetrisi avı (urlscan.io)

`urlscan.io`, gönderilen URL'lerin geçmiş screenshots, DOM, requests ve TLS metadata'sını depolar. Brand abuse ve clone'ları avlayabilirsiniz:<sup>[[8]](#references)</sup>

Örnek sorgular (UI veya API):
- Meşru domain'leriniz hariç lookalike'ları bulun: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Asset'lerinizi hotlinkleyen siteleri bulun: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Sonuçları yakın tarihlere göre sınırlayın: `AND date:>now-7d` ekleyin

API örneği:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON'dan şu alanlara göre pivot edin:
- Lookalike alan adları için çok yeni sertifikaları tespit etmek üzere `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`
- Bulguları CT monitoring ile ilişkilendirmek için `certstream-suspicious` gibi `task.source` değerleri

### RDAP ile domain age (scriptable)

RDAP, makine tarafından okunabilir registration events döndürür. **Yeni kaydedilmiş domain'leri (NRD'ler)** işaretlemek için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Pipeline'ınızı alan adlarını kayıt yaşı aralıklarıyla (ör. <7 gün, <30 gün) etiketleyerek zenginleştirin ve triage işlemlerini buna göre önceliklendirin.

### AiTM infrastructure'ını tespit etmek için TLS/JAx fingerprints

Credential-phishing, session token'larını çalmak için **Adversary-in-the-Middle (AiTM)** reverse proxy'leri (ör. Evilginx) kullanabilir.<sup>[[11]](#references)</sup> Network-side detection'lar ekleyebilirsiniz:

- Egress noktasında TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) kaydedin. Bazı Evilginx build'lerinin kararlı JA4 client/server değerleriyle gözlemlendiği olmuştur. Bilinen kötü fingerprints değerleri için yalnızca zayıf bir sinyal olarak alert üretin ve her zaman content ve domain intel ile doğrulayın.<sup>[[12]](#references)</sup>
- CT veya urlscan üzerinden keşfedilen lookalike host'lar için TLS certificate metadata'sını (issuer, SAN sayısı, wildcard kullanımı, geçerlilik) proaktif olarak kaydedin ve DNS yaşı ile geolocation bilgileriyle ilişkilendirin.

> Not: Fingerprints değerlerini tek başına blocker olarak değil, enrichment olarak değerlendirin; framework'ler gelişir ve değerleri randomise edebilir veya obfuscate edebilir.

### Keyword kullanan domain names

Parent page ayrıca, **victim'ın domain name'ini daha büyük bir domain içine yerleştirmekten** oluşan bir domain name variation tekniğinden bahseder (ör. paypal.com için paypal-financial.com).

#### Certificate Transparency

Certificate Transparency (CT) log'ları certificate identity'lerini açığa çıkarır; bu nedenle Subject veya SAN names alanlarında brand keyword'lerini aramak lookalike domain'leri ortaya çıkarabilir (örneğin, `paypal-financial.com` için bir certificate `paypal` keyword'ünü açığa çıkarır). Yararlı olduğunda sonuçları issuance date ve CA'ya göre filtreleyin ve keyword eşleşmeleri false positive olabileceğinden adayları doğrulayın.<sup>[[13]](#references)</sup>

Patrik Hudak'ın orijinal [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/)'ı, Let's Encrypt gibi certificate date ve issuer filtrelerini de içerecek şekilde bu workflow'u Censys'te gösterir.<sup>[[13]](#references)</sup>

![Lookalike domain'leri tespit etmek için kullanılan Censys certificate search sonuçları](<../../images/image (1115).png>)

Keyword aramak ve sonuçları date ile CA'ya göre filtrelemek için ücretsiz [**crt.sh**](https://crt.sh) service'ini de kullanabilirsiniz.<sup>[[13]](#references)</sup>

![Şüpheli certificate identity'lerini aramak için kullanılan crt.sh keyword search](<../../images/image (519).png>)

Matching Identities alanı, gerçek domain'deki identity'leri şüpheli domain'lerle karşılaştırmaya yardımcı olabilir; ancak eşleşmeleri kanıt değil, araştırma ipuçları olarak değerlendirin.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) CT güncellemelerini neredeyse gerçek zamanlı olarak stream eder ve [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) bu stream'i tüketerek şüpheli certificate names değerlerini skorlar.<sup>[[14]](#references)[[15]](#references)</sup>

Pratik ipucu: CT hit'lerini triage ederken NRD'lere, güvenilmeyen/bilinmeyen registrar'lara, privacy-proxy WHOIS'e ve çok yakın tarihli `NotBefore` zamanlarına sahip certificate'lara öncelik verin. Gürültüyü azaltmak için sahip olduğunuz domain'lerin/brand'lerin bir allowlist'ini tutun.

#### **New domains**

İkinci seçenek, TLD'ye göre yeni kayıt edilmiş domain'leri (örneğin [Whoxy](https://www.whoxy.com/newly-registered-domains/) aracılığıyla) toplamak ve brand keyword'lerine göre filtrelemektir. Bu yöntem, keyword registered domain'de bulunmadığında subdomain'lerde barındırılan phishing'i kaçırır.<sup>[[13]](#references)</sup>

Ek heuristic: belirli **file-extension TLD**'lerini (ör. `.zip`, `.mov`) alerting sırasında ekstra şüpheyle değerlendirin. Bunlar lure'larda sıklıkla filename'lerle karıştırılır; daha iyi precision için TLD sinyalini brand keyword'leri ve NRD yaşıyla birleştirin.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Bitflipping ile Microsoft'un windows.com trafiğini hijack etmek](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Derinlemesine inceleme: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol için JSON yanıtları](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token taktikleri: Cloud token hırsızlığını önleme, tespit etme ve buna yanıt verme](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing'i bulma: Araçlar ve teknikler](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream'i tanıtmak](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
