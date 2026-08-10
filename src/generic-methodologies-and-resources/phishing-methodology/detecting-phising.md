# Phishing Tespit Etme

## Giriş

Bir phishing girişimini tespit etmek için **günümüzde kullanılan phishing tekniklerini anlamak** önemlidir. Bu yazının parent page'inde bu bilgileri bulabilirsiniz; bu tekniklerin bugün hangileri olduğunun farkında değilseniz parent page'e gidip en azından ilgili bölümü okumanızı öneririm.

Bu yazı, **saldırganların bir şekilde kurbanın domain adını taklit etmeye veya kullanmaya çalışacağı** fikrine dayanır. Domain'inizin adı `example.com` ise ve herhangi bir nedenle `youwonthelottery.com` gibi tamamen farklı bir domain adı kullanılarak phish edildiyseniz, bu teknikler bunu ortaya çıkaramaz.

## Domain adı varyasyonları

E-postada **benzer bir domain** adı kullanacak **phishing** girişimlerini **ortaya çıkarmak** oldukça **kolaydır**.\
Saldırganın kullanabileceği **en olası phishing adlarının bir listesini oluşturmak** ve bunların **kayıtlı** olup olmadığını **kontrol etmek** ya da yalnızca bunlardan herhangi birini kullanan bir **IP** olup olmadığını kontrol etmek yeterlidir.

### Şüpheli domain'leri bulma

Bu amaçla aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Her ikisi de kullanımda olup olmadıklarını kontrol etmek için aday domain'leri resolve eder.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

İpucu: Bir aday listesi oluşturursanız, bunu DNS resolver log'larınıza da göndererek **kurumunuzun içinden gelen NXDOMAIN lookup'larını** tespit edin (kullanıcıların, saldırgan gerçekten kaydetmeden önce bir typo'ya erişmeye çalışması). Politikanız izin veriyorsa bu domain'leri sinkhole edin veya önceden engelleyin.

### Bitflipping

**Kısa bir açıklama için parent page'e, birincil Windows.com bitsquatting araştırması için ise [Remy Hax'in yazısına](https://remyhax.xyz/posts/bitsquatting-windows/) ve [BleepingComputer'ın raporuna](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) bakabilirsiniz**.<sup>[[1]](#references)[[2]](#references)</sup>

Örneğin, microsoft.com domain'inde yapılan 1 bitlik bir değişiklik onu _windnws.com_ haline dönüştürebilir.\
**Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek için kurbanla ilişkili mümkün olduğunca çok bit-flipping domain'i kaydetmeye çalışabilir**.<sup>[[1]](#references)[[2]](#references)</sup>

**Olası tüm bit-flipping domain adları da izlenmelidir.**

Homoglyph/IDN benzerliklerini de (ör. Latin/Kiril karakterlerinin karıştırılması) dikkate almanız gerekiyorsa şuraya bakın:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Temel kontroller

Potansiyel şüpheli domain adlarının bir listesini oluşturduktan sonra, bunları **kontrol ederek** (özellikle HTTP ve HTTPS portlarını) **kurbanın domain'indekine benzer bir login formu kullanıp kullanmadıklarını görmelisiniz**.\
Ayrıca 3333 numaralı portu kontrol ederek açık olup olmadığını ve bir `gophish` instance'ı çalıştırıp çalıştırmadığını görebilirsiniz.\
**Keşfedilen her şüpheli domain'in ne kadar eski olduğunu** bilmek de ilginçtir; domain ne kadar yeniyse risk de o kadar yüksektir.\
Şüpheli HTTP ve/veya HTTPS web sayfasının **screenshots**'larını alarak şüpheli olup olmadığını görebilir ve bu durumda **daha ayrıntılı incelemek için erişebilirsiniz**.

### İleri düzey kontroller

Bir adım daha ileri gitmek istiyorsanız **bu şüpheli domain'leri izlemenizi ve arada bir (her gün mü? yalnızca birkaç saniye/dakika sürer) yenilerini aramanızı** öneririm. Ayrıca ilişkili IP'lerin açık **port'larını kontrol etmeli**, **`gophish` veya benzer araç instance'larını aramalı** (evet, saldırganlar da hata yapar) ve kurbanın web sayfalarından herhangi bir login formunu kopyalayıp kopyalamadıklarını görmek için **şüpheli domain ve subdomain'lerin HTTP ve HTTPS web sayfalarını izlemelisiniz**.\
Bunu **otomatikleştirmek** için kurbanın domain'lerindeki login formlarının bir listesini oluşturmanızı, şüpheli web sayfalarını spider'lamanızı ve şüpheli domain'lerde bulunan her login formunu `ssdeep` gibi bir araç kullanarak kurbanın domain'indeki her login formuyla karşılaştırmanızı öneririm.\
Şüpheli domain'lerin login formlarını tespit ettiyseniz, **junk credentials göndermeyi** ve **sizi kurbanın domain'ine yönlendirip yönlendirmediğini kontrol etmeyi** deneyebilirsiniz.

---

### Favicon ve web fingerprint'leriyle hunting (Shodan/Censys)

Birçok phishing kiti, taklit ettikleri markanın favicon'larını yeniden kullanır. Shodan, base64-encoded favicon verilerini MurmurHash3 ile hash'lerken Censys kendi favicon hash alanlarını sunar.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan uyumlu bir hash oluşturup bunun üzerinden pivot edebilirsiniz:

Python örneği (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan'ı sorgula: `http.favicon.hash:309020573`
- Tooling kullanarak: hash'leri hesaplamak ve Shodan dork'ları oluşturmak için favfreak gibi community tools'lara göz atın.<sup>[[16]](#references)</sup>

Notlar
- Favicon'lar yeniden kullanılır; eşleşmeleri ipucu olarak değerlendirin ve harekete geçmeden önce içeriği ve sertifikaları doğrulayın.
- Daha iyi hassasiyet için domain-age ve keyword heuristics'i birleştirin.

### URL telemetry hunting (urlscan.io)

`urlscan.io`, gönderilen URL'lerin geçmiş ekran görüntülerini, DOM'unu, isteklerini ve TLS metadata'sını depolar. Brand abuse ve clone'ları avlayabilirsiniz:<sup>[[8]](#references)</sup>

Örnek sorgular (UI veya API):
- Meşru domain'lerinizi hariç tutarak lookalike'ları bulun: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Asset'lerinizi hotlink eden siteleri bulun: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Sonuçları yakın tarihle sınırlayın: `AND date:>now-7d` ekleyin

API örneği:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON'dan şu alanları pivot noktası olarak kullanın:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` alanlarını kullanarak lookalike domain'ler için çok yeni sertifikaları tespit edin
- Bulguları CT monitoring ile ilişkilendirmek için `certstream-suspicious` gibi `task.source` değerlerini kullanın

### RDAP üzerinden domain yaşı (script ile kullanılabilir)

RDAP, makine tarafından okunabilir registration event'leri döndürür. **Yeni kaydedilmiş domain'leri (NRD'ler)** işaretlemek için kullanışlıdır.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Alan adlarını kayıt yaş gruplarıyla (ör. <7 gün, <30 gün) etiketleyerek pipeline'ınızı zenginleştirin ve triage işlemlerini buna göre önceliklendirin.

### AiTM altyapısını tespit etmek için TLS/JAx parmak izleri

Credential-phishing, oturum token'larını çalmak için **Adversary-in-the-Middle (AiTM)** reverse proxy'lerini (ör. Evilginx) kullanabilir.<sup>[[11]](#references)</sup> Ağ tarafında aşağıdaki tespitleri ekleyebilirsiniz:

- Egress noktasında TLS/HTTP parmak izlerini (JA3/JA4/JA4S/JA4H) loglayın. Bazı Evilginx build'lerinin sabit JA4 client/server değerleriyle gözlemlendiği olmuştur. Bilinen kötü parmak izleri için yalnızca zayıf bir sinyal olarak alarm üretin ve her zaman content ve domain intel ile doğrulayın.<sup>[[12]](#references)</sup>
- CT veya urlscan üzerinden keşfedilen lookalike host'lar için TLS certificate metadata'sını (issuer, SAN sayısı, wildcard kullanımı, geçerlilik) proaktif olarak kaydedin ve DNS yaşı ile geolocation bilgileriyle ilişkilendirin.

> Not: Parmak izlerini tek başına blocker olarak değil, enrichment olarak değerlendirin; framework'ler gelişir ve parmak izlerini randomise edebilir veya obfuscate edebilir.

### Anahtar kelimeler kullanan domain adları

Parent page ayrıca, **victim'ın domain adını daha büyük bir domain'in içine yerleştirmekten** oluşan bir domain name variation tekniğinden bahseder (ör. paypal.com için paypal-financial.com).

#### Certificate Transparency

Certificate Transparency (CT) log'ları certificate identity'lerini açığa çıkarır; bu nedenle Subject veya SAN adlarında brand keyword'lerini aramak lookalike domain'leri ortaya çıkarabilir (örneğin, `paypal-financial.com` için bir certificate `paypal` keyword'ünü açığa çıkarır). Gerektiğinde sonuçları issuance date ve CA'ya göre filtreleyin ve keyword eşleşmeleri false positive olabileceğinden adayları doğrulayın.<sup>[[13]](#references)</sup>

Patrik Hudak'ın orijinal [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/), certificate date ve Let's Encrypt gibi issuer filtreleri de dahil olmak üzere bu workflow'u Censys'te gösterir.<sup>[[13]](#references)</sup>

Keyword aramak ve sonuçları date ile CA'ya göre filtrelemek için ücretsiz [**crt.sh**](https://crt.sh) service'ini de kullanabilirsiniz.<sup>[[13]](#references)</sup>

Matching Identities alanı, gerçek domain'deki identity'leri şüpheli domain'lerle karşılaştırmaya yardımcı olabilir; ancak eşleşmeleri kanıt değil, araştırma ipucu olarak değerlendirin.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067), CT update'lerini neredeyse gerçek zamanlı olarak stream eder ve [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) şüpheli certificate adlarını skorlamak için bu stream'i tüketir.<sup>[[14]](#references)[[15]](#references)</sup>

Pratik ipucu: CT hit'lerini triage ederken NRD'lere, güvenilmeyen/bilinmeyen registrar'lara, privacy-proxy WHOIS'e ve `NotBefore` zamanı çok yakın olan certificate'lara öncelik verin. Gürültüyü azaltmak için sahip olduğunuz domain ve brand'lerin allowlist'ini yönetin.

#### **Yeni domain'ler**

İkinci bir seçenek, TLD'ye göre yeni kaydedilmiş domain'leri (örneğin [Whoxy](https://www.whoxy.com/newly-registered-domains/) aracılığıyla) toplamak ve brand keyword'lerine göre filtrelemektir. Bu yöntem, keyword registered domain'de bulunmadığında subdomain'lerde barındırılan phishing'i kaçırır.<sup>[[13]](#references)</sup>

Ek heuristic: belirli **file-extension TLD**'lerini (ör. `.zip`, `.mov`) alerting sırasında daha şüpheli olarak değerlendirin. Bunlar lure'larda sıklıkla filename sanılır; daha iyi precision için TLD sinyalini brand keyword'leri ve NRD yaşıyla birleştirin.

## References

- [1] [Remy Hax – Windows.com üzerinde Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Bitflipping ile Microsoft'un windows.com trafiğini ele geçirme](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Derinlemesine inceleme: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol için JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token taktikleri: cloud token theft nasıl önlenir, tespit edilir ve buna nasıl yanıt verilir](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing bulma: Araçlar ve teknikler](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream'i tanıtıyoruz](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
