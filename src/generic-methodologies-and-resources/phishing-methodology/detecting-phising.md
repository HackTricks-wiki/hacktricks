# Phishing Tespiti

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Bir phishing girişimini tespit etmek için **günümüzde kullanılan phishing tekniklerini anlamak** önemlidir. Bu gönderinin üst sayfasında bu bilgileri bulabilirsiniz; bu nedenle günümüzde hangi tekniklerin kullanıldığından haberdar değilseniz üst sayfaya gitmenizi ve en azından ilgili bölümü okumanızı öneririm.

Bu gönderi, **saldırganların bir şekilde kurbanın domain adını taklit etmeye veya kullanmaya çalışacağı** fikrine dayanır. Domain'inizin adı `example.com` ise ve herhangi bir nedenle `youwonthelottery.com` gibi tamamen farklı bir domain adı kullanılarak phish edildiyseniz, bu teknikler bunu ortaya çıkaramaz.

## Domain adı varyasyonları

E-posta içinde **benzer bir domain** adı kullanacak **phishing** girişimlerini **ortaya çıkarmak** oldukça **kolaydır**.\
Bir saldırganın kullanabileceği **en olası phishing adlarının bir listesini oluşturmak** ve bunların **kayıtlı olup olmadığını kontrol etmek** veya yalnızca bunlardan herhangi birini kullanan bir **IP** olup olmadığını kontrol etmek yeterlidir.

### Şüpheli domain'leri bulma

Bu amaçla aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Bu araçların, domain'e herhangi bir IP atanıp atanmadığını kontrol etmek için otomatik olarak DNS istekleri de gerçekleştireceğini unutmayın:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

İpucu: Bir aday listesi oluşturursanız, bunu DNS resolver log'larınıza da aktararak **kurumunuz içinden gelen NXDOMAIN sorgularını** (kullanıcıların, saldırgan gerçekten kaydetmeden önce bir typo'ya erişmeye çalışmasını) tespit edin. Politika izin veriyorsa bu domain'leri sinkhole'a yönlendirin veya önceden engelleyin.

### Bitflipping

**Bu tekniğin kısa bir açıklamasını üst sayfada bulabilirsiniz. Ya da orijinal araştırmayı** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup> **adresinde okuyabilirsiniz.**

Örneğin, microsoft.com domain'inde 1 bitlik bir değişiklik, domain'i _windnws.com._ haline dönüştürebilir.\
**Saldırganlar, meşru kullanıcıları kendi altyapılarına yönlendirmek için kurbanla ilişkili mümkün olduğunca çok bit-flipping domain'i kaydedebilir**.<sup>[[1]](#references)</sup>

**Olası tüm bit-flipping domain adları da izlenmelidir.**

Homoglyph/IDN benzerlerini de (ör. Latin/Kiril karakterlerinin karıştırılması) dikkate almanız gerekiyorsa şuraya bakın:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Temel kontroller

Olası şüpheli domain adlarının bir listesine sahip olduğunuzda, bunları (özellikle HTTP ve HTTPS portlarını) **kurbanın domain'indekilere benzer bir login formu kullanıp kullanmadıklarını görmek için kontrol etmelisiniz**.\
Açık olup olmadığını ve bir `gophish` instance'ı çalıştırıp çalıştırmadığını görmek için 3333 portunu da kontrol edebilirsiniz.\
**Keşfedilen her şüpheli domain'in ne kadar eski olduğunu** bilmek de ilginçtir; domain ne kadar yeniyse risk de o kadar yüksektir.\
Şüpheli HTTP ve/veya HTTPS web sayfasının **ekran görüntülerini** alarak şüpheli olup olmadığını görebilir ve bu durumda **daha ayrıntılı incelemek için erişebilirsiniz**.

### İleri düzey kontroller

Bir adım daha ileri gitmek istiyorsanız **bu şüpheli domain'leri izlemenizi ve zaman zaman daha fazlasını aramanızı** (her gün mü? yalnızca birkaç saniye/dakika sürer) öneririm. Ayrıca ilgili IP'lerin açık **port'larını kontrol etmeli**, **`gophish` instance'larını veya benzer araçları aramalı** (evet, saldırganlar da hata yapar) ve kurbanın web sayfalarındaki herhangi bir login formunu kopyalayıp kopyalamadıklarını görmek için **şüpheli domain'lerin ve subdomain'lerin HTTP ve HTTPS web sayfalarını izlemelisiniz**.\
Bunu **otomatikleştirmek** için kurbanın domain'lerindeki login formlarının bir listesini oluşturmanızı, şüpheli web sayfalarını spider'lamanızı ve şüpheli domain'lerde bulunan her login formunu `ssdeep` gibi bir araç kullanarak kurbanın domain'indeki her login formuyla karşılaştırmanızı öneririm.\
Şüpheli domain'lerin login formlarını tespit ettiyseniz, **sahte kimlik bilgileri göndermeyi** ve **sizi kurbanın domain'ine yönlendirip yönlendirmediğini kontrol etmeyi** deneyebilirsiniz.

---

### Favicon ve web fingerprint'leriyle avcılık (Shodan/ZoomEye/Censys)

Birçok phishing kiti, taklit ettikleri markaların favicon'larını yeniden kullanır. Internet genelindeki scanner'lar, base64 ile kodlanmış favicon'un MurmurHash3'ünü hesaplar. Hash'i oluşturabilir ve bunun üzerinden pivot edebilirsiniz:

Python örneği (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan'da sorgulayın: `http.favicon.hash:309020573`
- Tooling ile: Shodan/ZoomEye/Censys için hash'ler ve dork'lar oluşturmak üzere favfreak gibi community tool'larına göz atın.

Notlar
- Favicon'lar yeniden kullanılır; eşleşmeleri ipucu olarak değerlendirin ve harekete geçmeden önce içeriği ve sertifikaları doğrulayın.
- Daha iyi hassasiyet için domain-age ve keyword heuristics'i birleştirin.

### URL telemetry hunting (urlscan.io)

`urlscan.io`, gönderilen URL'lerin geçmiş ekran görüntülerini, DOM'unu, isteklerini ve TLS metadata'sını depolar. Brand abuse ve clone'ları arayabilirsiniz:<sup>[[2]](#references)</sup>

Örnek sorgular (UI veya API):
- Meşru domain'leriniz hariç lookalike'ları bulun: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Asset'lerinize hotlink veren siteleri bulun: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Sonuçları yenilerle sınırlayın: `AND date:>now-7d` ekleyin

API örneği:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON'dan şu alanlara göre pivot edin:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`: lookalike'lar için çok yeni sertifikaları tespit etmek üzere
- `task.source` değerleri (ör. `certstream-suspicious`): bulguları CT monitoring ile ilişkilendirmek üzere

### RDAP ile domain yaşı (betiklenebilir)

RDAP, makine tarafından okunabilir oluşturma olayları döndürür. **Yeni kaydedilmiş domain'leri (NRD'ler)** işaretlemek için kullanışlıdır.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Pipeline'ınızı domain'leri kayıt yaşı aralıklarıyla (ör. <7 gün, <30 gün) etiketleyerek zenginleştirin ve triage işlemlerini buna göre önceliklendirin.

### AiTM infrastructure'ını tespit etmek için TLS/JAx parmak izleri

Modern credential-phishing saldırıları, session token'larını çalmak için giderek daha fazla **Adversary-in-the-Middle (AiTM)** reverse proxy'leri (ör. Evilginx) kullanıyor. Network tarafında aşağıdaki detections'ları ekleyebilirsiniz:

- Egress noktasında TLS/HTTP parmak izlerini (JA3/JA4/JA4S/JA4H) loglayın. Bazı Evilginx build'lerinde kararlı JA4 client/server değerleri gözlemlenmiştir. Bilinen kötü parmak izleri için yalnızca zayıf bir sinyal olarak alert üretin ve her zaman content ile domain intel üzerinden doğrulayın.<sup>[[3]](#references)</sup>
- CT veya urlscan üzerinden keşfedilen lookalike host'lar için TLS certificate metadata'sını (issuer, SAN sayısı, wildcard kullanımı, geçerlilik) proaktif olarak kaydedin ve DNS yaşı ile geolocation bilgileriyle ilişkilendirin.

> Not: Parmak izlerini tek başına blocker olarak değil, enrichment olarak değerlendirin; framework'ler gelişir ve parmak izlerini randomise edebilir veya obfuscate edebilir.

### Keyword kullanan domain isimleri

Parent page ayrıca, **victim'ın domain adını daha büyük bir domain'in içine yerleştirmekten** oluşan bir domain name variation tekniğinden bahsediyor (ör. paypal.com için paypal-financial.com).

#### Certificate Transparency

Önceki "Brute-Force" yaklaşımını uygulamak mümkün değildir; ancak certificate transparency sayesinde bu tür **phishing girişimlerini ortaya çıkarmak mümkündür**. Bir CA tarafından certificate emit edildiğinde, ayrıntıları public hale gelir. Bu, certificate transparency'yi okuyarak veya izleyerek **adında bir keyword kullanan domain'leri bulmanın mümkün olduğu** anlamına gelir. Örneğin bir attacker [https://paypal-financial.com](https://paypal-financial.com) için bir certificate oluşturursa, certificate'i inceleyerek "paypal" keyword'ünü bulmak ve suspicious email'in kullanıldığını anlamak mümkündür.

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) post'u, belirli bir keyword'ü etkileyen certificate'leri aramak ve sonuçları tarihe göre (yalnızca "new" certificate'ler) ve CA issuer'ı "Let's Encrypt" olacak şekilde filtrelemek için Censys kullanabileceğinizi öne sürüyor:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Ancak ücretsiz web sitesi [**crt.sh**](https://crt.sh) üzerinden "aynı şeyi" yapabilirsiniz. **Keyword'ü arayabilir** ve isterseniz sonuçları **tarihe ve CA'ya göre filtreleyebilirsiniz**.

![Domain names using keywords - Certificate Transparency: However, you can do "the same" using the free web crt.sh . You can search for the keyword and the filter the results by date and...](<../../images/image (519).png>)

Bu son seçeneği kullanarak, gerçek domain'deki herhangi bir identity'nin suspicious domain'lerden biriyle eşleşip eşleşmediğini görmek için Matching Identities alanını da kullanabilirsiniz (suspicious bir domain'in false positive olabileceğini unutmayın).

**Bir başka alternatif**, [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) adlı harika project'tir. CertStream, belirli keyword'leri (neredeyse) real-time olarak tespit etmek için kullanabileceğiniz, yeni oluşturulan certificate'lerin real-time stream'ini sağlar. Hatta tam olarak bunu yapan [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) adlı bir project vardır.

Practical tip: CT hit'lerini triage ederken NRD'lere, güvenilmeyen/bilinmeyen registrar'lara, privacy-proxy WHOIS bilgilerine ve `NotBefore` zamanları çok yakın olan cert'lere öncelik verin. Gürültüyü azaltmak için sahip olduğunuz domain'ler ve brand'ler için bir allowlist tutun.

#### **New domain'ler**

**Son bir alternatif**, bazı TLD'ler için **newly registered domain'lerin** listesini toplamak ([Whoxy](https://www.whoxy.com/newly-registered-domains/) böyle bir service sağlar) ve bu domain'lerdeki **keyword'leri kontrol etmektir**. Ancak uzun domain'ler genellikle bir veya daha fazla subdomain kullanır; bu nedenle keyword FLD'nin içinde görünmez ve phishing subdomain'ini bulamazsınız.

Additional heuristic: belirli **file-extension TLD'lerini** (ör. `.zip`, `.mov`) alerting sırasında ekstra şüpheli olarak değerlendirin. Bunlar lure'larda genellikle filename'lerle karıştırılır; daha iyi precision için TLD sinyalini brand keyword'leri ve NRD yaşıyla birleştirin.

## References

- [1] [Bitflipping ile Microsoft'un windows.com trafiğini hijack etmek](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Phishing'i bulma: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
