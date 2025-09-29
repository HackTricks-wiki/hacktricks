# Phishing Tespiti

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Bir phishing denemesini tespit etmek için günümüzde kullanılan phishing tekniklerini **anlamak** önemlidir. Bu yazının üst sayfasında bu bilgiyi bulabilirsiniz; bugün hangi tekniklerin kullanıldığından haberdar değilseniz, üst sayfaya gidip en azından o bölümü okumanızı öneririm.

Bu yazı, **saldırganların bir şekilde hedefin domain adını taklit etmeye ya da kullanmaya çalışacağı** fikrine dayanır. Eğer domaininiz `example.com` ise ve farklı bir domain (ör. `youwonthelottery.com`) kullanılarak hedeflenmişseniz, bu teknikler bunu ortaya çıkaramayacaktır.

## Domain name varyasyonları

E-posta içinde benzer bir domain adı kullanacak phishing girişimlerini ortaya çıkarmak bir hayli **kolaydır**.\
Saldırganın kullanabileceği en olası phishing isimlerinin bir listesini **oluşturmak** ve bunların **kayıtlı** olup olmadığını ya da herhangi bir **IP**'nin bunları kullanıp kullanmadığını **kontrol etmek** yeterlidir.

### Finding suspicious domains

Bu amaç için aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Bu araçların domainin herhangi bir IP'ye atanmış olup olmadığını kontrol etmek için otomatik olarak DNS istekleri de yapacağını unutmayın:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: Eğer aday bir liste oluşturursanız, bunu DNS resolver loglarınıza da göndererek **kuruluş içinden gelen NXDOMAIN sorgularını** tespit edin (kullanıcıların saldırgan gerçekten kaydını yapmadan önce bir yazım hatasına ulaşmayı denemesi). Politika izin veriyorsa bu domainleri sinkhole'layın veya önceden engelleyin.

### Bitflipping

**Bu tekniğin kısa bir açıklamasını üst sayfada bulabilirsiniz. Veya özgün araştırmayı şu adreste okuyun** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Örneğin, microsoft.com domainindeki 1 bit'lik bir değişiklik onu _windnws.com_ şeklinde dönüştürebilir.\
**Saldırganlar hedefle ilgili mümkün olduğunca çok bit-flipping domain kaydı yapabilirler ve meşru kullanıcıları kendi altyapılarına yönlendirebilirler.**

**Tüm olası bit-flipping domain isimleri de izlenmelidir.**

Eğer homoglyph/IDN lookalikes'ları da göz önüne almanız gerekiyorsa (ör. Latin/Kiril karakterlerin karıştırılması), bakınız:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Temel kontroller

Potansiyel şüpheli domain isimleri listesini elde ettikten sonra, bunları (özellikle HTTP ve HTTPS portlarında) **kontrol ederek hedef domainin kullandığına benzer bir login formu kullanıp kullanmadıklarını görmelisiniz**.\
Port 3333'ü de kontrol ederek açık olup `gophish` çalıştırıp çalıştırmadığını görebilirsiniz.\
Ayrıca keşfedilen her şüpheli domainin **ne kadar eski olduğunu** bilmek ilginçtir; ne kadar yeni ise o kadar risklidir.\
Şüpheli web sayfalarının HTTP ve/veya HTTPS ekran görüntülerini alarak şüpheli olup olmadıklarını görebilir ve gerekirse **daha derinlemesine incelemek için erişebilirsiniz**.

### İleri düzey kontroller

Eğer bir adım daha ileri gitmek isterseniz, bu şüpheli domainleri düzenli olarak **izlemenizi ve zaman zaman yeni aramalar yapmanızı** öneririm (her gün mü? sadece birkaç saniye/dakika sürer). İlgili IP'lerin açık portlarını da **kontrol etmeli** ve `gophish` veya benzeri araç örneklerini **aramalısınız** (evet, saldırganlar da hata yapar) ve şüpheli domainlerin ve subdomainlerin HTTP ve HTTPS sayfalarını **izleyerek** hedefin web sayfalarından herhangi bir login formunu kopyalayıp kopyalamadıklarını kontrol edin.\
Bunu **otomatikleştirmek** için, hedef domainlerin login formlarının bir listesini tutmanızı, şüpheli web sayfalarını taramanızı ve şüpheli domainlerde bulunan her login formunu hedef domainin her login formuyla `ssdeep` gibi bir şeyle karşılaştırmanızı öneririm.\
Şüpheli domainlerin login formlarını bulduysanız, **sahte kimlik bilgileri gönderip** bunun sizi hedefin domainine **yönlendirip yönlendirmediğini kontrol edebilirsiniz**.

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

Birçok phishing kit'i taklit ettikleri markanın favicon'larını yeniden kullanır. Internet çapındaki tarayıcılar base64 ile kodlanmış favicon'un MurmurHash3'ünü hesaplar. Bu hash'i üretebilir ve bunun üzerinden pivot yapabilirsiniz:

Python örneği (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan'da sorgu: `http.favicon.hash:309020573`
- Araçlarla: favfreak gibi topluluk araçlarına bakarak Shodan/ZoomEye/Censys için hash ve dork oluşturun.

Notlar
- Favicons yeniden kullanılır; eşleşmeleri lead olarak değerlendirin ve işlem yapmadan önce içeriği ve certs'i doğrulayın.
- Daha yüksek doğruluk için domain-age ve keyword heuristics ile birleştirin.

### URL telemetri araştırması (urlscan.io)

`urlscan.io` gönderilen URL'lerin geçmiş ekran görüntülerini, DOM'unu, isteklerini ve TLS meta verilerini saklar. Marka kötüye kullanımı ve klonlar için arama yapabilirsiniz:

Örnek sorgular (UI veya API):
- Meşru domainlerinizi hariç tutarak benzer siteleri bulun: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Varlıklarınıza hotlinking yapan siteleri bulun: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Sonuçları yakın zamanla kısıtlamak için ekleyin: `AND date:>now-7d`

API örneği:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON'dan pivot on:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` — lookalikes için çok yeni cert'leri tespit etmek
- `task.source` değerleri, örn. `certstream-suspicious` — bulguları CT monitoring'e bağlamak için

### RDAP üzerinden alan adı yaşı (scriptable)

RDAP makine-okunabilir oluşturma olayları döndürür. **Yeni kayıtlı alan adlarını (NRDs)** işaretlemek için kullanışlı.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Pipeline'inizi alan adlarını kayıt yaşı kovalarına (ör., <7 days, <30 days) göre etiketleyerek zenginleştirin ve triajı buna göre önceliklendirin.

### TLS/JAx fingerprints to spot AiTM infrastructure

Modern credential-phishing giderek daha fazla **Adversary-in-the-Middle (AiTM)** reverse proxy'leri (ör., Evilginx) kullanarak oturum token'larını çalıyor. Ağ tarafı tespitleri ekleyebilirsiniz:

- Egress'te TLS/HTTP fingerprint'lerini (JA3/JA4/JA4S/JA4H) kaydedin. Bazı Evilginx yapılarında stabil JA4 istemci/sunucu değerleri gözlemlenmiştir. Bilinen-kötü fingerprint'lerde yalnızca zayıf bir gösterge olarak alarm oluşturun ve her zaman içerik ile domain istihbaratıyla teyit edin.
- CT veya urlscan üzerinden keşfedilen lookalike hostlar için TLS sertifika meta verilerini (issuer, SAN sayısı, wildcard kullanımı, geçerlilik) proaktif olarak kaydedin ve bunları DNS yaşı ve coğrafi konumla korelasyonlayın.

> Not: Fingerprint'leri zenginleştirme olarak değerlendirin, tek başına engelleyici olarak kullanmayın; framework'ler evrilebilir ve rastgeleleştirme/obfuscation yapabilir.

### Domain names using keywords

Ana sayfa ayrıca **kurbanın domain adını daha büyük bir domainin içine koyma** tekniğinden de bahsediyor (ör., paypal-financial.com, paypal.com için).

#### Certificate Transparency

Önceki "Brute-Force" yaklaşımını kullanmak her zaman mümkün olmayabilir ama sertifika şeffaflığı sayesinde bu tür phishing girişimlerini ortaya çıkarmak **mümkündür**. Her seferinde bir CA tarafından bir sertifika verildiğinde, detaylar kamuya açılır. Bu, certificate transparency'i okuyarak veya izleyerek, bir ismin içinde anahtar kelime kullanan domainleri **bulmanın mümkün olduğu** anlamına gelir. Örneğin, bir saldırgan [https://paypal-financial.com](https://paypal-financial.com) için bir sertifika oluşturduğunda, sertifikayı görerek "paypal" anahtar kelimesini bulmak ve şüpheli e-postanın kullanıldığını bilmek mümkündür.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) Censys kullanarak belirli bir anahtar kelimeyi etkileyen sertifikaları tarih (sadece "yeni" sertifikalar) ve CA issuer "Let's Encrypt" ile filtreleyerek arayabileceğinizi öneriyor:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Bununla birlikte, ücretsiz web [**crt.sh**](https://crt.sh) ile de "aynı" işi yapabilirsiniz. Anahtar kelimeyi **arama** ve sonuçları isterseniz **tarih ve CA'ya göre filtreleme** imkanınız var.

![](<../../images/image (519).png>)

Bu son seçenekle Matching Identities alanını kullanarak gerçek domain'den herhangi bir identity'nin şüpheli domainlerle eşleşip eşleşmediğini bile görebilirsiniz (şüpheli bir domainin false positive olabileceğini unutmayın).

**Bir diğer alternatif** harika proje [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream, yeni oluşturulan sertifikaların gerçek zamanlı akışını sağlar; belirli anahtar kelimeleri (neredeyse) gerçek zamanlı olarak tespit etmek için kullanabilirsiniz. Aslında, bunu yapan [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) adında bir proje var.

Pratik ipucu: CT bulgularını triajlarken NRD'leri, güvensiz/bilinmeyen registrar'ları, privacy-proxy WHOIS kayıtlarını ve çok yeni `NotBefore` zamanlarına sahip sertifikaları önceliklendirin. Gürültüyü azaltmak için sahip olduğunuz domain/markaların bir allowlist'ini tutun.

#### **New domains**

**Son bir alternatif** bazı TLD'ler için **yeni kaydedilmiş domain** listeleri toplmaktır (Whoxy bu hizmeti sağlar: https://www.whoxy.com/newly-registered-domains/) ve bu domainlerde anahtar kelimeleri **kontrol etmektir**. Ancak, uzun domainler genellikle bir veya daha fazla subdomain kullanır; dolayısıyla anahtar kelime FLD'nin içinde görünmeyebilir ve phishing alt domain'ini bulamayabilirsiniz.

Ek heuristik: belirli **file-extension TLD'leri** (ör., `.zip`, `.mov`) uyarılarında ekstra şüpheyle ele alın. Bunlar lure'larda dosya isimleriyle karıştırılmaya eğilimlidir; daha iyi doğruluk için TLD sinyalini marka anahtar kelimeleri ve NRD yaşı ile birleştirin.

## Referanslar

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
