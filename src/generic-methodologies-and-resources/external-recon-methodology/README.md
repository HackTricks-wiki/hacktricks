# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

> Bir şirkete ait her şeyin kapsamda olduğu söylendi ve bu şirketin aslında nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** bulmaktır. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın alımlarını bulun; bu, kapsam içindeki şirketleri belirleyecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını belirleyecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, alan adları...) aramak için reverse whois sorgularını kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanın (`ssl` yöntemi yinelemeli olarak uygulanabilir).

Çözümlenmiş alt alan adlarından HTTP crawling ve port keşfine geçiş aşamaları için [Pentesting Metodolojisi](../pentesting-methodology.md#11-modern-recon-pipeline) bölümüne bakın.

### **Satın alımlar**

Öncelikle **ana şirkete ait diğer şirketlerin** hangileri olduğunu öğrenmemiz gerekiyor.\
Seçeneklerden biri [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret edip **ana şirketi aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** için arama yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket ağaçları ve bağlı şirketler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri biliyor olmalısınız. Şimdi bunların varlıklarını nasıl bulacağımıza bakalım.

### **ASN'ler**

Bir otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici ağlara erişim için açıkça tanımlanmış bir politikaya sahip olan **IP adresi bloklarından** oluşur. Tek bir kuruluş tarafından yönetilir ancak birden fazla operatörden oluşabilir.

Şirketin **IP aralıklarını** bulmak için kendisine herhangi bir **ASN atanıp atanmadığını** öğrenmek önemlidir. **Kapsam** içindeki tüm **host'lara** karşı bir **zafiyet testi** yapmak ve bu IP'lerdeki **alan adlarını aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adına**, **IP'ye** veya **alan adına** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için şu bağlantılar yararlı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda, muhtemelen tüm** yararlı bilgiler **(IP aralıkları ve Whois)** ilk bağlantıda zaten yer alıyordur.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'ın** enumeration'ı tarama sonunda ASN'leri otomatik olarak bir araya getirip özetler.

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

Bir kuruluşun IP aralıklarını, sınırlı ücretsiz API katmanı sunan [ASNLookup](https://asnlookup.com/) ile de bulabilirsiniz.

### **Zafiyet arama**

Bu noktada **scope içindeki tüm varlıkları** biliyoruz; bu nedenle izin veriliyorsa tüm hostlarda bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) çalıştırabilir **veya** açık portları **bulmak için** Shodan, Censys ya da ZoomEye gibi servisleri **kullanabilirsiniz**. Bulduklarınıza bağlı olarak, çalışan olası servislerin pentest işlemlerini nasıl yapacağınızı öğrenmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** parola **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **ile servislerde bruteforce yapmayı deneyebileceğinizi de belirtmekte fayda var.**

## Domainler

> Scope içindeki tüm şirketleri ve varlıklarını biliyoruz; şimdi scope içindeki domainleri bulma zamanı.

_Aşağıda önerilen tekniklerle subdomainleri de bulabileceğinizi ve bu bilgiyi küçümsememeniz gerektiğini unutmayın._

Öncelikle her şirketin **ana domain(lerini)** aramalısınız. Örneğin _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domainlerin tüm IP aralıklarını bulduğunuza göre, **scope içindeki daha fazla domaini bulmak için** bu **IP'lerde reverse DNS sorguları** yapmayı deneyebilirsiniz. Kurbanın DNS sunucularından birini veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için [SecurityTrails](https://securitytrails.com/) de kullanabilirsiniz; ancak geçmiş DNS verileri ücretli plan gerektirir.\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar, reverse lookup işlemlerini ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e-posta adresleri**, telefon numaraları gibi pek çok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olan, bu alanlardan herhangi biriyle **reverse whois lookup** yaparak **şirketle ilişkili daha fazla varlık** bulabilmenizdir (örneğin aynı e-posta adresinin göründüğü diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web arayüzü; API ücretlidir.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Mevcut DNS/alt alan adları için sınırlı ücretsiz API erişimi sunar; geçmiş veriler ve reverse lookup işlemleri ücretli plan gerektirir.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kaydolunca 500 ücretsiz API kredisi; sonrasında ücretli.

[**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak bu görevi otomatikleştirebilirsiniz (whoxy API anahtarı gerektirir).\
[amass](https://github.com/owasp-amass/amass) ile de otomatik reverse whois keşfi yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuzda, bu tekniği kullanarak daha fazla domain adı keşfedebileceğinizi unutmayın.**

### **Trackers**

İki farklı sayfada **aynı tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görünüyorsa.

Bu tracker'ları ve daha fazlasını aramanıza olanak tanıyan bazı sayfalar ve araçlar şunlardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Ücretli** web ve API hizmeti ([fiyatlandırma](https://www.stackscan.com/pricing)); şu anda ücretsiz plan sunulduğu belirtilmiyor. Yalnızca tracker ID'leriyle değil, sunulan herhangi bir varlık üzerinden pivot yapın: bir script yolu, self-hosted bundle adı veya varlığın yüklendiği host; sonuç olarak bu varlığın bulunduğu tüm siteler döndürülür.

API, tek bir domain için teknoloji yığınını döndürür; bu da aday bir varlığın aynı kuruluşa ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Algılanan her teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, domain başına arama yapar.

### **Favicon**

Aynı favicon simge hash'ini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte kullanımı:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash değerine sahip domain'leri keşfetmemizi sağlar.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA'da pivot olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini** şu şekilde **hesaplayabilirsiniz** (favicon baytlarının **base64 kodlanmış** hali üzerinde MMH3):

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url, timeout=10)
    favicon = codecs.encode(response.content, "base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

Ayrıca [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile büyük ölçekte favicon hash'leri alabilir ve ardından Shodan/Censys'te pivot edebilirsiniz.

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt olarak değil, gösterge olarak değerlendirin**: MMH3 kısadır; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı sahtecilik mümkündür.
- **Yalnızca** `/favicon.ico` **yolunu sorgulamayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik asset'lere WAF/SSO/IdP kontrollerinin arkasından erişilebilir durumda kalınabilir**: ikona doğrudan istek gönderin ve `ETag`, `Last-Modified`, yönlendirmeleri ve cache başlıklarını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: başlığı, HTML/body hash'ini, başlıkları, TLS sertifikası subject/SAN değerlerini, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümeleyin**: tutarlı bir şablon fingerprint'i güçlendirir; farklı şablonlar, genel veya paylaşılan bir ikona işaret eder.
- **Farklı signature'lar, portlar ve ürünlerde görünen bir hash'i olası bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz hedeflerde, gerçek bir sayfayı var olmayan bir yolla karşılaştırın**; örneğin `/_favicon_probe_<8-hex>`. Hosting veya park edilmiş alan adı yanıtlarının eşleşmesi, ortak ikonu açıklayabilir.
- **Favicon hash'lerini ürünlerle ve CPE'lerle eşleştiren Nuclei detection rule'ları veya herkese açık dataset'lerle ilk incelemeyi başlatın.**
- **IP merkezli kapsam açığını unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast ve yalnızca domain üzerinden erişilen yüzeyler Shodan benzeri dataset'lerde bulunmayabilir.

### **Telif Hakkı / Benzersiz string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde paylaşılabilecek string'leri** arayın. **Copyright string** buna iyi bir örnek olabilir. Ardından bu string'i **Google'da**, diğer **tarayıcılarda** veya hatta **Shodan'da** arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron job kullanmak yaygındır

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency loglarındaki konumları ilişkilendirmek, birbiriyle bağlantılı alan adlarını ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### E-posta DMARC bilgileri

**Aynı DMARC bilgilerini paylaşan alan adlarını ve alt alan adlarını** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Bir başka yararlı hizmet de [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı IP adresini yeniden tahsis ettiğinde erişilebilir hâle gelebilir. Kaynak gösterilen araştırma, bir instance oluşturup adresini pasif DNS verileriyle ilişkilendiren fırsatçı bir iş akışını ortaya koyuyor; takeover senaryolarını yalnızca izin verilen kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir alan adı bulduğunuzda, ilgili keşif adımlarını tekrarlayın: her sonuç, ilk başlangıç noktasından görünmeyen ek sertifika adlarını, pasif DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostlarda, TLS sertifikasında geçen yeni ve beklenmedik alan adlarını kontrol edin.

Ana web sayfasının **TLS certificate** bilgilerine erişip **Organisation name** bilgisini alın. Ardından bu adı, **shodan** tarafından bilinen tüm web sayfalarının **TLS certificates** bilgileri içinde şu filtreyle arayın: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanın.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), bir ana alan adıyla **ilişkili alan adlarını** ve bunların **alt alan adlarını** arayan harika bir araçtır.

**Pasif DNS / Geçmiş DNS**

Pasif DNS verileri, hâlâ çözümlenen veya takeover edilebilecek **eski ve unutulmuş kayıtları** bulmak için çok faydalıdır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Zafiyetleri arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir alan adını kullanıyordur** ama **sahipliğini kaybetmiştir**. (Yeterince ucuzsa) alan adını kaydedin ve şirkete haber verin.

Varlık keşfi sırasında bulduklarınızdan **farklı bir IP adresine sahip bir alan adı** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen alan adının, istemcinin kontrolünde olmayan ve dolayısıyla kapsam dışında kalan bir IP adresinde barındırıldığını unutmayın; dikkatli olun._

## Alt alan adları

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm alan adlarını biliyoruz.

Bulduğumuz her alan adının mümkün olan tüm alt alan adlarını bulma zamanı.

> [!TIP]
> Alan adlarını bulmak için kullanılan bazı araç ve tekniklerin alt alan adlarını bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **alt alan adlarını** bulmaya çalışalım. **Zone Transfer** denemesi de yapmalıyız (Güvenlik açığı varsa rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

For APIs and platforms covering infrastructure, reputation, breach records, and enrichment beyond subdomain discovery, see the [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md).

Çok sayıda subdomain bulmanın en hızlı yolu harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API key'leri yapılandırın):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

- [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

- [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

- [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

- [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar bile alt alan adlarını bulmak için kullanılabilecek **başka ilgi çekici araçlar/API’ler** de vardır:

- [**IP.THC.ORG**](https://ip.thc.org) ücretsiz API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB ücretsiz API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) ücretsiz API

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

- [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir alan adı için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i JS dosyaları bulmak için tarar ve buradan alt alan adlarını çıkarırlar.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

- [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

- [**Censys alt alan adı bulucu**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) güncel DNS ve subdomain verilerine sınırlı ücretsiz API erişimi sunar; geçmiş DNS/IP verileri için ücretli plan gerekir.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz** sunar. Bu verilere [chaospy](https://github.com/Moaaz-0x/chaospy) kullanarak veya bu projenin kullandığı scope'a [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) adresinden erişebilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayalım ve yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larından oluşan bir liste oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirip filtrelemek üzere [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şu listeyi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır ancak yanlış pozitif sonuçlara yatkındır.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Sanırım bu yalnızca 1 resolver kullanıyor.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), Go dilinde yazılmış bir `massdns` wrapper'ıdır. Aktif bruteforce ile geçerli alt alan adlarını numaralandırmanın yanı sıra wildcard işleme ve kolay girdi-çıktı desteğiyle alt alan adlarını çözümlemeyi sağlar.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns` de kullanır.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını eşzamansız olarak brute force etmek için asyncio kullanır.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### İkinci DNS Brute-Force Turu

Açık kaynakları kullanarak ve brute-force yaparak subdomain'leri bulduktan sonra, daha fazlasını bulmayı denemek için bulduğunuz subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla çeşitli araçlar kullanışlıdır:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Verilen domain'ler ve subdomain'ler için permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'ler için permütasyonlar üretir.
  - goaltdns permütasyon **wordlist**'ini [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain’lerden permütasyonlar oluşturur. Bir permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları üretmenin yanı sıra, bunları resolve etmeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
  - altdns permütasyonları için **wordlist**'i [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) edinebilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permutation, mutation ve değiştirme işlemlerini gerçekleştiren başka bir araç. Sonucu brute force yöntemiyle bulur (DNS wildcard desteği yoktur).
  - dmut permutation wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, daha fazla subdomain keşfetmeye çalışmak için belirtilen pattern'lere göre **yeni olası subdomain adları üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'ler öğrenir ve çözümlenmesi için aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili, DNS yanıtı rehberli bir algoritmayla çalışan bir subdomain brute-force fuzzer'dır. Özel bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir girdi kümesini kullanarak eşleşen başka domain adlarını doğru biçimde sentezler ve DNS taraması sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Alt Alan Adı Keşif İş Akışı**

Trickest iş akışı örnekleri, tekrarlanabilir alt alan adı enumerasyonu için OSINT, DNS brute force ve permütasyon aşamalarını birleştirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Alt alan adlarına ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, IP’deki domainleri bulmak için **OSINT kaynaklarını** inceleyerek veya o IP’deki VHost domain adlarına **brute force uygulayarak** **aynı IP’de web sitesi bulunan diğer alt alan adlarını bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya başka API’leri kullanarak IP’lerdeki bazı VHost’ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı alt alan adlarının gizlenmiş olabileceğinden şüpheleniyorsanız brute force uygulamayı deneyebilirsiniz:

Name-based VHost’lar için `Host` başlığını fuzz edin ve varsayılan yanıtı filtrelemek üzere ffuf’un auto-calibration özelliğini kullanın.<sup>[[2]](#references)</sup>

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

> [!TIP]
> Bu teknikle dahili/gizli endpoint’lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ başlığında geçerli bir domain/subdomain belirtildiğinde _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, bu davranışı kötüye kullanarak yeni **subdomain**’ler **keşfedebilirsiniz**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**Subdomain** ararken herhangi bir **bucket**'a **yönlenip yönlenmediğine** dikkat edin; böyle bir durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca bu aşamada scope içindeki tüm domainleri biliyor olacağınız için olası bucket adlarını [**brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

[sublert ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) gibi araçların yaptığı şekilde **Certificate Transparency** Log'larını izleyerek bir domain için **yeni subdomain'ler** oluşturulup oluşturulmadığını **izleyebilirsiniz**.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Subdomain** bir **S3 bucket**'a yönleniyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset discovery sırasında bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir subdomain** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Not: Bazen subdomain, client tarafından kontrol edilmeyen bir IP üzerinde barındırılır ve bu nedenle scope içinde değildir; dikkatli olun._

## IPs

İlk adımlarda muhtemelen **bazı IP aralıkları, domainler ve subdomain'ler buldunuz**.\
Şimdi bu aralıklardaki IP'leri ve **domain/subdomain'lere ait IP'leri (DNS sorgularıyla) derlemenin** zamanı.

Aşağıdaki gibi servisleri kullanarak **domain ve subdomain'lerin daha önce kullandığı IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**SecurityTrails**](https://securitytrails.com/) (geçmiş DNS/IP verileri için ücretli plan gerekir)

Belirli bir IP adresine yönlenen domain'leri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'lerde port scan yapın** (çünkü buralarda muhtemelen ilginizi çekecek bir şey bulamazsınız). Bulunan çalışan servislerde **zafiyetler bulabilirsiniz**.

Host'ları nasıl tarayacağınız hakkında bir [**kılavuz**](../pentesting-network/index.html) **bulun**.

## Web sunucularını arama

> Tüm şirketleri ve varlıklarını bulduk; scope içindeki IP aralıklarını, domainleri ve subdomain'leri biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domain'ler üzerinde zaten bir miktar **recon** yaptınız; bu nedenle olası **tüm web sunucularını bulmuş** olabilirsiniz. Bulmadıysanız, şimdi scope içindeki web sunucularını bulmak için bazı **hızlı yöntemlere** göz atacağız.

Bunun **web app keşfine yönelik** olduğunu unutmayın; bu nedenle scope **izin veriyorsa** zafiyet ve **port taraması** da yapmalısınız.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemi burada bulunabilir**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını aramak için kullanabileceğiniz bir diğer kolay araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi verirsiniz; araç 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca başka portları da denemesini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsamdaki **tüm web sunucularını** (şirketin **IP**'leri ile tüm **domain** ve **subdomain**'leri arasından) keşfettiğinize göre, muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde işi basitleştirelim ve hepsinin ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya** **göz atarak** **savunmasız olma olasılığı daha yüksek** olan **tuhaf** endpoint'ler bulabilirsiniz.

Önerilen yöntemi uygulamak için [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, tüm **ekran görüntülerini** inceleyerek **hangilerinin muhtemelen güvenlik açığı içerdiğini**, hangilerinin içermediğini söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için **önce şirketi tanımlayan anahtar sözcüklerin listesini oluşturmalısınız**. Örneğin, bir kripto şirketi için `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gibi sözcükler kullanabilirsiniz.

Ayrıca **bucket'larda sık kullanılan sözcüklerden** oluşan wordlist'lere de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu sözcüklerle **varyasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Oluşan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **yalnızca AWS'deki bucket'lara bakmamanız** gerektiğini unutmayın.

### **Güvenlik açıklarını arama**

**Açık bucket'lar veya dışarıya açık cloud function'lar** gibi şeyler bulursanız, bunlara **erişmeli** ve neler sunduklarını, bunları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## E-postalar

Kapsam içindeki **domain** ve **subdomain**'lerle e-posta aramaya başlamak için gereken her şeye sahipsiniz. Bir şirkete ait e-postaları bulmak için en iyi sonuç veren **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Güvenlik açıklarını arama**

E-postalar daha sonra web girişlerine ve auth servislerine (SSH gibi) **brute-force uygularken** işinize yarar. Ayrıca **phishing** için de gereklidir. Bunun yanında bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** verir; bu bilgiler phishing kampanyasında faydalıdır.

## Credential Leak'leri

**Domain**'ler, **subdomain**'ler ve **e-postalar** ile bu e-postalara ait geçmişte leak edilmiş credential'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Güvenlik açıklarını arama**

**Geçerli, leak edilmiş** credential'lar bulursanız, bu çok kolay bir kazanımdır.

## Secret Leak'leri

Credential leak'leri, **hassas bilgilerin leak edilip satıldığı** şirket hack'leriyle ilişkilidir. Ancak şirketler, bilgileri bu veritabanlarında bulunmayan **başka leak'lerden** de etkilenmiş olabilir:

### Github Leak'leri

Credential'lar ve API'ler, **şirketin** veya o şirkette çalışan **kullanıcıların** **public repository**'lerinde leak edilmiş olabilir.\
Bir **organizasyonun** ve geliştiricilerinin tüm **public repo**'larını **indirmek** ve üzerlerinde otomatik olarak [**gitleaks**](https://github.com/gitleaks/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, **metin içeren** URL'lerin tümünde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfaları da secret içerir**.

#### Github Dorks

Organizasyonda arama yapabileceğiniz olası **GitHub dorks** için [GitHub dorks and leaks sayfasına](github-leaked-secrets.md) bakın.

### Paste Leak'leri

Bazen saldırganlar veya çalışanlar şirket içeriğini bir paste sitesinde **yayınlayabilir**. Bu içerik **hassas bilgi** içerebilir de içermeyebilir de; ancak aramaya değer.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki Google dorks, **orada olmaması gereken açık bilgileri bulmak** için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde manuel olarak çalıştıramayacağınız **binlerce** olası sorgunun bulunmasıdır. Bu nedenle, favori 10 sorgunuzu seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Regular Google tarayıcısını kullanarak veritabanının tamamını çalıştırmayı bekleyen araçların işi asla bitmez; çünkü Google sizi çok kısa sürede engeller._

### **Güvenlik açıklarını arama**

**Geçerli, leak edilmiş** credential'lar veya API token'ları bulursanız, bu çok kolay bir kazanımdır.

## Public Code Güvenlik Açıkları

Şirketin **open-source kodu** olduğunu bulduysanız, bu kodu **analiz edebilir** ve içindeki **güvenlik açıklarını** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır; [source-code review araçları](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca [**Snyk**](https://app.snyk.io/) gibi, **public repository'leri taramaya** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **güvenlik açıklarının çoğu** **web uygulamalarında** bulunur. Bu nedenle, bu noktada bir **web uygulaması test metodolojisinden** söz etmek istiyorum; [**bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünü özellikle belirtmek istiyorum. Bu araçların çok hassas güvenlik açıkları bulmasını beklememelisiniz; ancak başlangıç seviyesinde web bilgisi elde etmek için bunları **workflow'lara** eklemek faydalıdır.

## Özet

> Tebrikler! Bu noktada **temel keşif çalışmalarının** tümünü tamamladınız. Evet, bu temel düzeyde; çünkü çok daha fazla keşif yapılabilir (ileride daha fazla püf noktası göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsam içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (kapsam içindeyse bazı vuln scan'ler gerçekleştirdiniz)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lere ait tüm **subdomain**'leri buldunuz (subdomain takeover olasılığı var mı?)
5. Kapsam içindeki tüm **IP**'leri buldunuz (**CDN'lerden gelen ve gelmeyen**).
6. Tüm **web sunucularını** bulup ekran görüntülerini aldınız (daha yakından incelenmeye değer tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Size **çok kolay bir şekilde büyük kazanç sağlayabilecek** **e-postalar**, **credential leak'leri** ve **secret leak'leri** buldunuz.
9. Bulduğunuz tüm web sitelerine **pentesting uyguladınız**

## **Tam Otomatik Recon Araçları**

Belirli bir kapsama önerilen işlemlerin bir kısmını uygulayan çeşitli araçlar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor



## References

- [1] [Jason Haddix – Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicons Üzerine: Tarayıcı Simgelerinden Attack Surface Intelligence'a](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty'ler, OSINT ve Daha Fazlası için favicon.ico'yu Silahlandırmak](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerindeki Zaman Korelasyonu Saldırısıyla Domain'leri Keşfetmek](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif Takeover: Maliyetli Bir Subdomain Takeover Kampanyasını Ortaya Çıkarmak (ve Taklit Etmek)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Benzersiz Bir Yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Eksiksiz Subdomain Keşif Workflow'u, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest Workflow'u Kullanarak Eksiksiz Subdomain Brute Force Keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
