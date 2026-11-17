# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlık keşifleri

> Bir şirkete ait her şeyin scope içinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu bulmak istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri**, ardından da bu şirketlerin tüm **varlıklarını** bulmaktır. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın almalarını bulun; böylece scope içindeki şirketleri öğrenirsiniz.
2. Her şirketin varsa ASN'sini bulun; böylece şirketlerin sahip olduğu IP aralıklarını öğrenirsiniz.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, alan adları...) aramak için reverse Whois sorguları kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için Shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanın (`ssl` yöntemi yinelemeli olarak kullanılabilir).

Çözümlenmiş alt alan adlarından HTTP crawling ve port keşfine geçiş için [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) sayfasına bakın.

### **Satın almalar**

Öncelikle, ana şirketin sahip olduğu **diğer şirketleri** öğrenmemiz gerekiyor.\
Bunun bir yolu [https://www.crunchbase.com/](https://www.crunchbase.com) adresine gidip **ana şirketi aramak** ve "**acquisitions**" bölümüne **tıklamaktır**. Burada ana şirketin satın aldığı diğer şirketleri görürsünüz.\
Diğer bir yol, ana şirketin **Wikipedia** sayfasına gidip **acquisitions** ifadesini aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'taki **Companies House**) inceleyin.\
Küresel şirket ağaçları ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada scope içindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımıza bakalım.

### **ASN'ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir; ancak birden fazla operatörden meydana gelebilir.

Şirketin **IP aralıklarını** bulmak için şirkete herhangi bir **ASN atanıp atanmadığını** öğrenmek faydalıdır. **Scope** içindeki tüm **hostlar** üzerinde **zafiyet testi** yapmak ve bu IP'lerdeki **alan adlarını aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adına**, **IP'ye** veya **alan adına** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için bu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her hâlükârda, muhtemelen tüm** faydalı bilgiler **(IP aralıkları ve Whois)** ilk bağlantıda zaten bulunur.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot) enumeration'ı scan sonunda ASN'leri otomatik olarak toplar ve özetler.

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

Bir kuruluşun IP aralıklarını, sınırlı ücretsiz API katmanı sunan [ASNLookup](https://asnlookup.com/) aracılığıyla da bulabilirsiniz.

### **Zafiyet arama**

Bu noktada **kapsamdaki tüm varlıkları** biliyoruz; bu nedenle izniniz varsa tüm hostlarda bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapabilir **veya** Shodan, Censys ya da ZoomEye gibi servisleri kullanarak açık portları **bulabilirsiniz. Bulduklarınıza bağlı olarak, çalışan çeşitli olası servislerin pentestini nasıl yapacağınızı öğrenmek için** bu kitaba göz atmalısınız.\
**Ayrıca, bazı varsayılan kullanıcı adı ve** şifre **listeleri hazırlayıp [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servislerde** bruteforce **denemesi yapabileceğinizi de belirtmekte fayda var.**

## Domains

> Kapsamdaki tüm şirketleri ve varlıklarını biliyoruz; şimdi kapsam içindeki domainleri bulma zamanı.

_Aşağıda önerilen tekniklerle subdomainlerin de bulunabileceğini ve bu bilgilerin göz ardı edilmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana domainini** bulmalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domainlerin tüm IP aralıklarını bulduğunuza göre, **kapsam içindeki başka domainleri bulmak için bu IP’lerde reverse DNS lookup** yapmayı deneyebilirsiniz. Kurbanın DNS sunucularından birini veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için [SecurityTrails](https://securitytrails.com/) de kullanabilirsiniz; ancak geçmiş DNS verileri ücretli plan gerektirir.\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar, ters aramaları ve zenginleştirmeyi otomatikleştirmede kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **kuruluş adı**, **adres**, **e-postalar**, telefon numaraları gibi pek çok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olanı, bu alanlardan herhangi birini kullanarak **reverse whois aramaları yaptığınızda şirketle ilişkili daha fazla varlık** bulabilmenizdir (örneğin aynı e-postanın geçtiği diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web arayüzü; ücretli API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Güncel DNS/alt alan adları için sınırlı ücretsiz API erişimi; geçmiş veriler ve reverse lookuplar için ücretli plan gerekir.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kayıt sırasında 500 ücretsiz API kredisi; sonrasında ücretli.

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) ile otomatikleştirebilirsiniz (whoxy API key gerektirir).\
[amass](https://github.com/owasp-amass/amass) ile bazı otomatik reverse whois keşifleri de yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuzda daha fazla domain keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada **aynı tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görünüyorsa.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar şunlardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Ücretli** web ve API hizmeti ([fiyatlandırma](https://www.stackscan.com/pricing)); şu anda ücretsiz plan sunulduğu belirtilmiyor. Yalnızca tracker ID'leri değil, sunulan herhangi bir varlığı pivot noktası olarak kullanın: bir script yolu, self-hosted bir bundle adı veya bir varlığın yüklendiği host. Böylece bu varlığı barındıran tüm siteler döndürülür.

API, tek bir domain için stack'i döndürür; bu da aday bir varlığın aynı varlık grubuna ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Her tespit edilen teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, domain başına sorgulamayı destekler.

### **Favicon**

Aynı favicon simge hash’ini arayarak hedefimizle ilişkili domain ve subdomain’leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) aracı tam olarak bunu yapar. Nasıl kullanacağınız şöyle:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash değerini kullanan domainleri keşfetmek için kullanılır](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon hash değerine sahip domainleri keşfetmemizi sağlar.

![Aynı favicon hash değerine sahip domainleri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA üzerinde pivot olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini** şu şekilde **hesaplayabilirsiniz** (favicon baytlarının **base64 ile kodlanmış** hâli üzerinde MMH3):

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

Ayrıca [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile büyük ölçekte favicon hash'leri alıp Shodan/Censys'te pivot yapabilirsiniz.

Favicon parmak izlerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, gösterge olarak değerlendirin**: MMH3 kompakt olduğundan çakışmalar, yeniden kullanılan simgeler ve kasıtlı sahtecilik mümkündür.
- **Yalnızca** `/favicon.ico` **üzerinde inceleme yapmayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik varlıklara WAF/SSO/IdP denetimleri arkasından hâlâ erişilebilir olabilir**: simgeye doğrudan istek gönderin; `ETag`, `Last-Modified`, yönlendirmeleri ve cache başlıklarını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: başlığı, HTML/body hash'ini, başlıkları, TLS sertifikası konu adlarını/SAN'ları, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümeleyin**: tutarlı bir şablon parmak izini güçlendirir; farklı şablonlar genel veya paylaşılan bir simgeye işaret eder.
- **İlişkisiz imzalar, portlar ve ürünlerde görünen bir hash'i olası bir honeypot veya yer tutucu olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı var olmayan bir yolla** `/_favicon_probe_<8-hex>` **karşılaştırın**; aynı hosting veya park edilmiş alan adı yanıtları, paylaşılan simgeyi açıklayabilir.
- **Ürünleri ve CPE'leri favicon hash'leriyle eşleştiren Nuclei tespit kurallarını veya herkese açık veri kümelerini kullanarak ilk triyajı yapın.**
- **IP merkezli kapsama boşluğunu unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast kullanan ve yalnızca alan adı üzerinden erişilebilen yüzeyler Shodan benzeri veri kümelerinde eksik olabilir.

### **Telif Hakkı / Benzersiz Dize**

Web sayfalarında **aynı kuruluştaki farklı sitelerde paylaşılabilecek dizeleri** arayın. **Telif hakkı dizesi** buna iyi bir örnek olabilir. Ardından bu dizeyi **Google'da**, diğer **tarayıcılarda** veya hatta **Shodan'da** arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron job kullanılması yaygındır:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

bir sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency loglarındaki konumları ilişkilendirmek, bağlantılı alan adlarını ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı dmarc bilgilerini paylaşan alan adlarını ve alt alan adlarını** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Bir başka kullanışlı hizmet de [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturup adresini passive DNS verileriyle ilişkilendiren fırsatçı bir iş akışını gösteriyor; takeover senaryolarını yalnızca yetkili kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir alan adı bulduğunuzda ilgili keşif yöntemlerini tekrarlayın: her sonuç, başlangıçta görülemeyen ek sertifika adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostlarda, TLS sertifikasında yer alan yeni ve beklenmedik alan adlarını kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name** değerini alın. Ardından bu adı, **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikalarında** şu filtreyle arayın: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanın.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), bir ana alan adıyla **ilişkili alan adlarını** ve bunların **alt alan adlarını** arayan bir araçtır; oldukça etkileyici.

**Passive DNS / Geçmiş DNS**

Passive DNS verileri, hâlâ çözümlenen veya takeover edilebilecek **eski ve unutulmuş kayıtları** bulmak için çok kullanışlıdır. Şuralara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Güvenlik açıklarını arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) senaryolarını kontrol edin. Bir şirket bir **alan adını kullanıyor** olabilir ama **sahipliğini kaybetmiş** olabilir. Yeterince ucuzsa alan adını kaydedin ve şirkete haber verin.

Varlık keşfinde bulduğunuz IP'lerden **farklı bir IP'ye sahip bir alan adı** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan hizmetlere bağlı olarak **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Domain bazen istemcinin kontrolünde olmayan bir IP üzerinde barındırılabilir ve bu nedenle kapsam dışında olabilir; dikkatli olun._

## Alt alan adları

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm alan adlarını biliyoruz.

Bulduğumuz her alan adının olası tüm alt alan adlarını bulma zamanı.

> [!TIP]
> Alan adlarını bulmak için kullanılan bazı araç ve tekniklerin alt alan adlarını bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **alt alan adlarını** bulmaya çalışalım. **Zone Transfer** işlemine de bakmalıyız (güvenlik açığı varsa rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Subdomain keşfinin ötesinde altyapı, itibar, breach kayıtları ve zenginleştirme konularını kapsayan API'ler ve platformlar için [Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md) sayfasına bakın.

Çok sayıda subdomain elde etmenin en hızlı yolu, harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):


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

Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar da alt alan adlarını bulmak için yararlı olabilecek **başka ilginç araçlar/API'ler** de vardır:

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

- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault's Open Threat Exchange, the Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i JS dosyalarını bulmak için tarar ve buradan subdomain'leri çıkarırlar.

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

- [**SecurityTrails**](https://securitytrails.com/) güncel DNS ve subdomain verileri için sınırlı ücretsiz API erişimi sunar; geçmiş DNS/IP verileri ücretli plan gerektirir.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, **bug-bounty programlarıyla ilgili tüm subdomain'leri ücretsiz** sunar. Bu verilere [chaospy](https://github.com/Moaaz-0x/chaospy) kullanarak veya doğrudan bu projenin kullandığı scope'a [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) erişerek de ulaşabilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP adresleri de gerekir. Güvenilir DNS resolver'larının bir listesini oluşturmak için [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden resolver listesini indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute-force gerçekleştiren ilk araç buydu. Çok hızlıdır ancak false positive sonuçlar vermeye yatkındır.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), `massdns` etrafında yazılmış, go ile geliştirilmiş bir wrapper'dır. Aktif bruteforce ile geçerli alt alan adlarını numaralandırmanın yanı sıra wildcard işleme ve kolay girdi-çıktı desteğiyle alt alan adlarını çözümlemenizi sağlar.

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

Açık kaynakları kullanarak ve brute-force yaparak subdomain'leri bulduktan sonra, daha fazlasını bulmaya çalışmak için bulduğunuz subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain’lerden permütasyonlar oluşturur.
  - goaltdns **wordlist**’ini [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur. Bir permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permütasyonları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak yukarıda bahsedilen araçları kullanmak daha iyidir).
  - altdns permütasyon **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adları üzerinde permütasyonlar, mutasyonlar ve değişiklikler yapmak için başka bir araç. Bu araç sonucu brute force yöntemiyle bulur (DNS wildcard'ı desteklemez).
  - dmut permütasyon kelime listesini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, belirtilen kalıpları kullanarak yeni olası alt alan adı adları üretir ve böylece daha fazla alt alan adı keşfetmeye çalışır.

#### Akıllı permütasyon oluşturma

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen alt alan adlarından regex benzeri kalıplar öğrenir ve çözümlenmek üzere aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili bir DNS yanıtı güdümlü algoritmayla birleştirilmiş bir subdomain brute-force fuzzer'ıdır. Özel olarak hazırlanmış bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan girdi verilerini kullanarak, eşleşen daha fazla domain adını doğru biçimde üretir ve DNS taraması sırasında elde edilen bilgilere dayanarak bunları döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain’lere ait **bir veya birkaç web sayfası** barındıran bir IP adresi bulduysanız, IP’deki domain’leri **OSINT kaynaklarında** arayarak veya o IP’deki VHost domain adlarına **brute force uygulayarak** aynı IP’deki diğer subdomain’leri **bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API’leri kullanarak IP’lerdeki bazı VHosts’ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı subdomain’lerin gizlenmiş olabileceğinden şüpheleniyorsanız, brute force uygulamayı deneyebilirsiniz:

Name-based vhost’lar için `Host` header’ını fuzz edin ve varsayılan yanıtı filtrelemek üzere ffuf’un auto-calibration özelliğini kullanın.<sup>[[2]](#references)</sup>

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
> Bu teknikle internal/gizli endpoint'lere bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında yalnızca _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**Alt alan adlarını** ararken bunların herhangi bir **bucket'a yönlenip yönlenmediğini** kontrol edin. Böyle bir durum varsa [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Ayrıca, bu aşamada scope içindeki tüm domainleri biliyor olacağınız için olası bucket adlarını [**brute force ile deneyin ve izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **İzleme**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) gibi Certificate Transparency loglarını izleyerek bir domain için **yeni alt alan adlarının** oluşturulup oluşturulmadığını **izleyebilirsiniz**.

### **Güvenlik açıklarını arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Alt alan adı** bir **S3 bucket'a** yönleniyorsa [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Varlık keşfinde bulduklarınızdan **farklı bir IP'ye sahip bir alt alan adı** bulursanız, temel bir güvenlik açığı taraması (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta bunlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen alt alan adı, istemcinin kontrolünde olmayan bir IP üzerinde barındırılabilir; bu nedenle scope dışında olabilir. Dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP aralıkları, domainler ve alt alan adları bulmuş** olabilirsiniz.\
**Bu aralıklardaki ve domainler/alt alan adlarıyla ilişkili tüm IP'leri (DNS sorgularıyla) toplama** zamanı.

Aşağıdaki gibi servisleri kullanarak **domainler ve alt alan adları tarafından geçmişte kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ istemciye ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**SecurityTrails**](https://securitytrails.com/) (geçmiş DNS/IP verileri için ücretli plan gerekir)

Belirli bir IP adresine yönlenen domainleri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Güvenlik açıklarını arama**

**CDN'lere ait olmayan tüm IP'leri port taramasından geçirin** (çünkü CDN'lerde ilginç bir şey bulma olasılığınız çok düşüktür). Tespit edilen çalışan servislerde **güvenlik açıkları bulabilirsiniz**.

**Hostları nasıl tarayacağınızla ilgili bir** [**kılavuz**](../pentesting-network/index.html) **bulun.**

## Web sunucularını arama

> Tüm şirketleri ve varlıklarını bulduk; scope içindeki IP aralıklarını, domainleri ve alt alan adlarını biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfettiğiniz IP'ler ve domainler üzerinde zaten **recon** yaptınız; bu nedenle olası tüm web sunucularını **zaten bulmuş** olabilirsiniz. Ancak bulmadıysanız, şimdi scope içinde web sunucularını aramak için bazı **hızlı yöntemlere** bakacağız.

Bunun **web uygulamalarını keşfetmeye yönelik** olduğunu unutmayın; bu nedenle scope tarafından **izin veriliyorsa** güvenlik açığı taraması ve port taraması da yapmalısınız.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemini burada bulabilirsiniz**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını aramak için kullanabileceğiniz bir diğer pratik araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi verirsiniz; araçlar 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portların da denenmesini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsamdaki **tüm web sunucularını** (şirketin **IP**'leri ile tüm **domain** ve **subdomain**'leri arasında) keşfettikten sonra muhtemelen **nereden başlayacağınızı bilmiyorsunuzdur**. O hâlde işi basitleştirip hepsinin ekran görüntülerini alarak başlayalım. **Ana sayfaya** şöyle bir **bakarak** bile **savunmasız** olma **olasılığı daha yüksek** olan **tuhaf** endpoint'ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, tüm **ekran görüntülerini** tarayıp hangilerinin **muhtemelen güvenlik açığı içerdiğini**, hangilerinin içermediğini öğrenmek için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için **önce şirketi tanımlayan anahtar kelimelerin bir listesini** oluşturmalısınız. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca **bucket'larda yaygın olarak kullanılan kelimelerin** wordlist'lerine de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permütasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **AWS'deki bucket'lardan daha fazlasını aramanız** gerektiğini unutmayın.

### **Güvenlik açıklarını arama**

**Açık bucket'lar veya dışarıya açık cloud function'lar** gibi şeyler bulursanız bunlara **erişin** ve ne sunduklarını, kötüye kullanıp kullanamayacağınızı anlamaya çalışın.

## E-postalar

Kapsamdaki **domain** ve **subdomain**'lerle, e-posta aramaya başlamak için gereken her şeye sahipsiniz. Bir şirkete ait e-postaları bulmak için en iyi sonuç veren **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Güvenlik açıklarını arama**

E-postalar, daha sonra **web girişlerini ve auth servislerini** (SSH gibi) **brute-force** etmek için işinize yarayacaktır. Ayrıca **phishing** için de gereklidir. Üstelik bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** verir; bu da phishing kampanyası için faydalıdır.

## Credential Leak'leri

**Domain**, **subdomain** ve **e-posta** bilgileriyle, bu e-posta adreslerine ait geçmişte leak olmuş kimlik bilgilerini aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Güvenlik açıklarını arama**

**Geçerli ve leak olmuş** kimlik bilgileri bulursanız bu, kolay bir başarıdır.

## Secret Leak'leri

Credential leak'leri, **hassas bilgilerin leak edilip satıldığı** şirket hack'leriyle ilgilidir. Ancak şirketler, bilgileri bu veritabanlarında bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leak'leri

Kimlik bilgileri ve API'ler, şirketin **public repository**'lerinde veya o github şirketinde çalışan **kullanıcıların** repository'lerinde leak edilmiş olabilir.\
Bir **kuruluşun** ve **geliştiricilerinin** tüm **public repo**'larını **indirmek** ve üzerlerinde [**gitleaks**](https://github.com/gitleaks/gitleaks) aracını otomatik olarak çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, kendisine **verilen URL'lerdeki** tüm **metinler** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfalarında da secret'lar bulunur**.

#### Github Dorks

Kuruluşta arama yapmak için kullanabileceğiniz olası **GitHub dorks**'ları [GitHub dorks and leaks sayfasında](github-leaked-secrets.md) bulabilirsiniz.

### Paste Leak'leri

Saldırganlar veya çalışanlar bazen şirket içeriğini bir paste sitesinde **yayınlar**. Bu içerik **hassas bilgiler** içerebilir de içermeyebilir de; yine de aramakta fayda var.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki Google dorks, **orada olmaması gereken dışarıya açık bilgileri** bulmak için her zaman işe yarar. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) veritabanında elle çalıştıramayacağınız **binlerce** olası sorgunun bulunmasıdır. Bu nedenle, en sevdiğiniz 10 sorguyu seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Standart Google tarayıcısını kullanarak tüm veritabanını taramayı amaçlayan araçların işi hiçbir zaman bitmez; çünkü Google sizi çok kısa sürede engeller._

### **Güvenlik açıklarını arama**

**Geçerli ve leak olmuş** kimlik bilgileri veya API token'ları bulursanız bu, kolay bir başarıdır.

## Public Code Güvenlik Açıkları

Şirketin **open-source kodu** olduğunu bulursanız, bu kodu **analiz edip** içindeki **güvenlik açıklarını** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır; [source-code review araçları](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca, aşağıdakiler gibi **public repository'leri taramanıza** olanak tanıyan ücretsiz hizmetler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **güvenlik açıklarının** büyük **çoğunluğu** **web uygulamalarında** bulunur. Bu nedenle bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum. [**Bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünü özellikle belirtmek isterim. Çok hassas güvenlik açıkları bulmalarını beklememeniz gerekse de, **ilk web bilgilerini edinmek için workflow'lara eklemek** kullanışlıdır.

## Özet

> Tebrikler! Bu noktada **tüm temel keşif işlemlerini** tamamladınız. Evet, bunlar temel işlemler; çünkü çok daha fazla keşif yapılabilir (ileride daha fazla numara göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (kapsam dâhilindeyse bazı vuln scan işlemleri de yaptınız)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lere ait tüm **subdomain**'leri buldunuz (subdomain takeover var mı?)
5. Kapsamdaki tüm **IP**'leri buldunuz (**CDN'lerden gelenleri ve gelmeyenleri**).
6. Tüm **web sunucularını** buldunuz ve ekran görüntülerini aldınız (daha yakından bakmaya değecek tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Kolayca **büyük bir başarı** sağlayabilecek **e-postaları**, **credential leak'lerini** ve **secret leak'lerini** buldunuz.
9. Bulduğunuz tüm web sitelerinde **pentesting** yaptınız

## **Tam Recon Otomasyon Araçları**

Belirli bir kapsama yönelik önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor



## References

- [1] [Jason Haddix – Bug Hunter'ın Metodolojisi v4.0: Recon Sürümü](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon'lar Hakkında: Tarayıcı Simgelerinden Attack Surface Intelligence'a](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty'ler, OSINT ve Daha Nicesi için favicon.ico'yu Weaponize Etmek](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerinde Zaman Korelasyonu Saldırısıyla Domain Keşfetme](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif Takeover: Pahalı Bir Subdomain Takeover Kampanyasını Ortaya Çıkarma (ve Taklit Etme)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Benzersiz Bir Yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Tam Subdomain Keşif Workflow'u, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest Workflow'u Kullanarak Tam Subdomain Brute-Force Keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
