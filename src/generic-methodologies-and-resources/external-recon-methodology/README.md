# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

> Size bir şirkete ait her şeyin scope içinde olduğu söylendi ve bu şirketin gerçekte nelere sahip olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** bulmaktır. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın almalarını bulun; bu, scope içindeki şirketleri belirlemenizi sağlar.
2. Her şirketin ASN'si (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını belirlemenizi sağlar.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, alan adları...) aramak için reverse whois sorguları kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için Shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanın (`ssl` yöntemi yinelemeli olarak kullanılabilir).

### **Satın almalar**

Öncelikle, **ana şirkete ait diğer şirketleri** öğrenmemiz gerekiyor.\
Bunun bir yolu, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi aramak** ve "**acquisitions**" bölümüne **tıklamaktır**. Burada ana şirketin satın aldığı diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR başvurularını**, **yatırımcı ilişkileri** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve bağlı ortaklıklar için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada scope içindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımıza bakalım.

### **ASN'ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip **IP adresi bloklarından** oluşur. Tek bir kuruluş tarafından yönetilir, ancak birden fazla operatörden oluşabilir.

Şirketin **IP aralıklarını** bulmak için kendisine atanmış bir **ASN'si olup olmadığını** öğrenmek faydalıdır. **Scope** içindeki tüm **hostlara** karşı bir **güvenlik açığı testi** yapmak ve bu IP'lerdeki **alan adlarını aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) adreslerinde şirket **adına**, **IP'ye** veya **alan adına** göre **arama yapabilirsiniz**.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için şu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda, muhtemelen tüm** faydalı bilgiler **(IP aralıkları ve Whois)** ilk bağlantıda zaten yer alır.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'nin** enumeration işlemi, tarama sonunda ASN'leri otomatik olarak toplar ve özetler.

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

Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) üzerinden de bulabilirsiniz (ücretsiz API'si var).\
Bir domain'in IP ve ASN bilgilerini [http://ipv4info.com/](http://ipv4info.com) üzerinden bulabilirsiniz.

### **Zafiyet arama**

Bu noktada **scope içindeki tüm varlıkları biliyoruz**, bu nedenle izin veriliyorsa tüm host'larda bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) çalıştırabilir **veya** açık portları **bulmak için** Shodan, Censys ya da ZoomEye gibi servisleri **kullanabilirsiniz**. Bulduklarınıza bağlı olarak, çalışan olası çeşitli servislerin pentest'inin nasıl yapılacağını öğrenmek için bu kitaba göz atmalısınız.\
**Ayrıca, varsayılan kullanıcı adı ve** parola **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **ile servisleri bruteforce etmeyi deneyebileceğinizi de belirtmekte fayda var.**

## Domain'ler

> Scope içindeki tüm şirketleri ve varlıklarını biliyoruz; şimdi scope içindeki domain'leri bulma zamanı.

_Aşağıda önerilen tekniklerle subdomain'ler de bulabileceğinizi ve bu bilgiyi göz ardı etmemeniz gerektiğini unutmayın._

Öncelikle her şirketin **ana domain(lerini)** bulmalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domain'lerin tüm IP aralıklarını bulduğunuza göre, **scope içindeki daha fazla domain'i bulmak için** bu **IP'lerde reverse DNS lookup** yapmayı deneyebilirsiniz. Kurbanın DNS sunucularından birini veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Geniş aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar, reverse lookup işlemlerini ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kurum adı**, **adres**, **e-posta adresleri**, telefon numaraları gibi pek çok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olanı, bu alanlardan herhangi birini kullanarak **reverse whois lookup** yaptığınızda **şirketle ilişkili daha fazla asset** bulabilmenizdir (örneğin, aynı e-posta adresinin bulunduğu diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web arayüzü **ücretsiz**, API ücretsiz değil.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 arama ücretsiz**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Ücretsiz değil (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Ücretsiz değil (API)

Bu görevi [**DomLink**](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API key gerektirir).\
[amass](https://github.com/OWASP/Amass) ile otomatik reverse whois keşfi de yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

İki farklı sayfada aynı tracker'ın **aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID**'sini veya aynı **Adsense ID**'sini görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/trackers bilgilerine göre ilişkili siteleri bulur)
- [**StackScan**](https://www.stackscan.com) - **Ücretsiz katman** (Web ve API). Yalnızca tracker ID'lerine değil, sunulan herhangi bir asset'e göre arama yapar: bir script yolu, self-hosted bir bundle adı veya bir asset'in yüklendiği host. Böylece bu asset'i barındıran tüm siteleri listeler.

API, tek bir domain için stack'i döndürür; bu, aday bir asset'in aynı varlık grubuna ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Tespit edilen her teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, alan adı başına sorgulamayı destekler.

### **Favicon**

Aynı favicon icon hash’ini arayarak hedefimizle ilişkili alan adlarını ve alt alan adlarını bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tam olarak bunu yapar. İşte nasıl kullanacağınız:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash'ini paylaşan alan adlarını keşfetmek için kullanıldı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash'ine sahip alan adlarını keşfetmemizi sağlar.

![favihash çıktısı, aynı favicon hash'ine sahip alan adlarını keşfetmek için kullanıldı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Bilinen bir favicon hash'ini Shodan veya FOFA'da pivot olarak kullanarak aynı teknolojinin internete açık diğer örneklerini bulun.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini hesaplamanın** yolu (favicon baytlarının **base64 kodlanmış** hali üzerinde MMH3):

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

Favicon hash'lerini [**httpx**](https://github.com/projectdiscovery/httpx) ile büyük ölçekte de alabilirsiniz (`httpx -l targets.txt -favicon`) ve ardından Shodan/Censys'te pivot edebilirsiniz.

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, bir gösterge olarak değerlendirin**: MMH3 kompakt bir hash'tir; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı taklitler mümkündür.
- **Yalnızca** `/favicon.ico` **yolunu sorgulamayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik varlıklara WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: ikonu doğrudan isteyin ve `ETag`, `Last-Modified`, yönlendirmeleri ve cache header'larını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: title'ı, HTML/body hash'ini, header'ları, TLS sertifikası subject/SAN'larını, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümeleyin**: tutarlı bir template fingerprint'i güçlendirir; farklı template'ler genel veya paylaşılan bir ikona işaret eder.
- **İlgisiz signature'larda, portlarda ve ürünlerde görünen bir hash'i olası bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı var olmayan bir yolla** (örneğin `/_favicon_probe_<8-hex>`) **karşılaştırın**; eşleşen hosting veya park sayfası yanıtları, paylaşılan ikonu açıklayabilir.
- **Triage işlemini, favicon hash'lerini ürünlere ve CPE'lere eşleyen Nuclei detection rule'ları veya herkese açık veri kümeleriyle başlatın.**
- **IP odaklı kapsama açığını unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast ve yalnızca domain üzerinden erişilen yüzeyler Shodan benzeri veri kümelerinde yer almayabilir.

### **Telif Hakkı / Benzersiz string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde ortak olabilecek string'leri** arayın. **Telif hakkı string'i** buna iyi bir örnek olabilir. Ardından bu string'i **google**'da, diğer **tarayıcılarda** ve hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron job kullanılması yaygındır:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

bir sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency günlüklerindeki konumları ilişkilendirmek, bağlantılı alan adlarını ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** günlüklerini doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı dmarc bilgilerini paylaşan alan adlarını ve alt alan adlarını** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Diğer kullanışlı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Terk edilmiş bir A record, bir cloud provider IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturup adresini passive DNS verileriyle ilişkilendiren fırsatçı bir iş akışını gösteriyor; takeover senaryolarını yalnızca yetkili kapsam dâhilinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yollar**

Yeni bir alan adı bulduğunuzda uygun keşif pivotlarını tekrarlayın: her sonuç, ilk seed'den görülemeyen ek sertifika adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanına sahip kuruluşun adını zaten biliyorsunuz. Shodan'da şu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan host'larda TLS sertifikasında geçen yeni ve beklenmeyen alan adlarını kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişip **Organisation name**'i alabilir, ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS certificates**'ı içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ana alan adıyla **ilişkili alan adlarını** ve bunların **alt alan adlarını** arayan bir araçtır; oldukça etkileyicidir.

**Passive DNS / Geçmiş DNS**

Passive DNS verileri hâlâ çözümlenen veya takeover edilebilecek **eski ve unutulmuş kayıtları** bulmak için harikadır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Güvenlik açıklarını arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Bir şirket bir **alan adını kullanıyor** olabilir, ancak **sahipliğini kaybetmiş** olabilir. (Yeterince ucuzsa) alan adını kaydedin ve şirkete haber verin.

Varlık keşfi sırasında bulduklarınızdan **farklı bir IP'ye sahip bir alan adı** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan hizmetlere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı püf noktaları** bulabilirsiniz.\
_Bazen alan adının, istemcinin kontrolünde olmayan bir IP üzerinde barındırıldığını ve bu nedenle kapsam dışında olduğunu unutmayın; dikkatli olun._

## Alt alan adları

> Kapsam dâhilindeki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm alan adlarını biliyoruz.

Şimdi bulunan her alan adının olası tüm alt alan adlarını bulma zamanı.

> [!TIP]
> Alan adlarını bulmak için kullanılan bazı araç ve tekniklerin alt alan adlarını bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **alt alan adları** bulmaya çalışalım. **Zone Transfer**'ı da denemeliyiz (Güvenlik açığı varsa rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Çok sayıda alt alan adı edinmenin en hızlı yolu harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/OWASP/Amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Edu4rdSHL/findomain/)

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

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Alt alan adlarını elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır.

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**JLDC ücretsiz API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** verilen bir domain için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri toplar.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'de JS dosyalarını ararlar ve bu dosyalardan subdomain'leri çıkarırlar.

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

- [**securitytrails.com**](https://securitytrails.com/) subdomain'leri ve IP geçmişini aramak için ücretsiz bir API sunar
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, bug-bounty programlarıyla ilişkili tüm subdomain'leri **ücretsiz** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) aracılığıyla da erişebilir veya bu projenin kullandığı scope'a [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) adresinden ulaşabilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP adreslerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının listesini oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirip filtrelemek üzere [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force işlemi gerçekleştiren ilk araç buydu. Çok hızlıdır ancak yanlış pozitif sonuçlara açıktır.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), Go ile yazılmış bir `massdns` wrapper'ıdır. Aktif brute force kullanarak geçerli alt alan adlarını enumerate etmenize, wildcard handling ile alt alan adlarını çözümlemenize ve kolay input-output desteğinden yararlanmanıza olanak tanır.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns` de kullanır.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), alan adlarını asenkron olarak brute force ile denemek için asyncio kullanır.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### İkinci DNS Brute-Force Turu

Açık kaynakları kullanarak ve brute-force yaparak alt alan adlarını bulduktan sonra, daha fazlasını bulmaya çalışmak için bulunan alt alan adlarının varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'lerden permütasyonlar oluşturur.
  - goaltdns permütasyon **wordlist**'ini [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) edinebilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur. Permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutation'ları oluşturmanın yanı sıra bunları resolve etmeyi de deneyebilir (ancak önceki yorumlarda belirtilen araçları kullanmak daha iyidir).
  - altdns permutation'larının **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permütasyonlarını, mutasyonlarını ve değişikliklerini yapmak için başka bir araç. Sonuçları brute force ile arar (DNS wildcard'ı desteklemez).
  - dmut permütasyon wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain'e dayanarak, daha fazla subdomain keşfetmek için belirtilen pattern'lere göre **yeni olası subdomain adları üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'ler öğrenir ve çözümlenmek üzere aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili, DNS yanıtı rehberli bir algoritmayla çalışan bir subdomain brute-force fuzzer'ıdır. Tailored wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan girdi verilerini kullanarak eşleşen başka domain adlarını doğru şekilde sentezler ve DNS taraması sırasında elde edilen bilgilere dayanarak bunları döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, o IP'de web sitesi bulunan **başka subdomain'ler bulmayı** deneyebilirsiniz. Bunun için **OSINT kaynaklarında** bir IP'deki domain'leri arayabilir veya o IP'deki VHost domain adlarına **brute force uygulayabilirsiniz**.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerdeki bazı VHost'ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı subdomain'lerin gizlenmiş olabileceğinden şüpheleniyorsanız, brute force uygulamayı deneyebilirsiniz:

Name-based vhost'lar için `Host` header'ını fuzz edin ve varsayılan yanıtı filtrelemek üzere ffuf'un auto-calibration özelliğini kullanın.<sup>[[2]](#references)</sup>

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
> Bu teknikle internal/hidden endpoint’lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header’ında geçerli bir domain/subdomain belirtildiğinde _**Access-Control-Allow-Origin**_ header’ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain’ler** **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Subdomain ararken herhangi bir tür **bucket**'a **yönelip yönelmediğini** kontrol edin; böyle bir durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada scope içindeki tüm domain'leri biliyor olacağınız için olası bucket adlarına [**brute force uygulamayı ve izinleri kontrol etmeyi**](../../network-services-pentesting/pentesting-web/buckets/index.html) deneyin.

### **İzleme**

[sublert ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) aracının yaptığı gibi **Certificate Transparency** Logs'u izleyerek bir domain'e ait **yeni subdomain'ler** oluşturulup oluşturulmadığını **izleyebilirsiniz**.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Subdomain** bir **S3 bucket**'a yöneliyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Varlık keşfinde bulduklarınızdan **farklı bir IP'ye sahip bir subdomain** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Çalışan servislere bağlı olarak **bu kitapta onlara "saldırmak" için bazı püf noktaları** bulabilirsiniz.\
_Bazen subdomain'in, client tarafından kontrol edilmeyen ve bu nedenle scope dışında olan bir IP üzerinde barındırıldığını unutmayın; dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP aralıkları, domain'ler ve subdomain'ler** bulmuş olabilirsiniz.\
Şimdi bu aralıklardaki ve **domain/subdomain'lerle ilişkili tüm IP'leri (DNS sorgularıyla) toplama** zamanı.

Aşağıdaki **ücretsiz API'lerden** yararlanarak domain ve subdomain'lerin kullandığı **önceki IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) yöntemleri bulmanıza yardımcı olabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Belirli bir IP adresine yönelen domain'leri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'lere port scan uygulayın** (çünkü CDN'lerde muhtemelen ilginizi çekecek bir şey bulamazsınız). Bulunan çalışan servislerde **zafiyetler** keşfedebilirsiniz.

Host'ların nasıl taranacağıyla ilgili bir [**kılavuz**](../pentesting-network/index.html) **bulun.**

## Web sunucularını arama

> Tüm şirketleri ve varlıklarını bulduk; scope içindeki IP aralıklarını, domain'leri ve subdomain'leri biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen **IP'ler ve domain'ler üzerinde recon** gerçekleştirdiniz; bu nedenle olası **tüm web sunucularını** zaten bulmuş olabilirsiniz. Bulmadıysanız, şimdi scope içindeki web sunucularını bulmak için bazı **hızlı yöntemlere** bakacağız.

Bunun **web app keşfine yönelik** olduğunu unutmayın; bu nedenle scope **izin veriyorsa** zafiyet taraması ve port taraması da **yapmalısınız**.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemini burada bulabilirsiniz**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını bulmak için kullanabileceğiniz bir diğer pratik araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi verirsiniz; araçlar 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portları da denemelerini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Artık kapsamda bulunan **tüm web sunucularını** (şirketin **IP**'leri ile tüm **domain** ve **subdomain**'leri arasından) keşfettiğinize göre, muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Öyleyse işi basitleştirip hepsinin ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya** **bakarak**, **savunmasız olma ihtimali daha yüksek** olan **tuhaf** endpoint'ler bulabilirsiniz.

Bu öneriyi uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, tüm **ekran görüntülerini** [**eyeballer**](https://github.com/BishopFox/eyeballer) ile inceleyerek **hangilerinin muhtemelen güvenlik açığı barındırdığını** ve hangilerinin barındırmadığını belirleyebilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için **önce şirketi tanımlayan anahtar kelimelerin bir listesini oluşturmalısınız**. Örneğin, bir crypto şirketi için şu tür kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca, **bucket'larda yaygın olarak kullanılan kelimelerden** oluşan wordlist'lere ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permütasyonlar** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **AWS'deki bucket'larla yetinmemeniz gerektiğini** unutmayın.

### **Güvenlik açıklarını arama**

**Açık bucket'lar veya dışarıya açık cloud function'lar** gibi şeyler bulursanız, bunlara **erişip** neler sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## E-postalar

Kapsamdaki **domain** ve **subdomain**'lerle e-posta aramaya başlamak için gereken her şeye sahipsiniz. Bir şirkete ait e-postaları bulmak için en iyi sonuç veren **API**'ler ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Güvenlik açıklarını arama**

E-postalar, daha sonra **web girişlerine ve auth servislerine** (SSH gibi) **brute-force** uygularken işinize yarayacak. Ayrıca **phishing** için de gereklidir. Üstelik bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** sağlayarak phishing kampanyasına yardımcı olur.

## Kimlik Bilgisi Leak'leri

**Domain**'ler, **subdomain**'ler ve **e-postalar** ile bu e-postalara ait geçmişte leak edilmiş kimlik bilgilerini aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Güvenlik açıklarını arama**

**Geçerli kimlik bilgileri** bulursanız bu, kolayca elde edilmiş bir başarıdır.

## Secret Leak'leri

Kimlik bilgisi leak'leri, **hassas bilgilerin leak edilip satıldığı** şirket hack'leriyle ilişkilidir. Ancak şirketler, bilgileri bu veritabanlarında bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leak'leri

Şirketin **public repository**'lerinde veya o Github şirketinde çalışan **kullanıcıların** repository'lerinde kimlik bilgileri ve API'ler leak edilmiş olabilir.\
Bir **organizasyonun** ve geliştiricilerinin tüm **public repo**'larını **indirmek** ve üzerlerinde [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, kendisine verilen **URL'lerdeki tüm metinler** üzerinde de **gitleaks** çalıştırmak için kullanılabilir; çünkü bazen **web sayfalarında da secret'lar bulunur**.

#### Github Dorks

Organizasyonda arayabileceğiniz olası **GitHub dorks** için [GitHub dorks and leaks page](github-leaked-secrets.md) sayfasına bakın.

### Paste Leak'leri

Bazen saldırganlar veya çalışanlar, şirket içeriğini bir paste sitesinde **yayınlar**. Bu içerik **hassas bilgi** içerebilir de içermeyebilir de, ancak aramakta fayda var.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama etkili Google dorks, **orada olmaması gereken açık bilgileri bulmak** için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde elle çalıştıramayacağınız birkaç **bin** olası sorgu bulunmasıdır. Bu nedenle, en sevdiğiniz 10 sorguyu seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Standart Google tarayıcısını kullanarak veritabanının tamamını çalıştırmayı bekleyen araçların işlemi asla bitmez; çünkü Google sizi çok kısa sürede engeller._

### **Güvenlik açıklarını arama**

**Geçerli, leak edilmiş** kimlik bilgileri veya API token'ları bulursanız bu, kolayca elde edilmiş bir başarıdır.

## Public Code Güvenlik Açıkları

Şirketin **open-source kodu** olduğunu fark ederseniz, kodu **analiz edip** içindeki **güvenlik açıklarını** arayabilirsiniz.

**Kullanılan dile bağlı olarak** farklı **araçlar** kullanabilirsiniz; liste için [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) bölümüne bakın.

Ayrıca, aşağıdakiler gibi **public repository'leri taramanıza** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **güvenlik açıklarının çoğu** **web uygulamalarında** bulunur. Bu nedenle bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum; bu [**bilgilere buradan ulaşabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünü özellikle belirtmek isterim. Bu araçların çok hassas güvenlik açıkları bulmasını beklememelisiniz; ancak ilk web bilgilerini edinmek için bunları **workflow'lara eklemek** faydalı olur.

## Özet

> Tebrikler! Bu noktada **temel keşif işlemlerinin** hepsini tamamladınız. Evet, bunlar temel işlemler; çünkü daha birçok keşif işlemi yapılabilir (ileride başka yöntemler de göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (ve kapsama dahilse bazı vuln scan işlemleri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lerin tüm **subdomain**'lerini buldunuz (subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP**'leri buldunuz (**CDN'lerden gelen ve gelmeyen**)
6. Tüm **web sunucularını** bulup ekran görüntülerini aldınız (daha yakından incelenmesi gereken tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Kolayca **büyük bir başarı** sağlayabilecek **e-postaları**, **kimlik bilgisi leak**'lerini ve **secret leak**'lerini buldunuz.
9. Bulduğunuz tüm web sitelerinde **pentesting yaptınız**

## **Tam Kapsamlı Recon Otomasyon Araçları**

Belirli bir kapsam üzerinde önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar bulunmaktadır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

## References

- [1] [Jason Haddix – Bug Hunter Metodolojisi v4.0: Recon Sürümü](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon'lar Üzerine: Tarayıcı Simgelerinden Saldırı Yüzeyi İstihbaratına](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty'ler, OSINT ve Daha Neler İçin favicon.ico'yu Silahlandırmak](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerindeki Zaman Korelasyonu Saldırısıyla Domain'leri Keşfetmek](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif Takeover: Pahalı Bir Subdomain Takeover Kampanyasını Ortaya Çıkarmak (ve Taklit Etmek)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Özgün Bir Yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Tam Subdomain Keşif Workflow'u, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest Workflow'u Kullanarak Tam Subdomain Brute-Force Keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
