# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

> Bir şirkete ait her şeyin scope içinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirketin sahip olduğu tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** bulmaktır. Bunun için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın aldığı şirketleri bulun. Bu, scope içindeki şirketleri belirlemenizi sağlar.
2. Her şirketin ASN'sini (varsa) bulun. Bu, her şirketin sahip olduğu IP aralıklarını belirlemenizi sağlar.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois sorgularını kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanın (`ssl` yöntemi yinelemeli olarak kullanılabilir).

### **Satın almalar**

Öncelikle, **ana şirketin sahibi olduğu diğer şirketleri** öğrenmemiz gerekiyor.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret edip **ana şirketi aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirketin satın aldığı diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** başlığını aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve bağlı kuruluşlar için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada scope içindeki tüm şirketleri biliyor olmalısınız. Varlıklarını nasıl bulacağımızı öğrenelim.

### **ASN'ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici ağlara erişim için açıkça tanımlanmış bir politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir; ancak birden fazla operatörden oluşabilir.

**IP aralıklarını** bulmak için şirketin herhangi bir **ASN**'si olup olmadığını öğrenmek faydalıdır. **Scope** içindeki tüm **host'lara** karşı bir **vulnerability testi** gerçekleştirmek ve bu IP'lerdeki **domain'leri aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) adreslerinde şirket **adına**, **IP'ye** veya **domain'e** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak daha fazla veri toplamak için şu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Ancak, muhtemelen tüm faydalı bilgiler (**IP aralıkları ve Whois**) zaten ilk bağlantıda yer almaktadır.**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'nin** enumeration'ı tarama sonunda ASN'leri otomatik olarak toplar ve özetler.

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

Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) adresini kullanarak da bulabilirsiniz (ücretsiz API'si var).\
Bir alan adının IP ve ASN bilgilerini [http://ipv4info.com/](http://ipv4info.com) adresini kullanarak bulabilirsiniz.

### **Güvenlik açıklarını arama**

Bu noktada **kapsam içindeki tüm varlıkları** biliyoruz; bu nedenle izniniz varsa tüm sunucularda bir **güvenlik açığı tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) çalıştırabilir **veya** Shodan, Censys ya da ZoomEye gibi servisleri **kullanarak** açık portları **bulabilirsiniz. Bulduklarınıza bağlı olarak, çalışan çeşitli olası servislerin pentest'ini nasıl yapacağınızı öğrenmek için bu kitaba göz atmalısınız.**\
**Ayrıca, bazı varsayılan kullanıcı adı ve** parola **listeleri hazırlayıp [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servisleri** bruteforce **etmeyi deneyebileceğinizi de belirtmekte fayda var.**

## Domains

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz; şimdi kapsam içindeki alan adlarını bulma zamanı.

_Aşağıda önerilen tekniklerle alt alan adlarını da bulabileceğinizi ve bu bilgilerin göz ardı edilmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana alan adını** (veya alan adlarını) bulmalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Alan adlarının tüm IP aralıklarını bulduğunuz için, **kapsam içindeki daha fazla alan adını bulmak üzere bu IP'lerde reverse dns lookup** yapmayı deneyebilirsiniz. Kurbanın bir dns sunucusunu veya iyi bilinen bir dns sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Geniş aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar, ters sorgulamaları ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e-posta adresleri**, telefon numaraları gibi birçok ilgi çekici **bilgi** bulabilirsiniz... Ancak daha da ilgi çekici olan, bu alanlardan herhangi birini kullanarak **ters whois sorgulamaları yaptığınızda** şirketle ilişkili **daha fazla varlık** bulabilmenizdir (örneğin, aynı e-posta adresinin bulunduğu başka whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **ücretsiz**, API ücretli.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Ücretsiz değil (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Ücretsiz değil (API)

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (whoxy API anahtarı gerektirir).\
[amass](https://github.com/OWASP/Amass) ile otomatik ters whois keşfi de yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir etki alanı bulduğunuzda daha fazla etki alanı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

Farklı iki sayfada aynı tracker'ın **aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID**'yi görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/trackers üzerinden ilişkili siteleri bulur)
- [**StackScan**](https://www.stackscan.com) - **Ücretsiz katman** (Web ve API). Yalnızca tracker ID'lerine değil, sunulan herhangi bir varlığa göre arama yapın: bir script yolu, kendi barındırdığınız bir bundle adı veya bir varlığın yüklendiği host. Bu arama, söz konusu varlığı barındıran tüm siteleri döndürür.

API, tek bir etki alanının stack'ini döndürür. Bu, bulunan bir varlığın aynı dijital varlık grubuna ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Tespit edilen her teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, alan adı başına aramayı kapsar.

### **Favicon**

Aynı favicon simge hash’ine bakarak hedefimizle ilişkili alan adlarını ve alt alan adlarını bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. Nasıl kullanılacağı şöyle:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash değerini paylaşan domain’leri keşfetmek için kullanılır](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse favihash, hedefimizle aynı favicon icon hash değerine sahip domain’leri keşfetmemizi sağlar.

![Aynı favicon hash değerine sahip domain’leri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA’da pivot olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini** şöyle **hesaplayabilirsiniz** (favicon'ın **base64 ile kodlanmış** baytları üzerinde MMH3):

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

Favicon hash'lerini [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile büyük ölçekte de alabilir, ardından Shodan/Censys'te pivot edebilirsiniz.

Favicon parmak izlerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, gösterge olarak değerlendirin**: MMH3 kompakttır; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı sahtecilik mümkündür.
- **Yalnızca** `/favicon.ico` **yolunu sorgulamayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik varlıklara WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: İkona doğrudan istek gönderin ve `ETag`, `Last-Modified`, yönlendirmeleri ve cache başlıklarını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: title'ı, HTML/body hash'ini, başlıkları, TLS sertifikası subject/SAN'larını, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümelendirin**: Tutarlı bir template, parmak izini güçlendirir; farklı template'ler genel veya paylaşılan bir ikona işaret eder.
- **Bir hash'in ilgisiz imzalar, portlar ve ürünlerde görünmesini olası bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı var olmayan bir yolla karşılaştırın**; örneğin `/_favicon_probe_<8-hex>`. Barındırma veya park sayfalarına ait yanıtların eşleşmesi, ortak ikonu açıklayabilir.
- **Favicon hash'lerini ürünlere ve CPE'lere eşleyen Nuclei detection kuralları veya herkese açık veri kümeleriyle ön incelemeyi başlatın.**
- **IP merkezli kapsama boşluğunu unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast ve yalnızca domain üzerinden erişilebilen yüzeyler Shodan benzeri veri kümelerinde bulunmayabilir.

### **Copyright / Uniq string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde ortak olabilecek dizeleri** arayın. **Copyright dizesi** buna iyi bir örnek olabilir. Ardından bu dizeyi **google**'da, diğer **tarayıcılarda** veya hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şöyle bir cron job'a sahip olmak yaygındır:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency log konumlarını ilişkilendirmek, bağlantılı domain'leri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı DMARC bilgilerini paylaşan domain ve subdomain'leri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesi veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir araç kullanabilirsiniz.\
Diğer faydalı araçlar arasında [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/) bulunur.

### **Passive Takeover**

Terk edilmiş bir A kaydı, cloud sağlayıcısı bir IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturup adresini passive DNS verileriyle ilişkilendiren fırsatçı bir iş akışını gösteriyor; takeover senaryolarını yalnızca yetkili kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir domain bulduğunuzda ilgili keşif pivotlarını tekrarlayın: her sonuç, başlangıçtaki seed'den görünmeyen ek sertifika adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan host'larda TLS sertifikasında geçen yeni ve beklenmedik domain'leri kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişip **Organisation name**'i alabilir, ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS certificates**'ı içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), bir ana domain ile **ilişkili domain'leri** ve bunların **subdomain'lerini** arayan bir araçtır; gerçekten etkileyici.

**Passive DNS / Geçmiş DNS**

Passive DNS verileri, hâlâ çözümlenen veya takeover edilebilecek **eski ve unutulmuş kayıtları** bulmak için çok kullanışlıdır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Güvenlik açıklarını arama**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) olup olmadığını kontrol edin. Belki bir şirket **bir domain kullanıyordur**, ancak **domain'in sahipliğini kaybetmiştir**. (Yeterince ucuzsa) domain'i kaydedin ve şirkete haber verin.

Varlık keşfi sırasında bulduğunuz IP'lerden **farklı bir IP'ye sahip bir domain** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen domain'in istemci tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve dolayısıyla kapsam dışında olduğunu unutmayın; dikkatli olun._

## Subdomain'ler

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm domain'leri biliyoruz.

Bulduğumuz her domain'in olası tüm subdomain'lerini bulma zamanı.

> [!TIP]
> Domain bulmak için kullanılan bazı araç ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **subdomain'leri** bulmaya çalışalım. **Zone Transfer**'ı da denemeliyiz (Güvenlik açığı varsa bunu rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Altyapı, itibar, ihlal kayıtları ve alt alan adı keşfinin ötesindeki zenginleştirme işlemlerini kapsayan API'ler ve platformlar için [Keşif ve Tehdit İstihbaratı API kataloğu](reconnaissance-and-threat-intelligence-apis.md) sayfasına bakın.

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

Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar da alt alan adlarını bulmak için yararlı olabilecek **başka ilginç araçlar/API’ler** de vardır:

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

- [**gau**](https://github.com/lc/gau)**:** verilen bir domain için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayıp JS dosyalarını bulur ve bunlardan subdomain'leri çıkarırlar.

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

- [**Censys subdomain bulucu**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) subdomain ve IP geçmişini aramak için ücretsiz bir API sunar
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, bug-bounty programlarıyla ilişkili tüm subdomain'leri **ücretsiz** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) üzerinden de erişebilir, hatta projenin kullandığı scope'a [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) adresinden ulaşabilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı yaygın **subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının listesini oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şu listeyi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force işlemi gerçekleştiren ilk araçtı. Çok hızlıdır ancak yanlış pozitif sonuçlar verme eğilimindedir.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), Go ile yazılmış `massdns` için bir wrapper'dır. Active bruteforce kullanarak geçerli subdomain'leri enumerate etmenin yanı sıra, wildcard handling ve kolay input-output desteğiyle subdomain'leri resolve etmeyi sağlar.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns` de kullanır.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), alan adlarını eşzamansız olarak brute force etmek için asyncio kullanır.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### İkinci DNS Brute-Force Turu

Açık kaynakları kullanarak ve brute-force yaparak subdomain’leri bulduktan sonra, daha fazlasını bulmayı denemek için bulunan subdomain’lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain’lerden permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'ler için permütasyonlar üretir.
  - goaltdns permütasyon **wordlist**'ini [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur. Permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları oluşturmanın yanı sıra, bunları çözümlemeyi de deneyebilir (ancak önceki açıklanan araçları kullanmak daha iyidir).
  - altdns permütasyonları için **wordlist**'i [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adları üzerinde permütasyonlar, mutasyonlar ve değişiklikler yapmak için kullanılan başka bir araç. Sonuçları brute force ile bulur (DNS wildcard desteği yoktur).
  - dmut permütasyonları için kelime listesini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, daha fazla subdomain keşfetmek için belirtilen pattern'lere göre yeni olası subdomain adları **üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'ler öğrenir ve çözümlenmek üzere aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili, DNS yanıtlarıyla yönlendirilen bir algoritmayla çalışan bir subdomain brute-force fuzzer'dır. Sağlanan özel bir wordlist veya geçmiş DNS/TLS kayıtları gibi girdi verilerini kullanarak bunlarla eşleşen daha fazla domain adını doğru şekilde üretir ve DNS taraması sırasında toplanan bilgilere dayanarak bunları döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Alt Alan Adı Keşif İş Akışı**

Trickest iş akışı örnekleri, tekrarlanabilir alt alan adı numaralandırması için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Alt alan adlarına ait **bir veya birkaç web sayfası** barındıran bir IP adresi bulduysanız, IP'deki alan adlarını **OSINT kaynaklarında** arayarak veya o IP'de **VHost alan adlarına brute force uygulayarak** bu IP'de web sitesi bulunan başka alt alan adlarını **bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerdeki bazı VHost'ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı alt alan adlarının gizlenmiş olabileceğinden şüpheleniyorsanız, brute force uygulamayı deneyebilirsiniz:

Ad tabanlı vhost'lar için `Host` başlığını fuzz edin ve varsayılan yanıtı filtrelemek üzere ffuf'un auto-calibration özelliğini kullanın.<sup>[[2]](#references)</sup>

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
> Bu teknikle dahili/gizli endpoint'lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain belirtildiğinde _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalarla karşılaşırsınız. Bu senaryolarda, yeni **subdomain**'ler **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomain** ararken herhangi bir **bucket**'a **yönlenip yönlenmediğine** dikkat edin. Böyle bir durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada kapsamdaki tüm domain'leri biliyor olacağınız için olası bucket adlarını [**brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) gibi araçların yaptığı şekilde **Certificate Transparency** Logs'u izleyerek bir domain'in **yeni subdomain'lerinin** oluşturulup oluşturulmadığını **izleyebilirsiniz**.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**subdomain** bir **S3 bucket**'a yönleniyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Varlık keşfi sırasında bulduklarınızdan **farklı bir IP adresine sahip bir subdomain** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Çalışan servislere bağlı olarak **bu kitapta onlara "saldırmak" için bazı yöntemler bulabilirsiniz**.\
_Bazı durumlarda subdomain'in, istemci tarafından kontrol edilmeyen ve dolayısıyla kapsam içinde olmayan bir IP'de barındırıldığını unutmayın; dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP aralıkları, domain'ler ve subdomain'ler bulmuş olabilirsiniz**.\
Şimdi bu aralıklardaki **tüm IP'leri** ve **domain'ler/subdomain'ler için olanları (DNS sorgularıyla) toplama zamanı.**

Aşağıdaki **ücretsiz API'lerin** servislerini kullanarak domain'ler ve subdomain'ler tarafından kullanılan **önceki IP adreslerini** de bulabilirsiniz. Bu IP'ler hâlâ istemciye ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Belirli bir IP adresine yönlenen domain'leri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'leri port taramasından geçirin** (çünkü büyük olasılıkla CDN'lerde ilginç bir şey bulamazsınız). Keşfedilen çalışan servislerde **zafiyetler bulabilirsiniz**.

Host'ların nasıl taranacağı hakkında bir [**kılavuz**](../pentesting-network/index.html) **bulabilirsiniz.**

## Web sunucularını keşfetme

> Tüm şirketleri ve varlıklarını bulduk; kapsamdaki IP aralıklarını, domain'leri ve subdomain'leri biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen **IP'ler ve domain'ler üzerinde recon** gerçekleştirdiniz; dolayısıyla olası **tüm web sunucularını zaten bulmuş olabilirsiniz**. Ancak bulmadıysanız, şimdi kapsam içindeki web sunucularını bulmak için bazı **hızlı yöntemleri** inceleyeceğiz.

Bunun **web uygulamalarını keşfetmeye yönelik** olduğunu unutmayın; bu nedenle kapsam tarafından **izin veriliyorsa** zafiyet ve port taraması da **gerçekleştirmelisiniz**.

[**masscan** kullanarak web sunucularıyla ilgili açık portları keşfetmek için hızlı bir yöntem burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını bulmak için kullanabileceğiniz bir diğer araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi verirsiniz, araçlar 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portları da denemelerini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsamda bulunan **tüm web sunucularını** (şirketin **IP**’leri ve tüm **domain** ve **subdomain**’leri arasından) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde işi basitleştirelim ve hepsinin ekran görüntülerini alarak başlayalım. Sadece **ana sayfaya** **göz atarak** daha **savunmasız** olma ihtimali bulunan **tuhaf** endpoint’ler bulabilirsiniz.

Önerilen yöntemi uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca [**eyeballer**](https://github.com/BishopFox/eyeballer) aracını tüm **ekran görüntülerini** inceleyip hangilerinin **muhtemelen zafiyet içerdiğini** ve hangilerinin içermediğini belirlemek için kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için önce **şirketi tanımlayan anahtar kelimelerin listesini** oluşturmalısınız. Örneğin, bir crypto şirketi için `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gibi kelimeler kullanabilirsiniz.

Ayrıca **bucket’larda kullanılan yaygın kelimelerin** wordlist’lerine de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist’lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **AWS’teki bucket’lardan fazlasını aramanız** gerektiğini unutmayın.

### **Zafiyet arama**

**Açık bucket’lar veya dışarıya açık cloud functions** gibi şeyler bulursanız, bunlara **erişmeli**, neler sunduklarını ve kötüye kullanıp kullanamayacağınızı incelemelisiniz.

## E-postalar

Kapsam içindeki **domain** ve **subdomain**’lerle e-posta aramaya başlamak için gereken her şeye sahipsiniz. Şirket e-postalarını bulmak için benim en çok işime yarayan **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API’lerle
- [**https://hunter.io/**](https://hunter.io/) API’si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API’si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API’si (ücretsiz sürüm)

### **Zafiyet arama**

E-postalar daha sonra web login’lerine ve auth servislerine (SSH gibi) **brute-force** uygularken işe yarar. Ayrıca **phishing** için de gereklidir. Üstelik bu API’ler, e-postanın arkasındaki **kişi hakkında** daha fazla bilgi sağlar; bu da phishing kampanyasında faydalıdır.

## Kimlik Bilgisi Leaks

**Domain**’ler, **subdomain**’ler ve **e-postalar** sayesinde bu e-posta adreslerine ait geçmişte leak edilmiş kimlik bilgilerini aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet arama**

**Geçerli, leak edilmiş** kimlik bilgileri bulursanız, bu kolayca elde edilebilecek bir başarıdır.

## Secret Leaks

Kimlik bilgisi leak’leri, **hassas bilgilerin leak edilip satıldığı** şirket saldırılarıyla ilişkilidir. Ancak şirketler, bilgileri bu veritabanlarında bulunmayan **başka leak’lerden** de etkilenebilir:

### Github Leaks

Kimlik bilgileri ve API’ler, şirketin **public repository**’lerinde veya bu GitHub şirketi için çalışan **kullanıcıların** repository’lerinde leak edilmiş olabilir.\
[**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanarak bir **organizasyonun** ve geliştiricilerinin tüm **public repository**’lerini **indirebilir** ve üzerlerinde [**gitleaks**](https://github.com/zricethezav/gitleaks) aracını otomatik olarak çalıştırabilirsiniz.

**Leakos**, kendisine verilen tüm **metin** ve **URL’lerde** gitleaks çalıştırmak için de kullanılabilir; çünkü web sayfaları da bazen secret’lar içerir.

#### Github Dorks

Organizasyonda arama yapmak için olası **GitHub dorks**’ları [GitHub dorks and leaks sayfasında](github-leaked-secrets.md) bulabilirsiniz.

### Pastes Leaks

Bazen saldırganlar veya çalışanlar şirket içeriğini bir paste sitesinde **yayımlar**. Bu içerik **hassas bilgi** içerebilir de içermeyebilir de, ancak aramaya değer.\
Aynı anda 80’den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki Google dorks’lar, **orada olmaması gereken açık bilgileri** bulmak için her zaman işe yarar. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde elle çalıştıramayacağınız binlerce olası sorgu bulunmasıdır. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Regular Google tarayıcısını kullanarak veritabanının tamamını çalıştırmayı bekleyen araçların işlemi hiçbir zaman bitmeyeceğini unutmayın; çünkü Google sizi çok kısa sürede engeller._

### **Zafiyet arama**

**Geçerli, leak edilmiş** kimlik bilgileri veya API token’ları bulursanız, bu kolayca elde edilebilecek bir başarıdır.

## Public Code Zafiyetleri

Şirketin **open-source kodu** olduğunu bulduysanız, bu kodu analiz edip **zafiyetleri** arayabilirsiniz.

**Kullanılan dile bağlı olarak** farklı **araçlar** kullanabilirsiniz; [source-code review araçları](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca [**Snyk**](https://app.snyk.io/) gibi **public repository**’leri taramanıza olanak tanıyan ücretsiz servisler de vardır.

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter’ların bulduğu **zafiyetlerin çoğu** **web uygulamalarında** bulunur. Bu nedenle burada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum. [**Bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source araçları**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özellikle değinmek istiyorum. Bu araçların çok hassas zafiyetler bulmasını beklememelisiniz; ancak bazı başlangıç web bilgilerini elde etmek için bunları **iş akışlarına eklemek** faydalı olur.

## Özet

> Tebrikler! Bu noktada **temel keşif işlemlerinin** tamamını gerçekleştirdiniz. Evet, bunlar temel işlemler; çünkü çok daha fazla keşif yapılabilir (ileride daha fazla numara göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (kapsam içindeyse bazı vuln scan işlemleri de yaptınız)
3. Şirketlere ait tüm **domain**’leri buldunuz
4. Domain’lerin tüm **subdomain**’lerini buldunuz (subdomain takeover var mı?)
5. Kapsamdaki tüm **IP**’leri (CDN’lerden gelen ve gelmeyen) buldunuz.
6. Tüm **web sunucularını** buldunuz ve ekran görüntülerini aldınız (daha yakından incelenmeye değer tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Size kolayca **büyük bir başarı** sağlayabilecek **e-postaları**, **kimlik bilgisi leak’lerini** ve **secret leak’lerini** buldunuz.
9. Bulduğunuz tüm web’lerde **pentesting** yaptınız

## **Tam Recon Otomasyon Araçları**

Belirli bir kapsama karşı önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar mevcuttur.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncel değil

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
