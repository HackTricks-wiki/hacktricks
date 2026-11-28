# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

Ek OSINT ve web keşif projelerinin kategorilere ayrılmış listesi için [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint) bölümüne bakın.

> Bir şirkete ait her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirketin sahip olduğu tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** bulmaktır. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın aldığı şirketleri bulun; böylece kapsam dahilindeki şirketleri belirleyebilirsiniz.
2. Her şirketin ASN’sini (varsa) bulun; böylece her şirketin sahip olduğu IP aralıklarını belirleyebilirsiniz.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain’ler...) aramak için reverse whois sorgularını kullanın (bu işlem özyinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org`ve `ssl`filtreleri gibi başka teknikleri kullanın (`ssl` hilesi özyinelemeli olarak uygulanabilir).

Çözümlenen alt domain’lerden HTTP taramasına ve port keşfine geçiş için [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) bölümüne bakın.

### **Satın almalar**

Öncelikle, **ana şirketin sahip olduğu diğer şirketleri** öğrenmemiz gerekiyor.\
Bunun bir yolu, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret edip **ana şirketi aramak** ve "**acquisitions**" bölümüne **tıklamaktır**. Burada ana şirketin satın aldığı diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** bölümünü aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings** sayfalarını, **investor relations** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık’taki **Companies House**) kontrol edin.\
Küresel şirket ağaçları ve bağlı şirketler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam dahilindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımıza bakalım.

### **ASN’ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici ağlara erişim için açıkça tanımlanmış bir politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir; ancak birden fazla operatörden oluşabilir.

Şirketin **IP aralıklarını** bulmak için şirkete atanmış herhangi bir **ASN** olup olmadığını öğrenmek önemlidir. **Kapsam** dahilindeki tüm **host’lara** karşı bir **güvenlik açığı testi** yapmak ve bu IP’lerin içindeki **domain’leri aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) adreslerinde şirket **adına**, **IP’ye** ya da **domain’e** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için şu bağlantılar yararlı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda, muhtemelen tüm** yararlı bilgiler **(IP aralıkları ve Whois)** zaten ilk bağlantıda bulunur.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un** enumeration'ı tarama sonunda ASN'leri otomatik olarak toplar ve özetler.

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

Ayrıca [ASNLookup](https://asnlookup.com/) kullanarak bir kuruluşun IP aralıklarını bulabilirsiniz; sınırlı bir ücretsiz API katmanı sunar.

### **Güvenlik açıklarını arama**

Bu noktada **kapsamdaki tüm varlıkları biliyoruz**; bu nedenle izin veriliyorsa tüm hostlarda bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir **veya Shodan, Censys ya da ZoomEye gibi hizmetleri kullanarak** açık portları **bulabilirsiniz. Bulduklarınıza bağlı olarak, çalışan çeşitli olası hizmetlere nasıl pentest uygulanacağını öğrenmek için** bu kitaba göz atmalısınız.\
**Ayrıca, bazı varsayılan kullanıcı adı ve** parola **listeleri hazırlayıp [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile hizmetlere** bruteforce **uygulayabileceğinizi belirtmekte fayda var.**

## Alan adları

> Kapsamdaki tüm şirketleri ve varlıklarını biliyoruz; şimdi kapsam içindeki alan adlarını bulma zamanı.

_Lütfen, aşağıda önerilen tekniklerle alt alan adlarını da bulabileceğinizi ve bu bilgilerin hafife alınmaması gerektiğini unutmayın._

Öncelikle her şirketin **ana alan adını** bulmalısınız. Örneğin _Tesla Inc._ için bu, _tesla.com_ olacaktır.

### **Reverse DNS**

Alan adlarının tüm IP aralıklarını bulduğunuza göre, **kapsam içindeki daha fazla alan adını bulmak için** bu **IP'lerde reverse DNS sorguları** gerçekleştirmeyi deneyebilirsiniz. Kurbanın DNS sunucularından birini veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için [SecurityTrails](https://securitytrails.com/) da kullanabilirsiniz; ancak geçmiş DNS verileri ücretli plan gerektirir.\
Geniş aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar ters lookup'ları ve zenginleştirmeyi otomatikleştirmede kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e-posta adresleri**, telefon numaraları gibi pek çok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olan, bu alanlardan herhangi biriyle (örneğin aynı e-posta adresinin geçtiği diğer whois kayıtlarıyla) **reverse whois lookup** yaparak **şirketle ilişkili daha fazla varlık** bulabilmenizdir.\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web arayüzü; API ücretlidir.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Güncel DNS/alt alan adları için sınırlı ücretsiz API erişimi sunar; geçmiş veriler ve reverse lookup'lar ücretli plan gerektirir.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kaydolunca 500 ücretsiz API kredisi; sonrasında ücretlidir.

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (whoxy API anahtarı gerektirir).\
[amass](https://github.com/owasp-amass/amass) ile otomatik reverse whois keşfi de yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde daha fazla domain keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

İki farklı sayfada aynı tracker'ın **aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID'sini** veya aynı **Adsense ID'sini** görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Ücretli** web ve API hizmeti ([fiyatlandırma](https://www.stackscan.com/pricing)); şu anda ücretsiz plan sunulduğu belirtilmiyor. Yalnızca tracker ID'leriyle değil, sunulan herhangi bir varlık üzerinden pivot yapın: bir script yolu, kendi sunucunuzda barındırılan bir bundle adı veya bir varlığın yüklendiği host; araç, bunları içeren tüm siteleri döndürür.

API, tek bir domain için stack'i döndürür. Bu, aday bir varlığın aynı varlık grubuna ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Her tespit edilen teknolojiyi kategorisiyle birlikte döndürür. Varlık pivotlama şu anda yalnızca web için kullanılabilir; API, alan adı başına aramayı kapsar.

### **Favicon**

Aynı favicon simge hash'ini arayarak hedefimizle ilişkili alan adlarını ve alt alan adlarını bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte kullanım şekli:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash’ini paylaşan domain’leri keşfetmek için kullanılır](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash’ine sahip domain’leri keşfetmemizi sağlar.

![Aynı favicon hash’ine sahip domain’leri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash’ini Shodan veya FOFA pivot’u olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini hesaplamanın** yolu budur (favicon baytlarının **base64 ile kodlanmış** hâli üzerinde MMH3):

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

Ölçekli olarak [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile favicon hash'leri de alabilir, ardından Shodan/Censys'te pivot edebilirsiniz.

Favicon parmak izlerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, gösterge olarak değerlendirin**: MMH3 kompakt bir hash'tir; çakışmalar, yeniden kullanılan simgeler ve kasıtlı sahtecilik mümkündür.
- **Yalnızca** `/favicon.ico` **yolunu sorgulamayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik varlıklara WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: Simgeyi doğrudan isteyin ve `ETag`, `Last-Modified`, yönlendirmeler ile cache başlıklarını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: title'ı, HTML/body hash'ini, başlıkları, TLS sertifikası subject/SAN değerlerini, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümeleyin**: Tutarlı bir şablon parmak izini güçlendirir; farklı şablonlar ise genel veya paylaşılan bir simgeye işaret eder.
- **Bir hash'in ilgisiz imzalar, portlar ve ürünlerde görülmesini olası bir honeypot veya yer tutucu olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı mevcut olmayan bir yol ile karşılaştırın**; örneğin `/_favicon_probe_<8-hex>`. Eşleşen hosting veya park edilmiş alan adı yanıtları, paylaşılan simgeyi açıklayabilir.
- **Ürünleri ve CPE'leri favicon hash'leriyle eşleştiren Nuclei tespit kurallarından veya herkese açık veri kümelerinden yararlanarak triyaja başlayın.**
- **IP merkezli kapsam boşluğunu unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast kullanan ve yalnızca domain üzerinden erişilen yüzeyler Shodan benzeri veri kümelerinde yer almayabilir.

### **Copyright / Uniq string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde ortak olabilecek string'leri** arayın. **Copyright string'i** buna iyi bir örnek olabilir. Ardından bu string'i **Google'da**, diğer **tarayıcılarda** veya hatta **Shodan'da** arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron job olması yaygındır

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency loglarındaki konumları karşılaştırmak, ilişkili domainleri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı DMARC bilgilerini paylaşan domainleri ve alt domainleri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Bir diğer kullanışlı hizmet de [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturup adresini pasif DNS verileriyle karşılaştıran fırsatçı bir iş akışını gösteriyor; takeover senaryolarını yalnızca izin verilen kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir domain bulduğunuzda ilgili keşif pivotlarını tekrarlayın: her sonuç, ilk seed'den görünmeyen ek sertifika adlarını, pasif DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostlarda TLS sertifikasında yer alan yeni ve beklenmedik domainleri kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name** değerini alabilir, ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikalarında** şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana bir domainle **ilişkili domainleri** ve bunların **alt domainlerini** bulan, oldukça etkileyici bir araçtır.

**Pasif DNS / Geçmiş DNS**

Pasif DNS verileri, hâlâ çözümlenen veya takeover edilebilecek **eski ve unutulmuş kayıtları** bulmak için harikadır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Güvenlik açıklarını arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Bir şirket bir **domain kullanıyor** ancak **sahipliğini kaybetmiş** olabilir. (Yeterince ucuzsa) domaini kaydedip şirkete haber verin.

Varlık keşfinde bulduğunuz IP'lerden **farklı bir IP'ye sahip bir domain** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak **bu kitapta onlara "saldırmaya" yönelik bazı yöntemler** bulabilirsiniz.\
_Bazen domainin, istemci tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle kapsam dışında olduğunu unutmayın; dikkatli olun._

## Alt domainler

> Kapsamdaki tüm şirketleri, her şirkete ait tüm varlıkları ve şirketlerle ilişkili tüm domainleri biliyoruz.

Bulduğumuz her domainin olası tüm alt domainlerini bulma zamanı.

> [!TIP]
> Domainleri bulmaya yarayan bazı araç ve tekniklerin alt domainleri bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **alt domainleri** bulmaya çalışalım. Ayrıca **Zone Transfer** denemeliyiz (Güvenlik açığı varsa bunu rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Altyapı, itibar, breach kayıtları ve alt alan adı keşfinin ötesindeki zenginleştirme işlemlerini kapsayan API'ler ve platformlar için [Keşif ve Tehdit İstihbaratı API'leri kataloğuna](reconnaissance-and-threat-intelligence-apis.md) bakın.

Çok sayıda alt alan adı edinmenin en hızlı yolu, harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):


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

Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar bile, alt alan adlarını bulmak için yararlı olabilecek **başka ilginç araçlar/API'ler** de vardır:

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

- [**gau**](https://github.com/lc/gau)**:** Verilen herhangi bir alan adı için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): JS dosyalarını bulmak için web'i tarar ve bu dosyalardan subdomain'leri çıkarırlar.

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

- [**SecurityTrails**](https://securitytrails.com/) güncel DNS ve subdomain verileri için sınırlı ücretsiz API erişimi sunar; geçmiş DNS/IP verileri için ücretli plan gerekir.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz** sunar. Bu verilere [chaospy](https://github.com/Moaaz-0x/chaospy) kullanarak erişebilir veya bu projenin kullandığı scope'a şu adresten ulaşabilirsiniz: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP adreslerine de ihtiyacınız olacak. Güvenilir DNS resolver'larından oluşan bir liste oluşturmak için [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden resolver'ları indirip filtrelemek üzere [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şu listeyi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute-force işlemi gerçekleştiren ilk araç buydu. Çok hızlıdır ancak false positive üretmeye yatkındır.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bu araç sanırım yalnızca 1 resolver kullanıyor.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), Go ile yazılmış bir `massdns` wrapper'ıdır. Aktif brute force kullanarak geçerli alt alan adlarını enumerate etmenize, ayrıca wildcard handling ve kolay input-output desteğiyle alt alan adlarını çözümlemenize olanak tanır.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns` de kullanır.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını asenkron olarak brute force etmek için asyncio kullanır.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### İkinci DNS Brute-Force Turu

Açık kaynaklardan ve brute-force ile alt alan adlarını bulduktan sonra, daha fazlasını bulmayı denemek için bulunan alt alan adlarının varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'leri kullanarak permutations üretir.
  - goaltdns permutations **wordlist**'ini [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur. Bir permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permütasyonları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki yorumlarda belirtilen araçları kullanmak daha iyidir).
  - altdns permütasyonlarına ait **wordlist**’i [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Subdomain'lerde permütasyon, mutasyon ve değişiklik yapmak için kullanılan başka bir araç. Sonuçları brute force ile bulur (DNS wildcard desteklemez).
  - dmut permütasyon wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temel alarak, daha fazla alt alan adı keşfetmek için belirtilen pattern'lere göre **yeni olası alt alan adı isimleri üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen alt alan adlarından regex benzeri pattern'ler öğrenir ve çözümlenmek üzere aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili, DNS yanıtı güdümlü bir algoritmayla çalışan bir subdomain brute-force fuzzer'ıdır. Özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan girdi verilerini kullanarak, eşleşen başka domain adlarını doğru biçimde sentezler ve DNS taraması sırasında edinilen bilgilere dayanarak bunları döngüsel olarak daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Subdomain Keşif İş Akışı**

Trickest iş akışı örnekleri, tekrarlanabilir subdomain enumerasyonu için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain’lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, IP’deki domain’leri **OSINT kaynaklarında** arayarak veya o IP’deki VHost domain adlarına **brute force uygulayarak** **aynı IP’de web sitesi bulunan başka subdomain’ler** bulmayı deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API’leri kullanarak IP’lerdeki bazı VHost’ları** bulabilirsiniz.

**Brute Force**

Bir web sunucusunda bazı subdomain’lerin gizli olabileceğinden şüpheleniyorsanız, brute force uygulamayı deneyebilirsiniz:

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
> Bu teknikle dahili/gizli uç noktalara bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, _**Origin**_ başlığında geçerli bir alan adı/alt alan adı ayarlandığında yalnızca _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalarla karşılaşırsınız. Bu senaryolarda, bu davranışı kötüye kullanarak yeni **alt alan adlarını** **keşfedebilirsiniz**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Alt alan adlarını ararken herhangi bir **bucket**'a **yönlenip yönlenmediğine** dikkat edin; böyle bir durumda [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Ayrıca, bu aşamada kapsam içindeki tüm domain'leri bildiğiniz için olası bucket adlarına [**brute force uygulamayı ve izinleri kontrol etmeyi**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum) deneyin.

### **İzleme**

**Certificate Transparency** Logs'u izleyerek bir domain'in **yeni alt alan adları** oluşturup oluşturmadığını [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) gibi araçlarla **izleyebilirsiniz**.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Alt alan adı** bir **S3 bucket**'a yönleniyorsa [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Varlık keşfi sırasında bulduklarınızdan **farklı bir IP'ye sahip bir alt alan adı** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı püf noktaları** bulabilirsiniz.\
_Bazen alt alan adının, client tarafından kontrol edilmeyen ve bu nedenle kapsamda olmayan bir IP'de barındırıldığını unutmayın; dikkatli olun._

## IPs

İlk adımlarda bazı **IP aralıkları, domain'ler ve alt alan adları bulmuş** olabilirsiniz.\
Bu aralıklardaki ve **domain/alt alan adlarıyla ilişkili tüm IP'leri (DNS sorguları)** toplama zamanı.

Aşağıdaki gibi servisleri kullanarak **domain'ler ve alt alan adlarının daha önce kullandığı IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**SecurityTrails**](https://securitytrails.com/) (geçmiş DNS/IP verileri için ücretli plan gerekir)

Belirli bir IP adresine yönlenen domain'leri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla veya [**NetAPI**](https://netapi.com/lookup-ip/) gibi çevrimiçi bir reverse IP lookup hizmetiyle de kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'lerde port taraması yapın** (çünkü CDN'lerde ilginizi çekecek bir şey bulma olasılığınız düşüktür). Keşfedilen çalışan servislerde **zafiyetler bulabilirsiniz**.

Host'ların nasıl taranacağı hakkında bir [**kılavuz**](../pentesting-network/index.html) **bulun.**

## Web sunucusu arama

> Tüm şirketleri ve varlıklarını bulduk; kapsam içindeki IP aralıklarını, domain'leri ve alt alan adlarını biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen **IP'ler ve domain'ler üzerinde recon** yaptınız; bu nedenle **olası tüm web sunucularını** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, kapsam içindeki web sunucularını bulmak için bazı **hızlı yöntemlere** şimdi göz atacağız.

Bunun **web uygulamalarını keşfetmeye yönelik** olduğunu unutmayın; bu nedenle kapsam **izin veriyorsa** zafiyet ve port taramasını da **yapmalısınız**.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemini burada bulabilirsiniz**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını aramak için kullanışlı bir diğer araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araç 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portları denemesini de belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsamdaki **tüm web sunucularını** (şirketin **IP** adresleri ile tüm **domain** ve **subdomain** adresleri arasından) keşfettiğinize göre, muhtemelen **nereden başlayacağınızı bilmiyorsunuzdur**. Öyleyse işi basitleştirelim ve önce hepsinin ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya göz atarak**, **savunmasız olma ihtimali daha yüksek** olan **tuhaf** endpoint'ler bulabilirsiniz.

Bu öneriyi uygulamak için [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** kullanabilirsiniz.

Ayrıca, tüm **ekran görüntülerini** inceleyip **hangilerinin muhtemelen zafiyet içerdiğini** ve hangilerinin içermediğini belirlemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) aracını kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için, öncelikle **şirketi tanımlayan anahtar kelimelerden oluşan bir listeyle başlamalısınız**. Örneğin, bir kripto şirketi için `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gibi kelimeler kullanabilirsiniz.

Ayrıca **bucket'larda sık kullanılan kelimelerden** oluşan wordlist'lere de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** gibi araçları kullanabilirsiniz.

Cloud varlıklarını ararken **yalnızca AWS'deki bucket'lara bakmamanız** gerektiğini unutmayın.

### **Zafiyet arama**

**Açık bucket'lar veya dışarıya açık cloud function'lar** gibi şeyler bulursanız, bunlara **erişmeli**, neler sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı incelemelisiniz.

## E-postalar

Kapsam dahilindeki **domain** ve **subdomain** adresleriyle, **e-posta adreslerini aramaya başlamak için** gereken her şeye sahipsiniz. Bir şirketin e-posta adreslerini bulmak için en iyi sonuçları aldığım **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Zafiyet arama**

E-posta adresleri, daha sonra **web login'lerini ve auth servislerini** (SSH gibi) **brute-force etmek** için işinize yarayacak. Ayrıca **phishing** için de gerekliler. Üstelik bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** de sağlayarak phishing kampanyasına yardımcı olabilir.

## Credential Leak'leri

**Domain**, **subdomain** ve **e-posta adresleriyle**, geçmişte bu e-posta adreslerine ait olarak leak edilmiş credential'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet arama**

**Geçerli ve leak edilmiş** credential'lar bulursanız, bu kolayca elde edilmiş bir kazançtır.

## Secret Leak'leri

Credential leak'leri, **hassas bilgilerin leak edilip satıldığı** şirket hack'leriyle ilgilidir. Ancak şirketler, bilgileri bu veritabanlarında yer almayan **başka leak'lerden** de etkilenmiş olabilir:

### Github Leak'leri

Credential'lar ve API'ler, **şirketin** veya o şirket için çalışan **kullanıcıların** **public repository**'lerinde leak edilmiş olabilir.\
Bir **organizasyonun** ve geliştiricilerinin tüm **public repo**'larını **indirmek** ve bunların üzerinde [**gitleaks**](https://github.com/gitleaks/gitleaks) aracını otomatik olarak çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, kendisine verilen **URL'lerdeki** tüm **metinler** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfaları da secret'lar içerebilir**.

#### Github Dorks

Organizasyonda arama yapabileceğiniz olası **GitHub dorks** için [GitHub dorks ve leak'ler sayfasına](github-leaked-secrets.md) bakın.

### Pastes Leak'leri

Saldırganlar, hatta çalışanlar bazen **şirket içeriğini bir paste sitesinde yayınlayabilir**. Bu içerik **hassas bilgiler** içerebilir de içermeyebilir de; yine de aramak oldukça faydalıdır.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama değerli Google dorks, **orada olmaması gereken ve dışarıya açık bilgileri** bulmak için her zaman işe yarar. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde elle çalıştıramayacağınız binlerce olası sorgu bulunmasıdır. Bu nedenle, en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Düzenli Google tarayıcısını kullanarak tüm veritabanını çalıştırmayı bekleyen araçların işi asla bitmez; çünkü Google sizi çok kısa sürede engeller._

### **Zafiyet arama**

**Geçerli ve leak edilmiş** credential'lar veya API token'ları bulursanız, bu kolayca elde edilmiş bir kazançtır.

## Public Code Zafiyetleri

Şirketin **open-source kodu** olduğunu bulduysanız, kodu **analiz edip** içindeki **zafiyetleri** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır; [source-code review araçları](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca aşağıdakiler gibi, **public repository'leri taramanıza** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **zafiyetlerin çoğu** **web uygulamalarında** bulunur. Bu nedenle, bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum. [**Bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özellikle dikkat çekmek istiyorum. Bu araçların çok hassas zafiyetler bulmasını beklememelisiniz; ancak **başlangıç seviyesinde web bilgisi edinmek için iş akışlarında kullanışlıdırlar.**

## Özet

> Tebrikler! Bu noktada **tüm temel keşif işlemlerini** tamamlamış oldunuz. Evet, bunlar temel işlemler; çünkü çok daha fazla keşif yapılabilir (ileride daha fazla numara göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (kapsam dahilindeyse bazı zafiyet taramaları yaptınız)
3. Şirketlere ait tüm **domain** adreslerini buldunuz
4. Bu domain'lere ait tüm **subdomain** adreslerini buldunuz (subdomain takeover var mı?)
5. Kapsam dahilindeki tüm **IP** adreslerini buldunuz (**CDN'lerden gelen ve gelmeyen**).
6. Tüm **web sunucularını** bulup ekran görüntülerini aldınız (daha yakından incelenmeye değer tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. **Kolayca büyük kazanç sağlayabilecek** **e-posta adreslerini**, **credential leak'lerini** ve **secret leak'lerini** buldunuz.
9. Bulduğunuz tüm web sitelerinde **Pentesting** yaptınız

## **Tam Recon Otomasyon Araçları**

Verilen bir kapsama karşı önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor



## References

- [1] [Jason Haddix – Bug Hunter Metodolojisi v4.0: Recon Sürümü](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon'lar Hakkında: Tarayıcı Simgelerinden Attack Surface Intelligence'a](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty'ler, OSINT ve daha fazlası için favicon.ico'yu silahlandırmak](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerinde Zaman Korelasyonu Saldırısıyla Domain'leri Keşfetmek](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif Takeover: Maliyetli Bir Subdomain Takeover Kampanyasını Ortaya Çıkarmak (ve Taklit Etmek)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Özgün Bir Yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Tam Subdomain Keşif İş Akışı, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest İş Akışı ile Tam Subdomain Brute Force Keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
