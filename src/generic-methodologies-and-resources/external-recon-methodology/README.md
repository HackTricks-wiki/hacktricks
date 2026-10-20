# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

> Bir şirkete ait her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** bulmaktır. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın almalarını bulun; bu, kapsam dahilindeki şirketleri belirlemenizi sağlar.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını belirlemenizi sağlar.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, alan adları...) aramak için reverse whois sorguları kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanın (`ssl` hilesi yinelemeli olarak kullanılabilir).

### **Satın almalar**

Öncelikle, **ana şirketin sahibi olduğu diğer şirketleri** öğrenmemiz gerekiyor.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret edip **ana şirketi aramak** ve "**acquisitions**" öğesine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **satın almaları** aramaktır.\
Halka açık şirketler için **SEC/EDGAR başvurularını**, **yatırımcı ilişkileri** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve bağlı kuruluşlar için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam dahilindeki tüm şirketleri biliyor olmalısınız. Şimdi bunların varlıklarını nasıl bulacağımıza bakalım.

### **ASN'ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen, ancak birkaç operatörden oluşabilen **IP adresi bloklarından** oluşur.

Şirketin kendisine atanmış bir **ASN'si** olup olmadığını bulmak, **IP aralıklarını** belirlemek açısından önemlidir. **Kapsam** dahilindeki tüm **ana bilgisayarlara** karşı bir **güvenlik açığı testi** yapmak ve bu IP'lerdeki **alan adlarını aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) adreslerinde şirket **adına**, **IP'ye** ya da **alan adına** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için şu bağlantılar yararlı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her hâlükârda, muhtemelen tüm yararlı bilgiler **(IP aralıkları ve Whois)** ilk bağlantıda zaten bulunur.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration tarama sonunda ASN'leri otomatik olarak toplar ve özetler.

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

Bu noktada **kapsam içindeki tüm varlıkları biliyoruz**; dolayısıyla izin veriliyorsa tüm hostlarda bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapabilir **veya** Shodan, Censys ya da ZoomEye gibi servisleri **kullanarak** açık portları **bulabilirsiniz. Bulduklarınıza bağlı olarak, çalışan çeşitli servislerde nasıl pentest yapılacağını öğrenmek için** bu kitaba göz atmalısınız.\
**Ayrıca, bazı varsayılan kullanıcı adı ve** parola **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **ile servislerde bruteforce denemeye değer olabilir.**

## Domains

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz; şimdi kapsam içindeki domainleri bulma zamanı.

_Aşağıdaki önerilen tekniklerle subdomain'ler de bulabileceğinizi ve bu bilgilerin göz ardı edilmemesi gerektiğini unutmayın._

Öncelikle her şirketin **ana domain(ler)ini** bulmalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domainlerin tüm IP aralıklarını bulduğunuza göre, **kapsam içindeki daha fazla domaini bulmak için** bu **IP'lerde reverse DNS lookup** yapmayı deneyebilirsiniz. Kurbanın DNS sunucularından birini veya iyi bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

For this to work, yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için [SecurityTrails](https://securitytrails.com/) da kullanabilirsiniz; ancak geçmiş DNS verileri ücretli plan gerektirir.\
Geniş aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar, ters aramaları ve zenginleştirmeyi otomatikleştirmede kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olanı, bu alanlardan herhangi birini kullanarak **reverse whois aramaları yaptığınızda şirketle ilişkili başka varlıklar** bulabilmenizdir (örneğin, aynı e-postanın geçtiği diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web arayüzü; API ücretlidir.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Güncel DNS/alt alan adları için sınırlı ücretsiz API erişimi sunar; geçmiş veriler ve ters aramalar ücretli plan gerektirir.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kayıt sırasında 500 ücretsiz API kredisi; sonrasında ücretlidir.

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) ile otomatikleştirebilirsiniz (whoxy API anahtarı gerektirir).\
[amass](https://github.com/owasp-amass/amass) ile bazı reverse whois keşiflerini otomatik olarak da gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir alan adı bulduğunuz her seferinde daha fazla alan adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **İzleyiciler**

İki farklı sayfada **aynı izleyicinin aynı kimliğini** bulursanız, **iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID**'yi görürseniz.

Bu izleyicileri ve daha fazlasını aramanıza olanak tanıyan bazı sayfalar ve araçlar:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Ücretli** web ve API hizmeti ([fiyatlandırma](https://www.stackscan.com/pricing)); şu anda ücretsiz bir plan sunulduğu belirtilmiyor. Yalnızca izleyici ID'leriyle değil, sunulan herhangi bir varlık üzerinden de arama yapın: bir script yolu, kendi barındırdıkları bir bundle adı veya varlığın yüklendiği host üzerinden arama yaparak, bu öğeyi kullanan tüm siteleri bulun.

API, tek bir domain'in stack'ini döndürür; bu da olası bir varlığın aynı altyapıya ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Algılanan her teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, alan adı başına aramayı kapsar.

### **Favicon**

Aynı favicon simge hash'ini arayarak hedefimizle ilişkili alan adlarını ve alt alan adlarını bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) aracı tam olarak bunu yapar. Nasıl kullanacağınız aşağıda açıklanmıştır:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash değerini paylaşan domain'leri keşfetmek için kullanıldı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon hash değerine sahip domain'leri keşfetmemizi sağlar.

![Aynı favicon hash değerine sahip domain'leri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA'da pivot olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini** şu şekilde **hesaplayabilirsiniz** (**base64 ile kodlanmış** favicon baytları üzerinde MMH3):

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

Ölçekli favicon hash'leri [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile de alabilir, ardından Shodan/Censys'te pivot yapabilirsiniz.

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, gösterge olarak değerlendirin**: MMH3 kompakt bir formattadır; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı yanıltma mümkündür.
- **Yalnızca** `/favicon.ico` **üzerinde inceleme yapmayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik asset'lere WAF/SSO/IdP kontrollerinin arkasından erişilebilir durumda kalabilir**: ikonu doğrudan isteyin ve `ETag`, `Last-Modified`, yönlendirmeler ile cache başlıklarını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: başlığı, HTML/body hash'ini, başlıkları, TLS sertifikası subject/SAN'larını, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümelendirin**: tutarlı bir şablon fingerprint'i güçlendirir; farklı şablonlar genel veya paylaşılan bir ikona işaret eder.
- **İlgisiz imzalar, portlar ve ürünlerde görünen bir hash'i olası bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı bulunmayan bir yolla** (örneğin `/_favicon_probe_<8-hex>`) **karşılaştırın**; eşleşen hosting veya park sayfası yanıtları, paylaşılan ikonu açıklayabilir.
- **Favicon hash'lerini ürünlere ve CPE'lere eşleyen Nuclei tespit kuralları veya herkese açık veri kümeleriyle ilk incelemeyi başlatın.**
- **IP merkezli kapsam boşluğunu unutmayın**: CDN arkasındaki, SNI yönlendirmeli, anycast ve yalnızca domain üzerinden erişilen yüzeyler Shodan benzeri veri kümelerinde eksik olabilir.

### **Telif Hakkı / Benzersiz string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde paylaşılabilecek string'leri** arayın. **Telif hakkı string'i** buna iyi bir örnek olabilir. Ardından bu string'i **google**'da, diğer **tarayıcılarda** ve hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron job kullanılması yaygındır:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency loglarındaki konumları ilişkilendirmek, bağlantılı domainleri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı DMARC bilgilerini paylaşan domainleri ve subdomainleri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Bir diğer kullanışlı servis de [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı IP adresini yeniden atadığında erişilebilir hâle gelebilir. Referans verilen araştırma, bir instance oluşturup adresini pasif DNS verileriyle ilişkilendiren fırsatçı bir iş akışı gösteriyor; takeover senaryolarını yalnızca yetkilendirilmiş kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir domain bulduğunuzda geçerli keşif yöntemlerini tekrarlayın: her sonuç, başlangıçta kullanılan seed'den görünmeyen ek sertifika adlarını, pasif DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulduğunuz hostlarda, TLS sertifikasında yer alan yeni ve beklenmedik domainleri kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişerek **Organisation name** değerini alabilir, ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikalarında** şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), bir ana domainle **ilişkili domainleri** ve bunların **subdomainlerini** arayan bir araçtır; oldukça etkileyicidir.

**Passive DNS / Geçmiş DNS**

Pasif DNS verileri, hâlâ çözümlenen veya takeover yapılabilen **eski ve unutulmuş kayıtları** bulmak için çok kullanışlıdır. Şuralara bakın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Güvenlik açıklarını arama**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) olup olmadığını kontrol edin. Bir şirket **bir domain kullanıyor** ancak **sahipliğini kaybetmiş** olabilir. (Yeterince ucuzsa) domaini kaydedin ve şirkete haber verin.

Varlık keşfinde bulduklarınızdan **farklı bir IP adresine sahip bir domain** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen domain, istemci tarafından kontrol edilmeyen bir IP üzerinde barındırılır ve bu nedenle kapsam dışındadır; dikkatli olun._

## Subdomainler

> Kapsam dâhilindeki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm domainleri biliyoruz.

Bulduğumuz her domainin olası tüm subdomainlerini bulma zamanı.

> [!TIP]
> Domain bulmaya yönelik bazı araç ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **subdomainler** bulmaya çalışalım. **Zone Transfer** için de denemeliyiz (Güvenlik açığı varsa rapor etmelisiniz).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Altyapı, itibar, breach kayıtları ve subdomain keşfinin ötesinde zenginleştirme sağlayan API ve platformlar için [Reconnaissance ve Threat-Intelligence API kataloğuna](reconnaissance-and-threat-intelligence-apis.md) bakın.

Çok sayıda subdomain elde etmenin en hızlı yolu, harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API key’lerini yapılandırın):


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

Alt alan adlarını bulma konusunda doğrudan uzmanlaşmış olmasalar da alt alan adlarını bulmak için yararlı olabilecek **başka ilginç araçlar/API'ler** de vardır:

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

- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayarak JS dosyalarını bulur ve bunlardan alt alan adlarını çıkarırlar.

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

- [**SecurityTrails**](https://securitytrails.com/) güncel DNS ve subdomain verileri için sınırlı ücretsiz API erişimi sunar; geçmiş DNS/IP verileri ücretli plan gerektirir.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Bu proje, **bug-bounty programlarıyla ilgili tüm subdomain'leri ücretsiz** sunar. Bu verilere [chaospy](https://github.com/Moaaz-0x/chaospy) kullanarak da erişebilir veya bu projenin kullandığı kapsamı [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) adresinden edinebilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP adreslerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının listesini oluşturmak için [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden resolver'ları indirip filtrelemek üzere [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute-force gerçekleştiren ilk araç buydu. Çok hızlıdır ancak false positive sonuçlar verme eğilimindedir.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), Go ile yazılmış bir `massdns` sarmalayıcısıdır. Aktif bruteforce kullanarak geçerli alt alan adlarını listelemenizi ve wildcard yönetimi ile kolay girdi-çıktı desteği sunarak alt alan adlarını çözümlemenizi sağlar.

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

Açık kaynakları kullanıp brute-force yaparak subdomain'leri bulduktan sonra, daha fazlasını bulmaya çalışmak için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'ler için permütasyonlar oluşturur.
  - goaltdns permütasyon **wordlist**'ini [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur. Bir permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permütasyonları üretmenin yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki araçları kullanmak daha iyidir).
  - altdns permütasyon **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarında permütasyonlar, mutasyonlar ve değişiklikler yapmak için kullanılan başka bir araç. Sonuçları brute force ile bulur (DNS wildcard desteği yoktur).
  - dmut permütasyon wordlist'ini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) edinebilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain'i temel alarak, daha fazla subdomain keşfetmek için belirtilen pattern'lere göre yeni potansiyel subdomain adları üretir.

#### Akıllı permutation üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'ler öğrenir ve çözümlenmesi için aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili, DNS yanıtlarını temel alan bir algoritmayla çalışan bir subdomain brute-force fuzzer'dır. Özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir girdi kümesini kullanarak eşleşen başka alan adlarını hassas biçimde sentezler ve DNS taraması sırasında elde edilen bilgilere göre bunları bir döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Alt Alan Adı Keşif İş Akışı**

Trickest iş akışı örnekleri, tekrarlanabilir alt alan adı enumerasyonu için OSINT, DNS brute force ve permütasyon aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Alt alan adlarına ait **bir veya birkaç web sayfası** barındıran bir IP adresi bulduysanız, **OSINT kaynaklarında** bir IP'deki alan adlarını arayarak veya o IP'deki **VHost alan adlarına brute force uygulayarak** aynı IP'deki başka alt alan adlarını **bulmaya** çalışabilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya başka API'ler kullanarak IP'lerdeki bazı VHosts'ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı alt alan adlarının gizli olabileceğinden şüpheleniyorsanız brute force uygulamayı deneyebilirsiniz:

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
> Bu teknikle internal/hidden endpoint’lere bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, _**Origin**_ header’ında geçerli bir domain/subdomain ayarlandığında yalnızca _**Access-Control-Allow-Origin**_ header’ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**’leri **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**Subdomain** ararken herhangi bir **bucket**'a **yönlenip yönlenmediğini** kontrol edin ve böyle bir durum varsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada scope içindeki tüm domainleri biliyor olacağınız için olası bucket adlarını [**brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)aracının yaptığı gibi **Certificate Transparency** Log'larını izleyerek bir domainin **yeni alt alan adlarının** oluşturulup oluşturulmadığını **takip** edebilirsiniz.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Alt alan adı** bir **S3 bucket**'a yönleniyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset keşfi sırasında bulduklarınızdan **farklı bir IP'ye sahip bir alt alan adı** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı püf noktaları** bulabilirsiniz.\
_Alt alan adının bazen müşteri tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle scope dışında olabileceğini unutmayın; dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP aralıkları, domainler ve alt alan adları** bulmuş olabilirsiniz.\
Şimdi bu aralıklardaki **tüm IP'leri** ve **domainler/alt alan adları (DNS sorguları) için olan IP'leri** bir araya getirme zamanı.

Aşağıdakiler gibi servisleri kullanarak **domainler ve alt alan adları tarafından daha önce kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ müşteriye ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**SecurityTrails**](https://securitytrails.com/) (geçmiş DNS/IP verileri için ücretli plan gerekir)

Belirli bir IP adresine yönlenen domainleri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'lerde port taraması yapın** (çünkü bu IP'lerde muhtemelen ilginç bir şey bulamazsınız). Keşfedilen çalışan servislerde **zafiyetler bulabilirsiniz**.

Host'ların nasıl taranacağı hakkında bir [**kılavuza**](../pentesting-network/index.html) **göz atın.**

## Web sunucularını arama

> Tüm şirketleri ve varlıklarını bulduk; scope içindeki IP aralıklarını, domainleri ve alt alan adlarını biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen **IP'ler ve domainler üzerinde recon** gerçekleştirdiniz; dolayısıyla olası **tüm web sunucularını** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi scope içindeki web sunucularını bulmak için bazı **hızlı yöntemlere** göz atacağız.

Bunun **web uygulamalarını keşfetmeye yönelik** olduğunu unutmayın; bu nedenle scope tarafından **izin veriliyorsa** ayrıca **zafiyet taraması** ve **port taraması** da gerçekleştirmelisiniz.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemi burada bulunabilir**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını bulmak için kullanışlı diğer araçlar [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx). Yalnızca bir domain listesi verirsiniz; araçlar 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca başka portları da denemelerini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsamda bulunan **tüm web sunucularını** (şirketin **IP**'leri ile tüm **domain** ve **subdomain**'ler arasında) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde işi kolaylaştıralım ve hepsinin ekran görüntülerini almaya başlayalım. **Ana sayfaya** yalnızca **göz atarak** **savunmasız** olma **olasılığı daha yüksek** olan **tuhaf** endpoint'ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, tüm **ekran görüntülerini** inceleyip **hangilerinin muhtemelen güvenlik açığı içerdiğini** ve hangilerinin içermediğini söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için öncelikle **şirketi tanımlayan anahtar kelimelerden oluşan bir liste** hazırlamalısınız. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca bucket'larda **yaygın olarak kullanılan kelimelerin** wordlist'lerine ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından, bu kelimelerle **permutation**'lar oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **AWS'deki bucket'lardan fazlasına bakmanız** gerektiğini unutmayın.

### **Güvenlik açıklarını arama**

**Açık bucket'lar veya açığa çıkmış cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, neler sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## E-postalar

Kapsamdaki **domain** ve **subdomain**'lerle, e-posta aramaya başlamak için gereken her şeye sahipsiniz. Bir şirketin e-posta adreslerini bulmak için en iyi sonuç veren **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Güvenlik açıklarını arama**

E-postalar, daha sonra web login'lerini ve auth servislerini (SSH gibi) **brute-force** etmek için işinize yarayacak. Ayrıca **phishing** için de gereklidir. Üstelik bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** sağlayarak phishing kampanyasına yardımcı olur.

## Credential Leak'leri

**Domain**'ler, **subdomain**'ler ve **e-posta adresleriyle**, geçmişte leak edilmiş ve bu e-posta adreslerine ait credential'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Güvenlik açıklarını arama**

**Geçerli, leak edilmiş** credential'lar bulursanız bu, kolay bir kazançtır.

## Secret Leak'leri

Credential leak'leri, **hassas bilgilerin leak edilip satıldığı** şirket saldırılarıyla ilgilidir. Ancak şirketler, bilgileri bu veritabanlarında bulunmayan **başka leak'lerden** de etkilenmiş olabilir:

### Github Leak'leri

Credential'lar ve API'ler, şirketin **public repository**'lerinde veya o şirkette çalışan **kullanıcıların** repository'lerinde leak edilmiş olabilir.\
Bir **organization**'ın ve geliştiricilerinin tüm **public repo**'larını **indirmek** ve üzerlerinde [**gitleaks**](https://github.com/gitleaks/gitleaks) aracını otomatik olarak çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, **metin** içeren ve kendisine verilen **URL'ler** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü web sayfalarında da bazen secret'lar bulunur.

#### Github Dorks

Organization'da arama yapmak için olası **GitHub dork**'larını [GitHub dorks ve leak'ler sayfasında](github-leaked-secrets.md) bulabilirsiniz.

### Paste Leak'leri

Bazen saldırganlar veya çalışanlar şirket içeriklerini bir paste sitesinde **yayımlar**. Bu içerikler **hassas bilgiler** içerebilir de içermeyebilir de; ancak aramaya değer.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki Google dork'ları, **orada olmaması gereken açığa çıkmış bilgileri** bulmak için her zaman işe yarar. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde manuel olarak çalıştıramayacağınız **binlerce** olası sorgunun bulunmasıdır. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Standart Google tarayıcısını kullanarak veritabanının tamamını çalıştırmayı bekleyen araçların hiçbir zaman bitmeyeceğini unutmayın; Google sizi çok kısa sürede engeller._

### **Güvenlik açıklarını arama**

**Geçerli, leak edilmiş** credential'lar veya API token'ları bulursanız bu, kolay bir kazançtır.

## Public Code Güvenlik Açıkları

Şirketin **open-source kodu** olduğunu bulduysanız, bu kodu **analiz edebilir** ve **güvenlik açıkları** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır; [source-code review araçları](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca, aşağıdakiler gibi **public repository'leri taramanıza** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **güvenlik açıklarının çoğu** **web uygulamalarında** bulunur. Bu nedenle bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum. [**Bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Otomatik Tarayıcılar açık kaynak araçları**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünü özellikle belirtmek istiyorum. Çok hassas güvenlik açıkları bulmalarını beklememek gerekse de, başlangıç seviyesinde web bilgisi edinmek için bunları **workflow'lara eklemek** işe yarar.

## Özet

> Tebrikler! Bu noktada **tüm temel keşif işlemlerini** tamamladınız. Evet, bu temel düzeyde; çünkü çok daha fazla keşif yapılabilir (ileride daha fazla numara göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (ve kapsamdaysa bazı vuln scan'ler gerçekleştirdiniz)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lerin tüm **subdomain**'lerini buldunuz (subdomain takeover var mı?)
5. Kapsamdaki tüm **IP**'leri buldunuz (**CDN'lerden gelen ve gelmeyen**).
6. Tüm **web sunucularını** buldunuz ve ekran görüntülerini aldınız (daha yakından bakmaya değer tuhaf bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Size **kolayca büyük bir kazanç sağlayabilecek** **e-posta adresleri**, **credential leak**'leri ve **secret leak**'ler.
9. Bulduğunuz tüm web'lerde **pentesting**

## **Tam Recon Otomasyon Araçları**

Belirli bir kapsama karşı önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncel değil

## References

- [1] [Jason Haddix – Hata Avcısının Metodolojisi v4.0: Recon Sürümü](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon'lar Üzerine: Tarayıcı Simgelerinden Saldırı Yüzeyi İstihbaratına](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug Bounty'ler, OSINT ve Daha Fazlası için favicon.ico'yu Silahlandırmak](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerinde Zaman Korelasyonu Saldırısıyla Domain'leri Keşfetmek](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif Takeover: Pahalı Bir Subdomain Takeover Kampanyasını Ortaya Çıkarmak (ve Taklit Etmek)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Benzersiz Bir Yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Tam Subdomain Keşif Workflow'u, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest Workflow'u Kullanarak Tam Subdomain Brute Force Keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
