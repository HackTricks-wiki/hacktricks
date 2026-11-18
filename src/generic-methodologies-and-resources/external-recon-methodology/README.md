# Harici Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

Ek OSINT ve web keşif projelerinin kategorilere ayrılmış bir listesi için [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint) sayfasına bakın.

> Size bir şirkete ait her şeyin kapsamda olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu belirlemek istiyorsunuz.

Bu aşamanın amacı, önce **ana şirkete ait tüm şirketleri**, ardından bu şirketlerin tüm **varlıklarını** belirlemektir. Bunun için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın aldığı şirketleri bulun; bunlar kapsam içindeki şirketleri belirler.
2. Her şirketin varsa ASN'sini bulun; bu, her şirketin sahip olduğu IP aralıklarını belirler.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois sorgularını kullanın (bu işlem yinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan'ın `org`ve `ssl`filtreleri gibi başka teknikleri kullanın (`ssl` yöntemi yinelemeli olarak uygulanabilir).

Çözümlenmiş subdomain'lerden HTTP taramasına ve port keşfine aşamalı geçiş için [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline) sayfasına bakın.

### **Satın Almalar**

Öncelikle, ana şirkete ait **diğer şirketleri** belirlememiz gerekiyor.\
Bunun bir yolu [https://www.crunchbase.com/](https://www.crunchbase.com) adresine gidip **ana şirketi aramak** ve "**acquisitions**" öğesine **tıklamaktır**. Burada ana şirketin satın aldığı diğer şirketleri görebilirsiniz.\
Diğer bir yol da ana şirketin **Wikipedia** sayfasına gidip **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket ağaçları ve bağlı ortaklıklar için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri biliyor olmanız gerekir. Şimdi bunların varlıklarını nasıl bulacağımıza bakalım.

### **ASN'ler**

Otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip ve tek bir kuruluş tarafından yönetilen **IP adresi bloklarından** oluşur; ancak birden çok operatörden oluşabilir.

Şirketin herhangi bir **ASN'si olup olmadığını** öğrenmek, **IP aralıklarını** bulmak açısından önemlidir. **Kapsam** içindeki tüm **host'lara** karşı bir **güvenlik açığı testi** yapmak ve bu IP'lerdeki **domain'leri aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adına**, **IP'ye** veya **domain'e** göre **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için şu bağlantılar yararlı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa). Her durumda, muhtemelen tüm** yararlı bilgiler **(IP aralıkları ve Whois)** ilk bağlantıda zaten bulunur.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.

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

### **Zafiyetleri arama**

Bu noktada **kapsam içindeki tüm varlıkları biliyoruz**, bu nedenle izin veriliyorsa tüm ana bilgisayarlarda bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapabilir **veya Shodan, Censys ya da ZoomEye gibi servisleri kullanarak** açık portları **bulabilirsiniz. Bulduklarınıza bağlı olarak, çalışan çeşitli olası servislerin pentestini nasıl yapacağınızı öğrenmek için bu kitaba göz atmalısınız.**\
**Ayrıca, bazı varsayılan kullanıcı adı ve** parola **listeleri hazırlayıp** servislerde [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **ile kaba kuvvet denemeleri yapmanın da faydalı olabileceğini belirtmekte yarar var.**

## Alan adları

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz; artık kapsam içindeki alan adlarını bulma zamanı.

_Aşağıdaki önerilen tekniklerle alt alan adlarını da bulabileceğinizi ve bu bilgiyi hafife almamanız gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana alan adını** veya **ana alan adlarını** bulmalısınız. Örneğin, _Tesla Inc._ için bu alan adı _tesla.com_ olacaktır.

### **Reverse DNS**

Alan adlarının tüm IP aralıklarını bulduğunuza göre, **kapsam içindeki daha fazla alan adını bulmak için bu IP'lerde ters DNS sorguları** yapmayı deneyebilirsiniz. Kurbanın DNS sunucularından birini veya iyi bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için [SecurityTrails](https://securitytrails.com/) da kullanabilirsiniz; ancak geçmiş DNS verileri ücretli plan gerektirir.\
Geniş aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar ters sorgulamaları ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kurum adı**, **adres**, **e-postalar**, telefon numaraları gibi pek çok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olanı, bu alanlardan herhangi biriyle **reverse whois sorguları** yaparak **şirketle ilgili daha fazla varlık** bulabilmenizdir (örneğin, aynı e-postanın geçtiği diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Ücretsiz** web arayüzü; ücretli API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Güncel DNS/alt alan adları için sınırlı ücretsiz API erişimi; geçmiş veriler ve ters sorgulamalar ücretli plan gerektirir.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Kaydolduğunuzda 500 ücretsiz API kredisi; sonrasında ücretli.

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (whoxy API anahtarı gerekir).\
[amass](https://github.com/owasp-amass/amass) ile de otomatik reverse whois keşfi yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada **aynı tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birden fazla sayfada aynı **Google Analytics ID'sini** veya aynı **Adsense ID'sini** görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Ücretli** web ve API hizmeti ([fiyatlandırma](https://www.stackscan.com/pricing)); şu anda ücretsiz plan sunulduğu belirtilmiyor. Yalnızca tracker ID'lerine değil, sunulan herhangi bir varlığa göre arama yapın: bir script yolu, self-hosted bundle adı veya bir varlığın yüklendiği host; sonuç olarak bu öğeyi barındıran tüm siteleri listeler.

API, tek bir domain için stack'i döndürür; bu da aday bir varlığın aynı ortama ait olduğunu doğrulamak için kullanışlıdır:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Algılanan her teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web için kullanılabilir; API, alan adı başına sorgulamayı destekler.

### **Favicon**

Aynı favicon simge hash’ini arayarak hedefimizle ilişkili alan adlarını ve alt alan adlarını bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte nasıl kullanacağınız:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash sonuçları, aynı favicon hash değerini paylaşan domain'leri keşfetmek için kullanılır](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon hash değerine sahip domain'leri keşfetmemizi sağlar.

![favihash çıktısı, aynı favicon hash değerine sahip domain'leri keşfetmek için kullanılır](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı teknolojinin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA'da pivot olarak kullanın.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Bir web sitesinin **favicon hash'ini hesaplamak** için (favicon baytlarının **base64-encoded** hali üzerinde MMH3):

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

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevresindeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt değil, gösterge olarak değerlendirin**: MMH3 kompakt bir yapıya sahiptir; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı sahtecilik mümkündür.
- **Yalnızca** `/favicon.ico` **üzerinde inceleme yapmayın**: framework/build yollarını, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, satır içi data URL'lerini ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Statik asset'lere WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: İkona doğrudan istek gönderin ve `ETag`, `Last-Modified`, yönlendirmeleri ve cache header'larını inceleyin.
- **Eşleşmeleri çevresindeki sinyallerle doğrulayın**: title'ı, HTML/body hash'ini, header'ları, TLS sertifikası subject/SAN değerlerini, ürün bileşenlerini ve açık portları karşılaştırın.
- **HTML/body hash'ine göre kümeleme yapın**: Tutarlı bir template fingerprint'i güçlendirir; farklı template'ler genel veya paylaşılan bir ikona işaret eder.
- **İlgisiz signature'larda, portlarda ve ürünlerde görünen bir hash'i olası bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz hedeflerde gerçek bir sayfayı var olmayan bir path ile karşılaştırın**; örneğin `/_favicon_probe_<8-hex>`. Aynı hosting veya park edilmiş domain yanıtları, paylaşılan ikonu açıklayabilir.
- **Ürünleri ve CPE'leri favicon hash'leriyle eşleştiren Nuclei detection kuralları veya herkese açık dataset'lerle ilk triyajı başlatın.**
- **IP merkezli kapsam boşluğunu unutmayın**: CDN arkasındaki, SNI ile yönlendirilen, anycast kullanan ve yalnızca domain üzerinden erişilen yüzeyler Shodan benzeri dataset'lerde bulunmayabilir.

### **Telif Hakkı / Benzersiz string**

Web sayfalarında **aynı kuruluştaki farklı web sitelerinde paylaşılabilecek string'leri** arayın. **Telif hakkı string'i** buna iyi bir örnek olabilir. Ardından bu string'i **Google'da**, diğer **tarayıcılarda** veya hatta **Shodan'da** arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Şöyle bir cron görevi olması yaygındır:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency loglarındaki konumları ilişkilendirmek, bağlantılı alan adlarını ortaya çıkarabilir.<sup>[[6]](#references)</sup>

**certificate transparency** loglarını doğrudan da kullanabilirsiniz:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı DMARC bilgilerini paylaşan alan adlarını ve subdomain'leri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Bir diğer kullanışlı hizmet de [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturup adresini passive DNS verileriyle ilişkilendiren fırsatçı bir iş akışını gösteriyor; takeover senaryolarını yalnızca yetkilendirilmiş kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir alan adı bulduğunuzda geçerli keşif adımlarını tekrarlayın: her sonuç, başlangıçta görünmeyen ek sertifika adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten biliyorsunuz. Shodan'da bu veriyi kullanarak şu şekilde arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan host'ları inceleyerek TLS sertifikasında yeni ve beklenmedik alan adları arayın.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name** bilgisini alabilir, ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikalarında** şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` ya da [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana bir alan adıyla **ilişkili alan adlarını** ve bunların **subdomain'lerini** arayan bir araçtır; gerçekten etkileyici.

**Passive DNS / Historical DNS**

Passive DNS verileri, hâlâ çözümlenen veya takeover yapılabilecek **eski ve unutulmuş kayıtları** bulmak için çok kullanışlıdır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Zafiyet arama**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir alan adını kullanıyordur**, ancak **sahipliğini kaybetmiştir**. Yeterince ucuzsa alan adını kaydedin ve şirkete haber verin.

Varlık keşfinde bulduklarınızdan **farklı bir IP'ye sahip bir alan adı** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmaya" yönelik bazı yöntemler** bulabilirsiniz.\
_Bazen alan adının, istemci tarafından kontrol edilmeyen ve dolayısıyla kapsam dışında olan bir IP üzerinde barındırıldığını unutmayın; dikkatli olun._

## Subdomains

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm alan adlarını biliyoruz.

Bulduğumuz her alan adının olası tüm subdomain'lerini bulma zamanı.

> [!TIP]
> Alan adlarını bulmaya yönelik bazı araç ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın.

### **DNS**

**DNS** kayıtlarından **subdomain** bulmaya çalışalım. **Zone Transfer** denemesi de yapmalıyız (Güvenlik açığı varsa rapor edin).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Altyapı, itibar, breach kayıtları ve alt alan adı keşfinin ötesinde zenginleştirme hizmetleri sunan API'ler ve platformlar için [Reconnaissance and Threat-Intelligence APIs kataloğuna](reconnaissance-and-threat-intelligence-apis.md) bakın.

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

**Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar bile alt alan adlarını bulmak için kullanılabilecek başka ilginç araçlar/API'ler** de vardır. Örneğin:

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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): JS dosyalarını bulmak için web'i tarar ve bu dosyalardan alt alan adlarını çıkarırlar.

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

- [**Censys subdomain bulucusu**](https://github.com/christophetd/censys-subdomain-finder)

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

Bu proje, bug bounty programlarıyla ilgili tüm subdomain'leri **ücretsiz** sunar. Bu verilere [chaospy](https://github.com/Moaaz-0x/chaospy) ile de erişebilir, hatta bu projenin kullandığı scope'a [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) üzerinden ulaşabilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için aşağıdaki gibi bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca güvenilir DNS resolver'ların IP adreslerine de ihtiyacınız olacak. Güvenilir DNS resolver'ların listesini oluşturmak için [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden resolver'ları indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şu listeyi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute force yapan ilk araçtı. Çok hızlıdır ancak yanlış pozitiflere yatkındır.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Bu aracın yalnızca 1 resolver kullandığını düşünüyorum.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış bir `massdns` wrapper'ıdır. Aktif brute force kullanarak geçerli subdomain'leri enumerate etmenizi ve wildcard handling ile subdomain'leri resolve etmenizi sağlar; ayrıca kolay input-output desteği sunar.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): O da `massdns` kullanır.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını asenkron olarak brute force etmek için asyncio kullanır.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### İkinci DNS Brute-Force Turu

Açık kaynaklar ve brute-force kullanarak subdomain'leri bulduktan sonra, daha fazlasını bulmaya çalışmak için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Alan adları ve subdomain'ler verildiğinde permütasyonlar oluşturur.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.
  - goaltdns permütasyon **wordlist**'ini [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) edinebilirsiniz.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen alan adları ve alt alan adlarından permütasyonlar oluşturur. Bir permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutation'ları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki yorumlarda belirtilen araçları kullanmak daha iyidir).
  - altdns permutation **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Subdomain permutations, mutations ve değişiklikleri gerçekleştirmek için başka bir araç. Sonuçları brute force ile bulur (DNS wildcard desteği yoktur).
  - dmut permutations wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domaini temel alarak, daha fazla subdomain keşfetmek için belirtilen pattern'lere göre **yeni olası subdomain adları üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'ler öğrenir ve çözümlenmek üzere aday adlar üretir.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili bir DNS yanıtı yönlendirmeli algoritmayla çalışan bir subdomain brute-force fuzzer'dır. Özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan girdi verilerini kullanarak bunlarla eşleşen daha fazla domain adını doğru biçimde sentezler ve DNS taraması sırasında toplanan bilgilere göre bunları bir döngü içinde daha da genişletir.

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** barındıran bir IP adresi bulduysanız, IP'deki domain'leri bulmak için **OSINT kaynaklarını** kullanarak veya o IP'deki VHost domain adlarına **brute force uygulayarak** aynı IP'de web sitesi barındıran başka subdomain'ler bulmayı deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerdeki bazı VHosts'ları bulabilirsiniz.**

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
> Bu teknikle dahili/gizli endpoint'lere bile erişebilirsiniz.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain'leri** **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**Subdomain** ararken herhangi bir **bucket**'a **yönlenip yönlenmediğine** dikkat edin. Böyle bir durumda [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Ayrıca, bu aşamada scope içindeki tüm domainleri bildiğinizden, olası bucket adlarını [**Brute Force ile deneyin ve izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **İzleme**

**Certificate Transparency** Logs'u izleyerek bir domainin **yeni subdomain'lerinin** oluşturulup oluşturulmadığını takip edebilirsiniz; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)bunu yapar.

### **Güvenlik açıklarını arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**Subdomain** bir **S3 bucket**'a yönleniyorsa [**izinleri kontrol edin**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Varlık keşfinde bulduğunuz IP'lerden **farklı bir IP'ye sahip bir subdomain** bulursanız, **temel bir güvenlik açığı taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile [**port taraması**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta onlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Not: Bazen subdomain, istemci tarafından kontrol edilmeyen ve dolayısıyla scope dışında olan bir IP üzerinde barındırılır; dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP aralıkları, domainler ve subdomain'ler** bulmuş olabilirsiniz.\
Bu aralıklardaki tüm IP'leri ve **domain/subdomain'lere ait IP'leri (DNS sorguları aracılığıyla)** derleme zamanı.

Aşağıdaki gibi servisleri kullanarak **domain ve subdomain'lerin daha önce kullandığı IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ istemciye ait olabilir (ve [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**SecurityTrails**](https://securitytrails.com/) (geçmiş DNS/IP verileri ücretli plan gerektirir)

Belirli bir IP adresine yönlenen domain'leri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Güvenlik açıklarını arama**

**CDN'lere ait olmayan tüm IP'leri port taramasından geçirin** (çünkü orada muhtemelen ilginç bir şey bulamazsınız). Keşfedilen çalışan servislerde **güvenlik açıkları** bulabilirsiniz.

Host'ların nasıl taranacağı hakkında bir [**kılavuz**](../pentesting-network/index.html) **bulun**.

## Web sunucularını arama

> Tüm şirketleri ve varlıklarını bulduk; scope içindeki IP aralıklarını, domainleri ve subdomain'leri biliyoruz. Şimdi web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP ve domain'ler üzerinde **recon** yaptınız, bu nedenle **olası tüm web sunucularını** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi scope içindeki web sunucularını aramak için bazı **hızlı yöntemlere** bakacağız.

Bunun **web app keşfine yönelik** olduğunu unutmayın; bu nedenle scope tarafından **izin veriliyorsa** **güvenlik açığı taraması** ve **port taraması** da yapmalısınız.

[**masscan** kullanarak web sunucularıyla ilişkili açık portları keşfetmenin **hızlı bir yöntemi burada bulunabilir**](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını aramak için kullanışlı diğer araçlar [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araçlar 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca başka portları da denemelerini belirtebilirsiniz:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ekran Görüntüleri**

Kapsam dahilindeki **tüm web sunucularını** (şirketin **IP**’leri ile tüm **domain** ve **subdomain**’leri arasında) keşfettiğinize göre, muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde işi basitleştirip hepsinin ekran görüntülerini alarak başlayalım. Sadece **ana sayfaya** **bakmak**, **zafiyet barındırma olasılığı daha yüksek** olan **tuhaf** endpoint’leri bulmanızı sağlayabilir.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, tüm **ekran görüntülerini** tarayıp **hangilerinin muhtemelen zafiyet içerdiğini**, hangilerinin içermediğini söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz.

## Public Cloud Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için **öncelikle şirketi tanımlayan anahtar kelimelerden oluşan bir liste hazırlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca **bucket’larda kullanılan yaygın kelimelerin** wordlist’lerine de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından, bu kelimelerle **permütasyonlar** oluşturmalısınız (daha fazla bilgi için [**İkinci Tur DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist’lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud varlıklarını ararken **AWS’deki bucket’lardan fazlasını aramanız** gerektiğini unutmayın.

### **Zafiyet arama**

**Açık bucket’lar veya dışarıya açık cloud function’lar** gibi şeyler bulursanız, **bunlara erişmeli** ve size neler sunduklarını, bunları kötüye kullanıp kullanamayacağınızı incelemelisiniz.

## E-postalar

Kapsam dahilindeki **domain** ve **subdomain**’lerle, e-posta aramaya başlamak için gereken her şeye sahipsiniz. Bir şirketin e-postalarını bulmak için en iyi sonuç veren **API** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API’lerle
- [**https://hunter.io/**](https://hunter.io/) API’si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API’si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API’si (ücretsiz sürüm)

### **Zafiyet arama**

E-postalar daha sonra web login’lerine ve auth servislerine (SSH gibi) **brute-force** uygularken işinize yarayacak. Ayrıca **phishing** için de gereklidir. Üstelik bu API’ler, phishing kampanyasında işe yarayabilecek şekilde, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** sağlar.

## Kimlik Bilgisi Leak’leri

**Domain**’ler, **subdomain**’ler ve **e-postalar** ile bu e-posta adreslerine ait, geçmişte leak edilmiş kimlik bilgilerini aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet arama**

**Geçerli ve leak edilmiş** kimlik bilgileri bulursanız, bu kolay bir kazanımdır.

## Secret Leak’leri

Kimlik bilgisi leak’leri, **hassas bilgilerin leak edilip satıldığı** şirket saldırılarıyla ilgilidir. Ancak şirketler, bilgileri bu veritabanlarında yer almayan **başka leak’lerden** de etkilenmiş olabilir:

### Github Leak’leri

Şirketin **public repository**’lerinde veya o github şirketinde çalışan **kullanıcıların** public repository’lerinde kimlik bilgileri ve API’ler leak edilmiş olabilir.\
Bir **kuruluşun** ve geliştiricilerinin tüm **public repo**’larını **indirmek** ve üzerlerinde [**gitleaks**](https://github.com/gitleaks/gitleaks) aracını otomatik olarak çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, kendisine verilen tüm **metin URL’lerinde** **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfaları da secret içerir**.

#### Github Dorks

Kuruluşta aranabilecek olası **GitHub dorks** için [GitHub dorks and leaks sayfasına](github-leaked-secrets.md) bakın.

### Paste Leak’leri

Bazen saldırganlar veya çalışanlar şirket içeriğini bir paste sitesinde **yayınlayabilir**. Bu içerik **hassas bilgi** içerebilir de içermeyebilir de; ancak aramaya değer.\
Aynı anda 80’den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki google dorks, **orada olmaması gereken bilgileri bulmak** için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde elle çalıştıramayacağınız birkaç **bin** olası sorgu bulunmasıdır. Bu nedenle, favori 10 sorgunuzu seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Düzenli Google tarayıcısını kullanarak tüm veritabanını çalıştırması beklenen araçların işlemi hiçbir zaman bitmez; çünkü Google sizi çok kısa sürede engeller._

### **Zafiyet arama**

**Geçerli ve leak edilmiş** kimlik bilgileri veya API token’ları bulursanız, bu kolay bir kazanımdır.

## Public Code Zafiyetleri

Şirketin **open-source kodu** olduğunu bulduysanız, bunu **analiz edip** üzerinde **zafiyet** arayabilirsiniz.

**Kullanılan dile bağlı olarak** yararlanabileceğiniz farklı **araçlar** vardır; liste için [source-code review araçlarına](../../network-services-pentesting/pentesting-web/code-review-tools.md) bakın.

Ayrıca, aşağıdaki gibi **public repository’leri taramanıza** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Metodolojisi**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter’ların bulduğu **zafiyetlerin çoğu** **web uygulamalarında** yer alır. Bu nedenle bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum; [**bu bilgiyi burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca, [**Web Automated Scanners open source araçları**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özel olarak değinmek istiyorum. Bu araçların çok hassas zafiyetler bulmasını beklememelisiniz; ancak bazı başlangıç web bilgileri edinmek için bunları **workflow’lara eklemek** işinize yarar.

## Özet

> Tebrikler! Bu noktada **tüm temel enumeration** işlemlerini tamamladınız. Evet, bunlar temel işlemler; çünkü çok daha fazla enumeration yapılabilir (ileride başka numaralar da göreceğiz).

Şimdiye kadar:

1. Kapsam dahilindeki tüm **şirketleri** buldunuz.
2. Şirketlere ait tüm **varlıkları** buldunuz (kapsam dahilindeyse bazı vuln scan işlemleri de yaptınız).
3. Şirketlere ait tüm **domain**’leri buldunuz.
4. Domain’lerin tüm **subdomain**’lerini buldunuz (subdomain takeover var mı?).
5. Kapsam dahilindeki tüm **IP**’leri buldunuz (**CDN’lerden gelen ve gelmeyen**).
6. Tüm **web sunucularını** bulup ekran görüntülerini aldınız (daha yakından incelenmeye değer tuhaf bir şey var mı?).
7. Şirkete ait olabilecek tüm **public cloud varlıklarını** buldunuz.
8. Kolayca **büyük bir kazanç** sağlayabilecek **e-postaları**, **kimlik bilgisi leak’lerini** ve **secret leak’lerini** buldunuz.
9. Bulduğunuz tüm web’lerde **pentesting** yaptınız.

## **Tam Recon Otomasyon Araçları**

Verilen bir kapsama önerilen işlemlerin bir kısmını uygulayabilecek çeşitli araçlar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor



## References

- [1] [Jason Haddix – Bug Hunter’ın Metodolojisi v4.0: Recon Sürümü](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon’lar hakkında: Tarayıcı simgelerinden saldırı yüzeyi istihbaratına](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug bounty’ler, OSINT ve daha fazlası için favicon.ico’yu silahlandırma](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency üzerinde zaman korelasyon saldırısıyla domain keşfetme](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasif takeover: Pahalı bir subdomain takeover kampanyasını ortaya çıkarma (ve taklit etme)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain enumeration için benzersiz bir yöntem](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Tam subdomain keşif workflow’u, Bölüm 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Otomatik Trickest workflow’u ile tam subdomain brute-force keşfi, Bölüm 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash çıktı ekran görüntüsü](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
