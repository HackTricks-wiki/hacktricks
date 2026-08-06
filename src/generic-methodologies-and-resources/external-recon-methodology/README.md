# Harici Recon Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlık keşfi

> Yani bir şirkete ait olan her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte nelere sahip olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için:

1. Ana şirketin satın almalarını bulun; bu, kapsam içindeki şirketleri bize verecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois sorgularını kullanın (bu işlem recursive olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org`ve `ssl`filtreleri gibi teknikleri kullanın (`ssl` yöntemi recursive olarak uygulanabilir).

### **Satın almalar**

Öncelikle, **ana şirkete ait diğer şirketleri** öğrenmemiz gerekir.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri görebilirsiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımızı öğrenelim.

### **ASN'ler**

Bir otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen **IP adresi** **bloklarından** oluşur; ancak birkaç operatörden meydana gelebilir.

**IP aralıklarını** bulmak için **şirkete herhangi bir ASN atanıp atanmadığını** öğrenmek ilginçtir. **Kapsam** içindeki tüm **host'lara** karşı bir **vulnerability test** gerçekleştirmek ve bu IP'lerin içinde **domain'ler aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak, daha fazla veri toplamak için bu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa).** Her durumda, muhtemelen tüm **faydalı bilgiler** (**IP aralıkları ve Whois**) zaten ilk bağlantıda bulunuyordur.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un** enumeration'ı taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.
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
Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) kullanarak da bulabilirsiniz (ücretsiz API içerir).\
Bir domain'in IP ve ASN bilgilerini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Vulnerabilities aranıyor**

Bu noktada **scope içindeki tüm asset'leri biliyoruz**, bu nedenle izin veriliyorsa tüm host'lar üzerinde bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir **veya** Shodan, Censys ya da ZoomEye gibi servisleri **kullanarak** açık port'ları **bulabilirsiniz; bulduklarınıza bağlı olarak** çalışan olası çeşitli servislerde pentest yapmayı öğrenmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** varsayılan username **ve** password **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servisleri **bruteforce** etmeyi denemenin de faydalı olabileceğini belirtmek gerekir.

## Domains

> Scope içindeki tüm şirketleri ve asset'lerini biliyoruz; şimdi scope içindeki domain'leri bulma zamanı.

_Aşağıda açıklanan tekniklerle subdomain'leri de bulabileceğinizi ve bu bilgilerin küçümsenmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana domain**(lerini) aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domain'lerin tüm IP aralıklarını bulduğunuza göre, **scope içinde daha fazla domain bulmak için** bu **IP'ler üzerinde reverse DNS lookup** gerçekleştirmeyi deneyebilirsiniz. Mağdurun bir DNS server'ını veya iyi bilinen bir DNS server'ını (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar reverse lookup ve zenginleştirme işlemlerini otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olan, **bu alanlardan herhangi biriyle reverse whois lookups gerçekleştirerek** (örneğin aynı e-postanın göründüğü diğer whois kayıtları) **şirketle ilişkili daha fazla asset** bulabilmenizdir.\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web kullanımı **ücretsiz**, API ücretsiz değil.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Ücretsiz değil (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Ücretsiz değil (API)

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API key gerektirir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois discovery işlemleri gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferde daha fazla domain name keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada **aynı tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın** da **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID**'sini veya aynı **Adsense ID**'sini görürseniz.

Bu tracker'lar ve daha fazlasına göre arama yapmanıza olanak tanıyan bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/tracker'lara göre ilişkili siteleri bulur)

### **Favicon**

Aynı favicon icon hash'ini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte nasıl kullanıldığı:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon icon hash değerine sahip domain'leri keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash değerine sahip domain'leri keşfetmemizi sağlar.

Ayrıca, [**bu blog gönderisinde**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı üzere favicon hash kullanarak teknolojileri de arayabilirsiniz. Bu, **savunmasız bir web teknolojisi sürümünün favicon hash değerini** biliyorsanız, Shodan'da arama yapıp **daha fazla savunmasız yer bulabileceğiniz** anlamına gelir:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Bir web sitesinin **favicon hash'ini hesaplamanın** yolu şöyledir (**base64-encoded** favicon bytes üzerinde MMH3 kullanarak):
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

Favicon fingerprint'lerini kullanırken hatırlanması gereken faydalı noktalar:<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt olarak değil, bir gösterge olarak değerlendirin**: MMH3 kompakt yapıdadır ve çakışmalar mümkündür; operatörler favicon'ları değiştirebilir veya kasıtlı olarak yanıltıcı bir simgeyi yeniden kullanabilir.
- **`/favicon.ico` dışında daha fazla yol deneyin**: birçok ürün simgeleri framework/build yollarında veya `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, satır içi `data:` URL'leri ya da HTML `<link rel="icon">` etiketleri aracılığıyla sunar. Yolun kendisi bir ürün ailesini fingerprint edebilir.
- **Static dosyalara uygulama erişilebilir değilken bile çoğu zaman erişilebilir**: WAF/SSO/IdP kontrolleri dinamik rotaları koruyabilir, ancak static simgeleri yine de açığa çıkarabilir. Favicon'u her zaman doğrudan isteyin ve zayıf sürüm/build ipuçları için `ETag`, `Last-Modified`, yönlendirmeleri ve cache header'larını inceleyin.
- **Eşleşmeleri çevredeki sinyallerle doğrulayın**: bir favicon'un bir ürünü tanımladığı sonucuna varmadan önce başlığı, HTML/body hash'ini, header'ları, TLS sertifikası subject/SAN alanlarını, Shodan/Censys bileşenlerini ve açık portları karşılaştırın.
- **Büyük ölçekte pivot yaparken HTML/body hash'ine göre kümelendirin**: bir favicon'u paylaşan host'ların çoğu tek bir sayfa şablonunda birleşiyorsa fingerprint daha güçlüdür; aynı hash birçok ilgisiz şablona ayrılıyorsa ürün etiketi yerine "generic/shared/honeypot" tercih edin.
- **Honeypot sezgisi**: aynı favicon hash'i birçok ilgisiz HTML imzası, rastgele port ve çelişkili ürün arasında görünüyorsa bunu gerçek bir ürün fingerprint'i yerine muhtemel bir honeypot veya generic placeholder olarak değerlendirin.
- **Belirsiz hedeflerde 404 probe kullanın**: browser içinde gerçek bir sayfa ve `/_favicon_probe_<8-hex>` gibi var olmayan bir yol alın. Eşleşen hosting-provider/parking yanıtları, paylaşılan favicon'ları gerçek ürün örtüşmesinden daha iyi açıklayabilir.
- **Detection rule'larından mapping'ler oluşturun**: Nuclei template'leri ve public favicon dataset'leri, CVE duyurularından sonra hızlı triage için faydalı olan bilinen `favicon` ↔ `product` ↔ `CPE` mapping'leri sağlayabilir.
- **Kapsama uyarısı**: Shodan tarzı dataset'ler IP merkezlidir. CDN-fronted, SNI-routed, anycast ve yalnızca domain üzerinden erişilen yüzeyler düşük sayılabilir; bu nedenle düşük hit sayısı, gerçek dünyadaki dağıtımın düşük olduğu **anlamına gelmez**.

### **Copyright / Uniq string**

Web sayfalarının içinde **aynı kuruluşun farklı web siteleri arasında paylaşılabilecek string'leri** arayın. **Copyright string** iyi bir örnek olabilir. Ardından bu string'i **google**, diğer **browsers** veya hatta **shodan** içinde arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şu tür bir cron job kullanılması yaygındır:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm domain sertifikalarını yenilemek. Bu, bunun için kullanılan CA oluşturulma zamanını Validity time içinde belirtmese bile, **certificate transparency loglarında aynı şirkete ait domainleri bulmanın mümkün olduğu** anlamına gelir.\
Daha fazla bilgi için [**bu writeup'a göz atın**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı dmarc bilgilerini paylaşan domainleri ve subdomainleri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Diğer faydalı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Görünüşe göre insanların subdomainleri cloud provider'lara ait IP'lere yönlendirmesi ve bir noktada **bu IP adresini kaybedip DNS kaydını kaldırmayı unutması** oldukça yaygın. Bu nedenle bir cloud üzerinde (Digital Ocean gibi) yalnızca **bir VM oluşturmanız**, aslında **bazı subdomainleri ele geçirmenizi** sağlar.

[**Bu gönderi**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir olayı açıklıyor ve **DigitalOcean'da bir VM oluşturan**, yeni makinenin **IPv4** adresini **alan** ve **Virustotal'da kendisine yönlenen subdomain kayıtlarını arayan** bir script öneriyor.<sup>[[7]](#references)</sup>

### **Other ways**

**Yeni bir domain bulduğunuz her seferinde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

**Shodan**

IP alanına sahip kuruluşun adını zaten bildiğiniz için, Shodan'da şu ifadeyi kullanarak bu veriye göre arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları, TLS sertifikasında yer alan yeni ve beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name** bilgisini alabilir ve ardından bu adı, **Shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikaları** içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana domainle **ilişkili domainleri** ve bunların **subdomainlerini** arayan bir araçtır; oldukça etkileyicidir.

**Passive DNS / Historical DNS**

Passive DNS verileri, hâlâ çözümlenen veya ele geçirilebilen **eski ve unutulmuş kayıtları** bulmak için oldukça faydalıdır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir domain kullanıyordur**, ancak **sahipliğini kaybetmiştir**. Yeterince ucuzsa domaini kaydedin ve şirketi bilgilendirin.

Asset discovery sırasında daha önce bulduklarınızdan **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **port scan** gerçekleştirmelisiniz: [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside), **nmap/masscan/shodan** kullanabilirsiniz. Çalışan servislere bağlı olarak, **bu kitapta bunlara "saldırmak" için bazı teknikler** bulabilirsiniz.\
_Bazen domainin client tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle kapsam dahilinde olmadığını unutmayın; dikkatli olun._

## Subdomains

> Kapsam dahilindeki tüm şirketleri, her şirketin tüm assetlerini ve şirketlerle ilişkili tüm domainleri biliyoruz.

Bulunan her domainin olası tüm subdomainlerini bulmanın zamanı geldi.

> [!TIP]
> Domainleri bulmak için kullanılan bazı araçların ve tekniklerin subdomainleri bulmaya da yardımcı olabileceğini unutmayın

### **DNS**

**DNS** kayıtlarından **subdomainleri** elde etmeye çalışalım. Ayrıca **Zone Transfer** için de deneme yapmalıyız (zafiyet varsa raporlamalısınız).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu external sources üzerinde arama yapmaktır. En sık kullanılan **araçlar** aşağıdakilerdir (daha iyi sonuçlar için API anahtarlarını yapılandırın):

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
**subdomain** bulma konusunda doğrudan uzmanlaşmamış olsalar bile, subdomain bulmak için yararlı olabilecek **diğer ilginç araçlar/API'ler** de vardır:

- [**IP.THC.ORG**](https://ip.thc.org) ücretsiz API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Alt alan adlarını elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır
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
- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault'ın Open Threat Exchange, Wayback Machine ve Common Crawl servislerinden bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayarak JS dosyalarını arar ve bu dosyalardan subdomain'leri çıkarırlar.
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
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
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

Bu proje, **bug-bounty programlarıyla ilgili tüm subdomain'leri ücretsiz** olarak sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak da erişebilir veya bu proje tarafından kullanılan scope'a şu adresten erişebilirsiniz: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Bu araçların birçoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmayı deneyelim.

Bu işlem için bazı **yaygın subdomain wordlist'lerine ihtiyacınız olacak**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının bir listesini oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu da kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force işlemi gerçekleştiren ilk araçtı. Çok hızlıdır, ancak false positive'lere yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış, `massdns` etrafında çalışan bir wrapper'dır; aktif bruteforce kullanarak geçerli subdomain'leri enumerate etmenize, wildcard işleme ile subdomain'leri resolve etmenize ve kolay input-output desteğinden yararlanmanıza olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını asenkron olarak brute force yapmak için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynakları kullanarak ve brute-force yaparak subdomain'leri bulduktan sonra, daha fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain'lerden permutation'lar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.
- goaltdns permütasyonları için **wordlist**'i [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Domain ve subdomain'ler verildiğinde permutation'lar oluşturur. Bir permutation dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutations oluşturmaya ek olarak bunları resolve etmeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
- altdns permutations **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Subdomain'lerin permutations, mutations ve alteration işlemlerini gerçekleştiren başka bir araçtır. Bu araç sonucu brute force yöntemiyle bulur (dns wild card desteği yoktur).
- dmut permutations wordlist'ini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) edinebilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, daha fazla alt alan adı keşfetmeyi denemek için belirtilen kalıplara göre **yeni olası alt alan adı adları üretir**.

#### Akıllı permutation üretimi

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**gönderiyi**](https://cramppet.github.io/regulator/index.html) okuyun; ancak temel olarak **keşfedilen alt alan adlarından** **ana parçaları** alır ve daha fazla alt alan adı bulmak için bunları birbirleriyle karıştırır.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ancak etkili bir DNS yanıtı rehberli algoritmayla birleştirilmiş bir subdomain brute-force fuzzer'dır. Tailored wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir input data setini kullanarak daha fazla karşılık gelen domain name'i doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows** kullanarak bir domain üzerinden **subdomain discovery işlemini otomatikleştirme** hakkında yazdığım ve bilgisayarımda bir sürü aracı manuel olarak başlatmamı gerektirmeyen bu blog yazılarına göz atın:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birden fazla web sayfası** içeren bir IP adresi bulduysanız, **OSINT kaynaklarında** bir IP üzerindeki domain'leri arayarak veya **o IP üzerindeki VHost domain isimlerini brute-force ederek**, **o IP'de web sitesi bulunan diğer subdomain'leri bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerde bazı **VHost'ları bulabilirsiniz**.

**Brute Force**

Bir web server'da bazı subdomain'lerin gizlenmiş olabileceğinden şüpheleniyorsanız brute-force etmeyi deneyebilirsiniz:

**IP bir hostname'e yönlendirme yaptığında** (name-based vhosts), `Host` header'ını doğrudan fuzz'layın ve varsayılan vhost'tan farklı yanıtları öne çıkarmak için ffuf'un **auto-calibrate** özelliğini kullanın:<sup>[[2]](#references)</sup>
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
> Bu teknikle internal/hidden endpoint'lere bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında yalnızca _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı abuse edebilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** ararken herhangi bir **bucket** türüne **pointing** yapıp yapmadığını kontrol edin ve böyle bir durum varsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca bu aşamada kapsam içindeki tüm domainleri biliyor olacağınız için, [**olası bucket adlarını brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

**Certificate Transparency** Logs'u izleyerek bir domain için **yeni subdomain** oluşturulup oluşturulmadığını, [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) aracının yaptığı gibi **monitor** edebilirsiniz.

### **Looking for vulnerabilities**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
Eğer **subdomain** herhangi bir **S3 bucket**'ına pointing yapıyorsa, [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Eğer asset keşfi sırasında daha önce bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir subdomain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Çalışan servislere bağlı olarak, **bu kitapta bunlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen subdomain, client tarafından kontrol edilmeyen bir IP üzerinde barındırılır; bu nedenle kapsam içinde değildir. Dikkatli olun._

## IPs

İlk adımlarda bazı **IP aralıkları, domainler ve subdomainler** bulmuş olabilirsiniz.\
Şimdi bu aralıklardaki tüm IP'leri ve **domainler/subdomainler için (DNS queries)** bilgileri toplamaya başlamanın zamanı.

Aşağıdaki **free APIs** servislerini kullanarak **domainler ve subdomainler tarafından daha önce kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine pointing yapan domainleri kontrol edebilirsiniz.

### **Looking for vulnerabilities**

**CDN'lere ait olmayan tüm IP'lerde port scan gerçekleştirin** (çünkü büyük olasılıkla orada ilginç bir şey bulamazsınız). Keşfedilen çalışan servislerde **vulnerabilities bulabilirsiniz**.

Hostların nasıl taranacağı hakkında bir [**guide**](../pentesting-network/index.html) **bulun.**

## Web servers hunting

> Tüm şirketleri ve bunların asset'lerini bulduk; kapsam içindeki IP aralıklarını, domainleri ve subdomainleri biliyoruz. Şimdi web server arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domainler üzerinde bazı **recon** işlemleri gerçekleştirdiniz; dolayısıyla **olası tüm web serverları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi kapsam içindeki web serverları aramak için bazı **hızlı yöntemleri** inceleyeceğiz.

Lütfen bunun **web app discovery** odaklı olacağını unutmayın; bu nedenle kapsam tarafından **izin veriliyorsa**, **vulnerability** ve **port scanning** işlemlerini de gerçekleştirmelisiniz.

[**masscan** kullanarak web serverlarıyla ilişkili **açık portları** keşfetmek için hızlı bir yöntem [**burada bulunabilir**](../pentesting-network/index.html#http-port-discovery).\
Web serverları aramak için kullanılabilecek başka bir kullanıcı dostu araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araç port 80 (http) ve 443 (https) ile bağlantı kurmayı dener. Ayrıca başka portları denemesini de belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Artık kapsamda bulunan **tüm web sunucularını** (şirketin **IP** adresleri ile tüm **domain** ve **subdomain** adresleri arasından) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Öyleyse bunu basitleştirelim ve hepsinin ekran görüntülerini alarak başlayalım. Sadece **ana sayfaya** **bakarak**, **vulnerable** olma ihtimali daha **yüksek** olan **garip** endpoint'ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca daha sonra [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanarak tüm **screenshots** üzerinde çalıştırabilir ve size **hangilerinin vulnerability içermesinin muhtemel olduğunu**, hangilerinin ise olmadığını söylemesini sağlayabilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek cloud asset'lerini bulmak için **şirketi tanımlayan keyword'lerden oluşan bir listeyle başlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca bucket'larda kullanılan **yaygın kelimelere** ait wordlist'lere de ihtiyacınız olacaktır:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Daha sonra bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken yalnızca AWS'deki bucket'lara bakmamanız gerektiğini unutmayın.

### **Looking for vulnerabilities**

**Açık bucket'lar veya dışarıya açılmış cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, size neler sunduklarını ve bunları abuse edip edemeyeceğinizi görmeye çalışmalısınız.

## Emails

Kapsam içindeki **domain** ve **subdomain** adresleriyle, temel olarak **email aramaya başlamak** için ihtiyacınız olan her şeye sahipsiniz. Bunlar, bir şirkete ait email'leri bulmak için benim açımdan en iyi çalışan **API** ve **araçlardır**:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (free version)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (free version)
- [**https://minelead.io/**](https://minelead.io/) API'si (free version)

### **Looking for vulnerabilities**

Email'ler daha sonra **web login'lerine ve auth servislerine brute-force uygulamak** (SSH gibi) için işinize yarayacaktır. Ayrıca **phishing** için de gereklidirler. Bunun yanında bu API'ler, email'in arkasındaki **kişi hakkında daha fazla bilgi** sağlayacaktır; bu da phishing campaign için kullanışlıdır.

## Credential Leaks

**Domain'ler,** **subdomain'ler** ve **email'lerle**, geçmişte bu email'lere ait olarak leak edilmiş credential'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**Geçerli leak edilmiş** credential'lar bulursanız bu, çok kolay bir kazanımdır.

## Secrets Leaks

Credential leak'leri, şirketlerin hack'lendiği ve **hassas bilgilerin leak edilip satıldığı** durumlarla ilişkilidir. Ancak şirketler, bilgileri bu database'lerde bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credential'lar ve API'ler, **şirketin** veya o Github şirketinde çalışan **kullanıcıların** **public repository**'lerinde leak edilmiş olabilir.\
Tüm **public repo**'ları bir **organization**'dan ve onun **developer**'larından **download** etmek ve bunlar üzerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **tool**'unu kullanabilirsiniz.

**Leakos**, kendisine verilen **URL'lerdeki** tüm **text** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web page'ler de secret içerir**.

#### Github Dorks

Potansiyel **github dork**'ları için şu **page**'i de kontrol edin; bu dork'ları saldırdığınız organization içinde arayabilirsiniz:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar veya yalnızca çalışanlar, şirket içeriğini bir paste site'ında **publish** eder. Bu içerik **hassas bilgi** içerebilir veya içermeyebilir; ancak bunu aramak oldukça ilgi çekicidir.\
Aynı anda 80'den fazla paste site'ında arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) tool'unu kullanabilirsiniz.

### Google Dorks

Eski ama değerli Google dork'ları, **orada bulunmaması gereken expose edilmiş bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) içinde manuel olarak çalıştıramayacağınız binlerce olası query bulunmasıdır. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir tool** kullanabilirsiniz.

_Database'in tamamını normal Google browser'ı kullanarak çalıştırmayı bekleyen tool'ların hiçbir zaman bitmeyeceğini unutmayın; çünkü Google sizi çok kısa sürede engelleyecektir._

### **Looking for vulnerabilities**

**Geçerli leak edilmiş** credential'lar veya API token'ları bulursanız bu, çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**'a sahip olduğunu fark ederseniz bunu **analiz edebilir** ve üzerinde **vulnerability** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **tool'lar** vardır:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca aşağıdakiler gibi **public repository'leri scan etmenize** izin veren ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'lar tarafından bulunan **vulnerability'lerin çoğu** **web application'ların** içinde yer alır. Bu nedenle bu noktada bir **web application testing methodology** hakkında konuşmak istiyorum; bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünden özellikle bahsetmek istiyorum. Bu tool'ların çok hassas vulnerability'ler bulmasını beklememeniz gerekse de, bazı başlangıç seviyesinde web bilgilerine sahip olmak amacıyla bunları **workflow'lara eklemek** kullanışlıdır.

## Recapitulation

> Tebrikler! Bu noktada **tüm temel enumeration** işlemlerini zaten gerçekleştirdiniz. Evet, bu temel seviyededir; çünkü çok daha fazla enumeration yapılabilir (daha sonra daha fazla trick göreceğiz).

Şunları zaten yaptınız:

1. Kapsam içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset'leri** buldunuz (kapsam içindeyse bazı vuln scan işlemleri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain'leri** buldunuz
4. Domain'lerin tüm **subdomain'lerini** buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP** adreslerini (CDN'lerden gelen ve **gelmeyen**) buldunuz.
6. Tüm **web sunucularını** buldunuz ve ekran görüntülerini aldınız (daha derinlemesine incelenmeye değer garip bir şey var mı?)
7. Şirkete ait olabilecek tüm **public cloud asset'lerini** buldunuz.
8. Çok kolay bir şekilde **büyük bir kazanım** sağlayabilecek **email'leri**, **credential leak'lerini** ve **secret leak'lerini** buldunuz.
9. Bulduğunuz tüm web'lerde **Pentesting yaptınız**

## **Full Recon Automatic Tools**

Belirli bir kapsama karşı önerilen işlemlerin bir kısmını gerçekleştirebilen çeşitli tool'lar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncel değil

## References

- [1] [**@Jhaddix**](https://twitter.com/Jhaddix)'in [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI) gibi tüm ücretsiz kursları
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
