# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset keşfi

> Bir şirkete ait olan her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte neleri sahip olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirketin sahip olduğu tüm şirketleri** ve ardından bu şirketlerin tüm **asset'lerini** elde etmektir. Bunu yapmak için:

1. Ana şirketin satın almalarını bulun; bu, kapsam dahilindeki şirketleri verecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois sorgularını kullanın (bu işlem recursive olarak yapılabilir).
4. Diğer asset'leri aramak için shodan `org` ve `ssl` filtreleri gibi teknikleri kullanın (`ssl` tekniği recursive olarak uygulanabilir).

### **Acquisitions**

Öncelikle, **ana şirketin sahip olduğu diğer şirketleri** öğrenmemiz gerekir.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Global şirket yapıları ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam dahilindeki tüm şirketleri biliyor olmalısınız. Şimdi bunların asset'lerini nasıl bulacağımızı öğrenelim.

### **ASNs**

Bir autonomous system number (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **autonomous system**'e (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici network'lere erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen **IP adresi** **bloklarından** oluşur; ancak birden fazla operatörden meydana gelebilir.

Şirketin **IP aralıklarını** bulmak için herhangi bir **ASN atanmış olup olmadığını** öğrenmek ilginçtir. **Kapsam** dahilindeki tüm **host'lara** karşı bir **vulnerability test** gerçekleştirmek ve bu IP'ler içindeki **domain'leri aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak daha fazla veri toplamak için bu linkler faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** Her durumda, muhtemelen tüm** faydalı bilgiler **(IP aralıkları ve Whois)** zaten ilk linkte görünmektedir.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un**
enumeration'ı taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.
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

Bu noktada **scope içindeki tüm asset'leri** biliyoruz; bu nedenle izin veriliyorsa tüm host'lar üzerinde bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir **veya** Shodan, Censys ya da ZoomEye gibi servisleri **kullanarak** açık port'ları **bulabilirsiniz**; bulduklarınıza bağlı olarak, çalışan çeşitli olası servislerin pentest'ini nasıl yapacağınızı öğrenmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** password **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servisleri **bruteforce** etmeyi de deneyebileceğinizi belirtmek faydalı olabilir.

## Domain'ler

> Scope içindeki tüm şirketleri ve asset'lerini biliyoruz; şimdi scope içindeki domain'leri bulma zamanı.

_Lütfen aşağıda açıklanan tekniklerle subdomain'leri de bulabileceğinizi ve bu bilgilerin küçümsenmemesi gerektiğini unutmayın._

Öncelikle her şirketin **ana domain**(ler)ini aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domain'lerin tüm IP aralıklarını bulduğunuza göre, **scope içinde daha fazla domain bulmak için** bu **IP'ler üzerinde reverse dns lookups** gerçekleştirmeyi deneyebilirsiniz. Victim'e ait bir dns server'ı veya iyi bilinen bir dns server'ı (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
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

Bir **whois** içinde **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olan, bu alanlardan herhangi biriyle **reverse whois lookups** gerçekleştirerek **şirketle ilişkili daha fazla asset** bulabilmenizdir (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
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

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (whoxy API anahtarı gerektirir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois keşifleri gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Tracker'lar**

2 farklı sayfada aynı **tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın** da **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID'sini** veya aynı **Adsense ID'sini** görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanıza olanak tanıyan bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/tracker'lara göre ilişkili siteleri bulur)

### **Favicon**

Aynı favicon simgesinin hash'ini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. Kullanımı şöyledir:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon icon hash değerine sahip domain'leri keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash değerine sahip domain'leri keşfetmemizi sağlar.

Ayrıca, [**bu blog yazısında**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı gibi favicon hash değerini kullanarak teknolojileri de arayabilirsiniz. Bu, **web teknolojisinin savunmasız bir sürümüne ait favicon hash değerini** biliyorsanız, Shodan'da arama yapıp **daha fazla savunmasız yer bulabileceğiniz** anlamına gelir:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Bir web sitesinin **favicon hash** değerini şu şekilde **hesaplayabilirsiniz** (**base64-encoded** favicon baytları üzerinden MMH3):
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
Ayrıca [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile favicon hash'lerini geniş ölçekte alabilir ve ardından Shodan/Censys üzerinde pivot edebilirsiniz.

Favicon fingerprint'lerini kullanırken hatırlanması gerekenler:

- **Hash'i kanıt değil, bir gösterge olarak değerlendirin**: MMH3 compact bir yapıya sahiptir ve collision'lar mümkündür; operatörler favicon'ları değiştirebilir veya kasıtlı olarak yanıltıcı bir icon'u yeniden kullanabilir.
- **`/favicon.ico` dışında da probe yapın**: birçok ürün icon'ları framework/build path'lerinde veya `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, inline `data:` URL'leri ya da HTML `<link rel="icon">` tag'leri üzerinden sunar. Path'in kendisi bir ürün ailesini fingerprint edebilir.
- **Static file'lara uygulama erişilebilir olmadığında bile çoğunlukla ulaşılabilir**: WAF/SSO/IdP kontrolleri dynamic route'ları koruyabilir, ancak static icon'ları açıkta bırakabilir. Favicon'u her zaman doğrudan request edin ve zayıf version/build ipuçları için `ETag`, `Last-Modified`, redirect'leri ve cache header'larını inceleyin.
- **Match'leri çevredeki sinyallerle doğrulayın**: bir favicon'un bir ürünü tanımladığı sonucuna varmadan önce title, HTML/body hash'i, header'lar, TLS certificate subject/SAN'ları, Shodan/Censys component'leri ve açık port'ları karşılaştırın.
- **Geniş ölçekte pivot yaparken HTML/body hash'ine göre cluster oluşturun**: bir favicon'u paylaşan host'ların çoğu tek bir page template altında birleşiyorsa fingerprint daha güçlüdür; aynı hash birçok ilgisiz template'e ayrılıyorsa ürün etiketi yerine `"generic/shared/honeypot"` tercih edin.
- **Honeypot heuristic**: aynı favicon hash'i birçok ilgisiz HTML signature'ında, rastgele port'larda ve birbiriyle çelişen ürünlerde görülüyorsa bunu gerçek bir ürün fingerprint'i yerine olası bir honeypot veya generic placeholder olarak değerlendirin.
- **Belirsiz target'larda 404 probe kullanın**: browser'da gerçek bir page'i ve `/_favicon_probe_<8-hex>` gibi var olmayan bir path'i fetch edin. Eşleşen hosting-provider/parking response'ları, paylaşılan favicon'ları gerçek ürün örtüşmesinden daha iyi açıklayabilir.
- **Detection rule'larından bootstrap mapping'leri oluşturun**: Nuclei template'leri ve public favicon dataset'leri, CVE disclosure'larından sonra hızlı triage için faydalı olan bilinen `favicon` ↔ `product` ↔ `CPE` mapping'leri sağlayabilir.
- **Coverage caveat**: Shodan tarzı dataset'ler IP merkezlidir. CDN-fronted, SNI-routed, anycast ve yalnızca domain üzerinden erişilen surface'ler eksik sayılabilir; bu nedenle düşük hit sayısı, gerçek dünyadaki deployment'ın düşük olduğu anlamına **gelmez**.

### **Copyright / Uniq string**

Web page'lerinin içinde **aynı organisation içindeki farklı web siteleri arasında paylaşılabilecek string'leri** arayın. **Copyright string** iyi bir örnek olabilir. Ardından bu string'i **Google'da**, diğer **browser'larda** veya hatta **Shodan'da** arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şuna benzer bir cron job kullanılması yaygındır
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm domain sertifikalarını yenilemek. Bu, bunun için kullanılan CA, oluşturulma zamanını Validity time içinde belirtmese bile, **certificate transparency loglarında aynı şirkete ait domainleri bulmanın mümkün olduğu** anlamına gelir.\
Daha fazla bilgi için [**bu writeup'a göz atın**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**aynı dmarc bilgilerini paylaşan domainleri ve subdomainleri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesi veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir tool kullanabilirsiniz.\
Diğer faydalı tool'lar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

İnsanların subdomainleri cloud provider'lara ait IP'lere yönlendirmesi ve bir noktada **bu IP adresini kaybetmesine rağmen DNS kaydını kaldırmayı unutması** görünüşe göre yaygın bir durumdur. Bu nedenle bir cloud üzerinde (Digital Ocean gibi) yalnızca **bir VM oluşturduğunuzda**, aslında **bazı subdomainleri ele geçirmiş** olursunuz.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir olayı açıklamakta ve **DigitalOcean'da bir VM oluşturan**, yeni makinenin **IPv4** adresini **alan** ve **Virustotal'da kendisine yönlenen subdomain kayıtlarını arayan** bir script önermektedir.

### **Diğer yöntemler**

**Yeni bir domain bulduğunuz her seferde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

**Shodan**

IP alanına sahip kuruluşun adını zaten bildiğiniz için, Shodan'da şu ifadeyi kullanarak bu veriyi arayabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları, TLS sertifikasında yer alan yeni ve beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name** bilgisini alabilir ve ardından bu adı **Shodan** tarafından bilinen tüm web sayfalarının **TLS sertifikaları** içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir tool kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ana domainle **ilişkili domainleri** ve bunların **subdomainlerini** arayan bir tool'dur; oldukça etkileyicidir.

**Passive DNS / Historical DNS**

Passive DNS verileri hâlâ resolve olan veya ele geçirilebilen **eski ve unutulmuş kayıtları** bulmak için oldukça faydalıdır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Zafiyet arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Bir şirket **bir domain kullanıyor** olabilir, ancak **domainin sahipliğini kaybetmiş** olabilir. Yeterince ucuzsa domaini kaydedin ve şirkete bildirin.

Asset discovery sırasında daha önce bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) işlemleri gerçekleştirmelisiniz; bunun için **nmap/masscan/shodan** kullanabilirsiniz. Çalışan servislere bağlı olarak, **onlara "saldırmak"** için **bu kitapta bazı teknikler** bulabilirsiniz.\
_Bazen domainin, client tarafından kontrol edilmeyen bir IP içinde barındırıldığını ve bu nedenle kapsam dahilinde olmadığını unutmayın; dikkatli olun._

## Subdomainler

> Kapsam dahilindeki tüm şirketleri, her şirketin tüm assetlerini ve şirketlerle ilişkili tüm domainleri biliyoruz.

Bulunan her domainin olası tüm subdomainlerini bulmanın zamanı geldi.

> [!TIP]
> Domainleri bulmak için kullanılan bazı tool ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın

### **DNS**

**DNS** kayıtlarından **subdomainleri** elde etmeye çalışalım. Ayrıca **Zone Transfer** için de deneme yapmalıyız (Vulnerable ise bunu raporlamalısınız).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu external sources üzerinde arama yapmaktır. En çok kullanılan **tools** aşağıdakilerdir (daha iyi sonuçlar için API keys yapılandırın):

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
**subdomain bulma konusunda doğrudan uzmanlaşmamış olsalar da subdomain bulmak için faydalı olabilecek başka ilginç araçlar/API'ler** de vardır, örneğin:

- [**IP.THC.ORG**](https://ip.thc.org) ücretsiz API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Subdomain'leri elde etmek için [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanır
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
- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault's Open Threat Exchange, Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayarak JS dosyalarını arar ve buradan subdomain'leri çıkarırlar.
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

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz olarak** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak veya bu projenin kullandığı scope'a [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) erişerek ulaşabilirsiniz.

Bu araçların çoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının bir listesini oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu da kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır ancak false positive'lere yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bu aracın yalnızca 1 resolver kullandığını düşünüyorum
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış, `massdns` etrafında çalışan bir wrapper'dır; aktif bruteforce kullanarak geçerli subdomain'leri enumerate etmenize, ayrıca wildcard handling ve kolay input-output desteğiyle subdomain'leri resolve etmenize olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): O da `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını asynchronous olarak brute force etmek için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Aşaması

Open source ve brute-force kullanarak subdomain'leri bulduktan sonra, daha fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla çeşitli araçlar kullanılabilir:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain'leri kullanarak permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'leri kullanarak permutation'lar oluşturur.
- goaltdns permutation'ları için **wordlist**'i [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) edinebilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Domain ve subdomain'ler verildiğinde permutation'lar oluşturur. Herhangi bir permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutation'ları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
- altdns permutation'ları için **wordlist**'i [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Subdomain'lerin permutations, mutations ve alterations işlemlerini gerçekleştiren başka bir araç. Bu araç sonucu brute force ile bulur (dns wild card desteği yoktur).
- dmut permutations wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temel alınarak, daha fazla subdomain keşfetmeyi denemek için belirtilen pattern'lere göre **yeni olası subdomain adları oluşturur**.

#### Akıllı permutation oluşturma

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**yazıyı**](https://cramppet.github.io/regulator/index.html) okuyun; temel olarak **keşfedilen subdomain'lerden** **ana parçaları** alır ve daha fazla subdomain bulmak için bunları birbiriyle karıştırır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, özel olarak hazırlanmış bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan input verilerini kullanan, subdomain brute-force fuzzer'ıdır. Basit ancak etkili bir DNS response-guided algoritmayla, daha fazla karşılık gelen domain name'i doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows** kullanarak bir domain'den **subdomain discovery işlemini otomatikleştirme** hakkında yazdığım bu blog gönderisine göz atın; böylece bilgisayarımda bir sürü aracı manuel olarak çalıştırmam gerekmiyor:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, **OSINT kaynaklarında** bir IP üzerindeki domain'leri arayarak veya **bu IP'deki VHost domain adlarını brute-force ederek**, **aynı IP'de web siteleri bulunan diğer subdomain'leri bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerde bazı VHost'ları bulabilirsiniz**.

**Brute Force**

Bazı subdomain'lerin bir web sunucusunda gizlenmiş olabileceğinden şüpheleniyorsanız brute-force yapmayı deneyebilirsiniz:

**IP bir hostname'e yönlendirme yaptığında** (name-based vhosts), `Host` header'ını doğrudan fuzz'layın ve varsayılan vhost'tan farklı yanıtları öne çıkarmak için ffuf'un **auto-calibrate** özelliğini kullanın:
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
> Bu teknikle internal/hidden endpoint'lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** ararken bunlardan herhangi bir **bucket** türüne **pointing** yapıp yapmadığını kontrol edin ve böyle bir durumda [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu noktada scope içindeki tüm domainleri biliyor olacağınız için olası bucket adlarını [**brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

**Certificate Transparency** Logs'u izleyerek bir domaine ait **yeni subdomainler** oluşturulup oluşturulmadığını, [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)'in yaptığı gibi **monitor** edebilirsiniz.

### **Vulnerability arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**subdomain** herhangi bir **S3 bucket**'ına pointing yapıyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset discovery sırasında daha önce bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir subdomain** bulursanız, **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz; bunun için **nmap/masscan/shodan** kullanabilirsiniz. Çalışan servislere bağlı olarak **bu kitapta bunlara "attack" uygulamak için bazı yöntemler bulabilirsiniz**.\
_Bazen subdomain, client tarafından kontrol edilmeyen bir IP üzerinde barındırılabilir; bu nedenle scope içinde olmayabilir, dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP range'leri, domainler ve subdomainler** bulmuş olabilirsiniz.\
Şimdi bu range'lerdeki **tüm IP'leri** ve **domain/subdomain'ler için (DNS sorguları aracılığıyla)** IP'leri toplama zamanı.

Aşağıdaki **free api**'lerin servislerini kullanarak **domainler ve subdomainler tarafından daha önce kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypass'leri**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Belirli bir IP adresine pointing yapan domainleri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz.

### **Vulnerability arama**

**CDN'lere ait olmayan tüm IP'lerde port scan gerçekleştirin** (çünkü büyük olasılıkla burada ilginç bir şey bulamayacaksınız). Tespit edilen çalışan servislerde **vulnerability bulabilirsiniz**.

Host'ların nasıl taranacağı hakkında bir [**guide**](../pentesting-network/index.html) **bulun**.

## Web server hunting

> Tüm şirketleri ve bunların asset'lerini bulduk ve scope içindeki IP range'lerini, domainleri ve subdomainleri biliyoruz. Şimdi web server'ları arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domainler üzerinde bazı **recon** işlemleri gerçekleştirdiniz; bu nedenle **olası tüm web server'ları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, scope içindeki web server'ları aramak için bazı **hızlı yöntemleri** şimdi inceleyeceğiz.

Lütfen bunun **web app discovery** odaklı olacağını unutmayın; bu nedenle scope tarafından (**izin veriliyorsa**) **vulnerability** ve **port scanning** de gerçekleştirmelisiniz.

[**masscan** kullanarak web server'larla ilişkili **açık portları** keşfetmeye yönelik **hızlı bir yöntem** [burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web server'ları aramak için kullanılabilecek bir diğer kullanıcı dostu araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araç port 80'e (http) ve 443'e (https) bağlanmayı dener. Ayrıca başka portları denemesini de belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık scope içinde bulunan **tüm web sunucularını** (şirketin **IP'leri** ile tüm **domain** ve **subdomain**'ler arasında) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O hâlde işi basitleştirelim ve öncelikle tümünün ekran görüntülerini alalım. Sadece **ana sayfaya** **bakarak**, **vulnerable** olma ihtimali daha **yüksek** olan **garip** endpoint'ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot) kullanabilirsiniz**.**

Ayrıca tüm **ekran görüntüleri** üzerinde [**eyeballer**](https://github.com/BishopFox/eyeballer) çalıştırarak **vulnerabilities içermesi muhtemel olanları** ve olmayanları belirlemesini sağlayabilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek cloud asset'leri bulmak için **şirketi tanımlayan anahtar kelimelerden oluşan bir listeyle başlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca bucket'larda kullanılan **yaygın kelimelerden** oluşan wordlist'lere de ihtiyacınız olacaktır:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Daha sonra bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** gibi araçları kullanabilirsiniz.

Cloud Assets ararken AWS'deki bucket'lardan daha fazlasını aramanız gerektiğini unutmayın.

### **Vulnerabilities arama**

**Açık bucket'lar veya exposed cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, size neler sunduklarını ve bunları abuse edip edemeyeceğinizi kontrol etmelisiniz.

## E-postalar

Scope içindeki **domain** ve **subdomain**'lerle, **e-posta aramaya başlamak için ihtiyacınız olan her şeye** temel olarak sahipsiniz. Bunlar bir şirketin e-postalarını bulmak için benim açımdan en iyi sonuç veren **API'ler** ve **tool**'lardır:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (free version)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (free version)
- [**https://minelead.io/**](https://minelead.io/) API'si (free version)

### **Vulnerabilities arama**

E-postalar daha sonra **web login'lerini ve auth servislerini brute-force etmek** (SSH gibi) için işinize yarayacaktır. Ayrıca **phishing** için de gereklidir. Dahası, bu API'ler size e-postanın arkasındaki **kişi hakkında daha fazla bilgi** verecek ve bu da phishing campaign için faydalı olacaktır.

## Credential Leaks

**Domain**, **subdomain** ve **e-postalarla**, geçmişte bu e-postalara ait olarak leak edilmiş credential'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Vulnerabilities arama**

**Geçerli leak edilmiş** credential'lar bulursanız bu, çok kolay bir kazanımdır.

## Secrets Leaks

Credential leak'leri, şirketlerin **hassas bilgilerinin leak edilip satıldığı** hack'lerle ilişkilidir. Ancak şirketler, bilgileri bu database'lerde bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credential'lar ve API'ler, **şirketin** veya o github şirketinde çalışan **kullanıcıların** **public repository**'lerinde leak edilmiş olabilir.\
[**Leakos**](https://github.com/carlospolop/Leakos) **tool**'unu kullanarak bir **organization**'ın ve geliştiricilerinin tüm **public repo**'larını **download** edebilir ve bunların üzerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırabilirsiniz.

**Leakos**, kendisine **passed URL'ler** tarafından sağlanan tüm **text** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfaları da secret'lar içerir**.

#### Github Dorks

Potansiyel **github dorks** için, saldırdığınız organization'da da arayabileceğiniz şu **sayfayı** kontrol edin:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar veya yalnızca çalışanlar, **şirket içeriğini bir paste sitesinde publish eder**. Bu içerik **hassas bilgiler** içerebilir veya içermeyebilir; ancak aramak oldukça ilginçtir.\
80'den fazla paste sitesinde aynı anda arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) tool'unu kullanabilirsiniz.

### Google Dorks

Eski ama değerli google dorks, **orada bulunmaması gereken exposed bilgileri** bulmak için her zaman faydalıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in manuel olarak çalıştıramayacağınız **binlerce** olası query içermesidir. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini **çalıştırmak için** [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir tool** kullanabilirsiniz.

_Database'in tamamını normal Google browser'ı kullanarak çalıştırmayı bekleyen tool'ların, Google sizi çok kısa süre içinde engelleyeceği için hiçbir zaman sonlanmayacağını unutmayın._

### **Vulnerabilities arama**

**Geçerli leak edilmiş** credential'lar veya API token'ları bulursanız bu, çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**'a sahip olduğunu fark ederseniz, bunu **analyse** ederek üzerinde **vulnerabilities** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **tool**'lar vardır:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca aşağıdakiler gibi **public repository'leri scan etmenize** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'lar tarafından bulunan **vulnerabilities'ın çoğu** **web application**'ların içinde yer alır. Bu nedenle bu noktada bir **web application testing methodology**'sinden bahsetmek istiyorum; bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özel olarak değinmek istiyorum. Bu tool'ların çok hassas vulnerabilities bulmasını beklememeniz gerekse de, **bazı başlangıç web bilgilerine sahip olmak için workflow'lara dahil edilmeleri** faydalı olabilir.

## Özet

> Tebrikler! Bu noktada **tüm basic enumeration** işlemlerini zaten gerçekleştirdiniz. Evet, bu basic bir işlemdir; çünkü çok daha fazla enumeration yapılabilir (daha fazla trick'i ileride göreceğiz).

Şimdiye kadar:

1. Scope içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset'leri** buldunuz (scope içindeyse bazı vuln scan'leri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lerin tüm **subdomain**'lerini buldunuz (herhangi bir subdomain takeover var mı?)
5. Scope içindeki tüm **IP'leri** (CDN'lerden gelen ve **gelmeyen**) buldunuz.
6. Tüm **web server**'ları buldunuz ve bunların **ekran görüntüsünü** aldınız (daha ayrıntılı incelenmeye değer garip bir şey var mı?)
7. Şirkete ait tüm **potansiyel public cloud asset**'lerini buldunuz.
8. Size çok kolay şekilde **büyük bir kazanım** sağlayabilecek **e-postalar**, **credential leak'leri** ve **secret leak'leri** buldunuz.
9. Bulduğunuz tüm web'lerde **Pentesting** gerçekleştirdiniz

## **Full Recon Automatic Tools**

Dışarıda, önerilen işlemlerin bir kısmını belirli bir scope'a karşı gerçekleştiren çeşitli tool'lar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

## **Referanslar**

- [**@Jhaddix**](https://twitter.com/Jhaddix)'in [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI) gibi tüm ücretsiz kursları
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
