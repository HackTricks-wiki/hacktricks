# Harici Recon Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlıkların keşfi

> Size bir şirkete ait her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte neler sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın almalarını bulun; bu, kapsam dahilindeki şirketleri bize verecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, alan adları...) aramak için reverse whois sorgularını kullanın (bu işlem recursive olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org`and `ssl`filters gibi diğer teknikleri kullanın (`ssl` hilesi recursive olarak yapılabilir).

### **Satın almalar**

Öncelikle **ana şirkete ait diğer şirketleri** bilmemiz gerekir.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel kurumsal kayıtları (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam dahilindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımızı öğrenelim.

### **ASN'ler**

Bir otonom sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **otonom sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici ağlara erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen **IP adresi bloklarından** oluşur; ancak birden fazla operatörden oluşabilir.

Şirketin **IP aralıklarını** bulmak için herhangi bir **ASN atanmış** olup olmadığını araştırmak ilginçtir. **Kapsam** dahilindeki tüm **hostlara** karşı bir **vulnerability test** gerçekleştirmek ve bu IP'lerin içinde **domainler** aramak faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) adreslerinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak daha fazla veri toplamak için şu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa).** Her durumda, muhtemelen tüm **faydalı bilgiler** (IP aralıkları ve Whois) zaten ilk bağlantıda yer almaktadır.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'nun** enumeration işlemi, tarama sonunda ASN'leri otomatik olarak toplar ve özetler.
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
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir veya açık port'ları **bulmak için** Shodan, Censys ya da ZoomEye **gibi servisleri kullanabilirsiniz**; **bulduklarınıza bağlı olarak**, çalışan çeşitli olası servislerin pentest'ini nasıl yapacağınızı görmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** default username **ve** password **listeleri hazırlayabileceğinizi ve** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **ile servislerde** bruteforce **deneyebileceğinizi belirtmekte fayda var**.

## Domain'ler

> Scope içindeki tüm şirketleri ve asset'lerini biliyoruz; şimdi scope içindeki domain'leri bulma zamanı.

_Aşağıda açıklanan tekniklerle subdomain'leri de bulabileceğinizi ve bu bilgilerin küçümsenmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana domain'ini** veya **domain'lerini** aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domain'lerin tüm IP aralıklarını bulduğunuza göre, **scope içinde daha fazla domain bulmak için** bu **IP'ler üzerinde reverse DNS lookup** gerçekleştirmeyi deneyebilirsiniz. Mağdurun DNS sunucularından birini veya iyi bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrim içi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar reverse lookup ve enrichment işlemlerini otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz. Ancak daha da ilginç olan, **bu alanlardan herhangi birini kullanarak reverse whois lookups** gerçekleştirdiğinizde **şirketle ilişkili daha fazla asset** bulabilmenizdir (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
Şu çevrim içi araçları kullanabilirsiniz:

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

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API anahtarı gerektirir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois discovery işlemleri gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada aynı **tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın** da **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birden fazla sayfada aynı **Google Analytics ID**'sini veya aynı **Adsense ID**'sini görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanıza olanak tanıyan bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/tracker'lara göre ilişkili siteleri bulur)
- [**StackScan**](https://www.stackscan.com) - **Ücretsiz katman** (Web ve API). Yalnızca tracker ID'leri değil, sunulan herhangi bir asset üzerinden pivot yapar: bir script path'i, self-hosted bir bundle adı veya bir asset'in yüklendiği host; bunun sonucunda bu asset'i taşıyan tüm siteleri döndürür

API, tek bir domain için stack'i döndürür; bu da aday bir asset'in aynı estate'e ait olduğunu doğrulamak için kullanışlıdır:
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
Her algılanan teknolojiyi kategorisiyle birlikte döndürür. Asset pivoting şu anda yalnızca web üzerinde çalışır; API, domain başına lookup işlemini kapsar.

### **Favicon**

Aynı favicon icon hash değerini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool'u tam olarak bunu yapar. Nasıl kullanılacağı aşağıda açıklanmıştır:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Aynı favicon hash değerini paylaşan domainleri keşfetmek için kullanılan Favihash sonuçları](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash değerine sahip domainleri keşfetmemizi sağlar.

![Aynı favicon hash değerine sahip domainleri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı technology'nin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA üzerinde pivot olarak kullanın.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Bir web sitesinin **favicon hash** değerini şu şekilde **hesaplayabilirsiniz** (**base64-encoded** favicon bytes üzerinde MMH3):
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
Ayrıca [**httpx**](https://github.com/projectdiscovery/httpx) ile ölçekli olarak favicon hash'leri alabilir (`httpx -l targets.txt -favicon`) ve ardından Shodan/Censys üzerinde pivot yapabilirsiniz.

favicon fingerprint'lerini ipucu olarak değerlendirin ve çevredeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt olarak değil, gösterge olarak değerlendirin**: MMH3 compact'tır; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı spoofing mümkündür.
- **`/favicon.ico` dışındaki yolları da tarayın**: framework/build paths, manifest dosyaları, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL'leri ve HTML `<link rel="icon">` etiketlerini inceleyin.
- **Static assets, WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: ikona doğrudan istek gönderin ve `ETag`, `Last-Modified`, redirects ve cache headers bilgilerini inceleyin.
- **Eşleşmeleri çevredeki sinyallerle doğrulayın**: title, HTML/body hash, headers, TLS certificate subjects/SANs, product components ve exposed ports bilgilerini karşılaştırın.
- **HTML/body hash'e göre cluster oluşturun**: tutarlı bir template fingerprint'i güçlendirir; farklı template'ler generic veya shared bir ikona işaret eder.
- **Farklı signature'lar, port'lar ve product'lar arasında görünen bir hash'i potansiyel honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz target'larda gerçek bir page ile var olmayan bir path'i karşılaştırın**: `/_favicon_probe_<8-hex>` gibi; eşleşen hosting veya parking response'ları paylaşılan ikonu açıklayabilir.
- **Triage işlemini favicon hash'lerini product'lara ve CPE'lere eşleyen Nuclei detection rules veya public datasets üzerinden başlatın.**
- **IP-centric coverage gap'i unutmayın**: CDN-fronted, SNI-routed, anycast ve domain-only surface'ler Shodan benzeri dataset'lerde bulunmayabilir.

### **Copyright / Uniq string**

Web page'leri içinde **aynı organisation'daki farklı web'ler arasında paylaşılabilecek string'leri** arayın. **Copyright string** buna iyi bir örnek olabilir. Ardından bu string'i **google** üzerinde, diğer **browsers** içinde veya hatta **shodan** üzerinde arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şuna benzer bir cron job kullanılması yaygındır:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm sertifikaları aynı anda yenilemek. Sertifika zaman damgalarını veya certificate-transparency log konumlarını ilişkilendirmek, ilişkili domainleri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**aynı dmarc bilgilerini paylaşan domainleri ve subdomainleri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Diğer kullanışlı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Terk edilmiş bir A record, bir cloud provider bir IP'yi yeniden atadığında erişilebilir hâle gelebilir. Referans verilen araştırma, bir instance oluşturan ve adresini passive DNS verileriyle ilişkilendiren fırsatçı bir workflow'u gösterir; takeover senaryolarını yalnızca yetkilendirilmiş kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yollar**

Yeni bir domain bulduğunuzda, geçerli discovery pivotlarını tekrarlayın: her sonuç, orijinal seed'den görünmeyen ek certificate adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve organization identifier'larını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan organization'ın adını zaten biliyorsunuz. Bu veriyi kullanarak shodan üzerinde şu şekilde arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları, TLS certificate içindeki yeni ve beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişip **Organisation name**'i elde edebilir ve ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS certificates**'ları içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana bir domain ile **ilişkili domainleri** ve bunların **subdomainlerini** arayan bir araçtır; oldukça etkileyicidir.

**Passive DNS / Historical DNS**

Passive DNS verileri, hâlâ resolve olan veya takeover edilebilen **eski ve unutulmuş recordları** bulmak için harikadır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Vulnerabilities arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir domain kullanıyordur**, ancak **domainin sahipliğini kaybetmiştir**. Yeterince ucuzsa domaini register edin ve şirkete bildirin.

Eğer assets discovery sırasında zaten bulduğunuz adreslerden **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **port scan** gerçekleştirmelisiniz: [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside), **nmap/masscan/shodan**. Hangi servislerin çalıştığına bağlı olarak **bu kitapta onlara "attack" uygulamak için bazı yöntemler** bulabilirsiniz.\
_Domainin bazen client tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle kapsam içinde olmadığını unutmayın; dikkatli olun._

## Subdomains

> Kapsam içindeki tüm şirketleri, her şirketin tüm assetlerini ve şirketlerle ilişkili tüm domainleri biliyoruz.

Bulunan her domainin mümkün olan tüm subdomainlerini bulmanın zamanı geldi.

> [!TIP]
> Domainleri bulmak için kullanılan bazı araç ve tekniklerin subdomainleri bulmaya da yardımcı olabileceğini unutmayın

### **DNS**

**DNS** recordlarından **subdomainleri** elde etmeyi deneyelim. Ayrıca **Zone Transfer**'ı da denemeliyiz (Vulnerable ise bunu raporlamalısınız).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu external sources içinde arama yapmaktır. En çok kullanılan **tools** aşağıdakilerdir (daha iyi sonuçlar için API keys yapılandırın):

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
Doğrudan subdomain bulma konusunda uzmanlaşmamış olsalar bile subdomain bulmak için kullanılabilecek **başka ilginç araçlar/API'ler** de vardır. Örneğin:

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
- [**gau**](https://github.com/lc/gau)**:** belirtilen herhangi bir domain için AlienVault'ın Open Threat Exchange, Wayback Machine ve Common Crawl kaynaklarındaki bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): JS dosyalarını aramak için web'i tarar ve buradan subdomain'leri çıkarırlar.
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
- [**securitytrails.com**](https://securitytrails.com/) subdomain'leri ve IP geçmişini aramak için ücretsiz bir API'ye sahiptir
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz** olarak sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak veya bu projenin kullandığı scope'a [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) erişerek de ulaşabilirsiniz.

Bu araçların birçoğunun **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmayı deneyelim.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larından oluşan bir liste oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu da kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır, ancak false positive'lere yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış `massdns` etrafında bir wrapper'dır; aktif bruteforce kullanarak geçerli alt alan adlarını enumerate etmenize, ayrıca wildcard işleme ve kolay input-output desteğiyle alt alan adlarını resolve etmenize olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), domain adlarını eşzamansız olarak brute force etmek için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynakları kullanarak ve brute-force uygulayarak subdomain'leri bulduktan sonra, daha da fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla çeşitli araçlar kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain'ler için permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'lere göre permutation'lar oluşturur.
- goaltdns permutation'ları için **wordlist**'i [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur. Permütasyon dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutation'ları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
- altdns permutation'larına ait **wordlist**'i [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) edinebilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Subdomain'lerin permutations, mutations ve alteration işlemlerini gerçekleştiren başka bir araçtır. Bu araç sonucu brute force ile bulur (DNS wildcard desteği yoktur).
- dmut permutations wordlist'ini [**burada**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) bulabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temel alarak, daha fazla subdomain keşfetmeyi denemek için belirtilen pattern'lere göre **yeni potansiyel subdomain adları üretir**.

#### Akıllı permutation üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'leri öğrenir ve çözümlenecek aday adlar üretir.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ancak etkili bir DNS yanıtı güdümlü algoritmayla birleştirilmiş bir subdomain brute-force fuzzer'dır. Tailored bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir input veri kümesini kullanarak daha fazla karşılık gelen domain adını doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, **OSINT kaynaklarında** bir IP üzerindeki domain'leri arayarak veya **bu IP üzerindeki VHost domain adlarını brute force ederek**, **aynı IP'de web siteleri bulunan diğer subdomain'leri bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerde bazı VHost'ları bulabilirsiniz**.

**Brute Force**

Bir web sunucusunda bazı subdomain'lerin gizlenmiş olabileceğinden şüpheleniyorsanız brute force yapmayı deneyebilirsiniz:

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

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı abuse edebilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomain** ararken herhangi bir **bucket** türüne **pointing** yapıp yapmadığını kontrol edin ve böyle bir durum varsa [**permissions'ları kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada scope içindeki tüm domain'leri biliyor olacağınız için olası bucket isimlerini [**brute force ile bulun ve permissions'ları kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

**Certificate Transparency** Logs'u izleyerek bir domain için **new subdomains** oluşturulup oluşturulmadığını, [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)'in yaptığı gibi **monitor** edebilirsiniz.

### **Zafiyet arama**

Olası [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**subdomain** herhangi bir **S3 bucket**'a pointing yapıyorsa [**permissions'ları kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset discovery sırasında bulduklarınızdan **farklı bir IP'ye sahip herhangi bir subdomain** bulursanız, **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz; bunu **nmap/masscan/shodan** ile yapabilirsiniz. Çalışan servislere bağlı olarak **bu kitapta bunlara "saldırmak" için bazı teknikler** bulabilirsiniz.\
_Bazen subdomain'in client tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle scope içinde olmadığını unutmayın; dikkatli olun._

## IPs

İlk adımlarda bazı **IP range'leri, domain'ler ve subdomain'ler** bulmuş olabilirsiniz.\
Şimdi bu range'lerdeki tüm IP'leri ve **domain/subdomain'ler için (DNS queries)** tüm IP'leri **toplama** zamanı.

Aşağıdaki **free apis** servislerini kullanarak **domain'ler ve subdomain'ler tarafından kullanılan önceki IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine pointing yapan domain'leri de kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'lerde port scan gerçekleştirin** (çünkü büyük olasılıkla orada ilginç bir şey bulamayacaksınız). Tespit edilen çalışan servislerde **zafiyetler bulabilirsiniz**.

**Host'ların nasıl taranacağı hakkında bir** [**guide**](../pentesting-network/index.html) **bulun.**

## Web server hunting

> Tüm şirketleri ve asset'lerini bulduk ve scope içindeki IP range'lerini, domain'leri ve subdomain'leri biliyoruz. Şimdi web server'ları arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domain'ler üzerinde bazı **recon** işlemleri gerçekleştirdiniz; dolayısıyla **olası tüm web server'ları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi scope içindeki web server'ları aramak için bazı **hızlı teknikleri** göreceğiz.

Lütfen bunun **web app discovery** odaklı olacağını unutmayın; bu nedenle scope tarafından **izin veriliyorsa** vulnerability ve **port scanning** de gerçekleştirmelisiniz.

[**masscan** kullanarak web server'larla ilişkili **open port'ları** keşfetmeye yönelik **hızlı bir method** [burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web server'ları aramak için bir diğer kullanışlı araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Sadece bir domain listesi sağlarsınız; araç port 80'e (http) ve 443'e (https) bağlanmayı dener. Ayrıca başka portları denemesini de belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsamda bulunan **tüm web sunucularını** (şirketin **IP'leri** ile tüm **domain** ve **subdomain'leri**) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Öyleyse bunu basitleştirelim ve hepsinin ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya** **bakarak**, **vulnerable** olmaya daha **yatkın** **tuhaf** endpoint'ler bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca tüm **ekran görüntülerini** [**eyeballer**](https://github.com/BishopFox/eyeballer) üzerinden çalıştırarak hangilerinin **vulnerabilities** içermesinin **muhtemel** olduğunu ve hangilerinin olmadığını belirlemesini sağlayabilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek cloud asset'lerini bulmak için **şirketi tanımlayan anahtar kelimelerden oluşan bir listeyle başlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca **bucket'larda kullanılan yaygın kelimelerin** wordlist'lerine ihtiyacınız olacaktır:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken AWS'de yalnızca bucket'lara bakmamanız gerektiğini unutmayın.

### **Vulnerabilities arama**

**Açık bucket'lar veya expose edilmiş cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, size neler sunduklarını ve bunları abuse edip edemeyeceğinizi görmeye çalışmalısınız.

## E-postalar

Kapsam içindeki **domain** ve **subdomain'ler** ile temel olarak **e-posta aramaya başlamak** için **ihtiyacınız olan her şeye** sahipsiniz. Bunlar bir şirketin e-postalarını bulmak için benim için en iyi çalışan **API'ler** ve **araçlardır**:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (free version)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (free version)
- [**https://minelead.io/**](https://minelead.io/) API'si (free version)

### **Vulnerabilities arama**

E-postalar daha sonra **web login'lerini ve auth servislerini** (SSH gibi) **brute-force** etmek için işinize yarayacaktır. Ayrıca **phishing** için de gereklidir. Bununla birlikte bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** sağlayarak phishing kampanyası için faydalı olur.

## Credential Leaks

**Domain**, **subdomain** ve **e-postalar** ile bu e-postalara ait geçmişte **leak edilmiş credential'ları** aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Vulnerabilities arama**

**Geçerli leak edilmiş** credential'lar bulursanız bu çok kolay bir kazanımdır.

## Secrets Leaks

Credential leaks, **hassas bilgilerin leak edildiği ve satıldığı** şirket hack'leriyle ilişkilidir. Ancak şirketler, bilgileri bu database'lerde bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credential'lar ve API'ler, **şirketin** veya o github şirketinde çalışan **user'ların** **public repository'lerinde** leak edilmiş olabilir.\
[**Leakos**](https://github.com/carlospolop/Leakos) **tool**'unu kullanarak bir **organization**'ın ve **developer'larının** tüm **public repo'larını** **download** edebilir ve bunlar üzerinde [**gitleaks**](https://github.com/zricethezav/gitleaks)'ı otomatik olarak çalıştırabilirsiniz.

**Leakos**, kendisine **URL'lerle sağlanan** tüm **text** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web sayfaları da secret'lar içerir**.

#### Github Dorks

Organization içinde arama yapmak için potansiyel **GitHub dorks** hakkında [GitHub dorks and leaks page](github-leaked-secrets.md) sayfasına bakın.

### Pastes Leaks

Bazen attacker'lar veya yalnızca çalışanlar **şirket içeriğini bir paste sitesinde publish eder**. Bu içerik **hassas bilgi** içerebilir veya içermeyebilir; ancak aramak oldukça ilginçtir.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) tool'unu kullanabilirsiniz.

### Google Dorks

Eski ama değerli Google dork'ları, **orada bulunmaması gereken expose edilmiş bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in manuel olarak çalıştıramayacağınız **binlerce** olası query içermesidir. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir tool** kullanabilirsiniz.

_Regular Google browser'ını kullanarak database'in tamamını çalıştırmayı bekleyen tool'ların hiçbir zaman bitmeyeceğini unutmayın; çünkü Google sizi çok kısa sürede engelleyecektir._

### **Vulnerabilities arama**

**Geçerli leak edilmiş** credential'lar veya API token'ları bulursanız bu çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**'a sahip olduğunu bulursanız bunu **analiz edebilir** ve üzerinde **vulnerabilities** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **tool'lar** vardır; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca aşağıdakiler gibi **public repository'leri scan etmenize** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'lar tarafından bulunan **vulnerabilities'ın çoğu** **web application'ların** içinde yer alır. Bu nedenle bu noktada bir **web application testing methodology** hakkında konuşmak istiyorum; bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünden özellikle bahsetmek istiyorum. Bunların çok hassas vulnerabilities bulmasını beklememeniz gerekse de, **bazı başlangıç web bilgilerine sahip olmak için workflow'lara dahil edilmeleri** faydalıdır.

## Recapitulation

> Tebrikler! Bu noktada **tüm temel enumeration'ı** zaten gerçekleştirdiniz. Evet, bu temel seviyededir; çünkü çok daha fazla enumeration yapılabilir (daha fazla trick'i ileride göreceğiz).

Şunları zaten yaptınız:

1. Kapsam içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset'leri** buldunuz (kapsamdaysa bazı vuln scan'leri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain'leri** buldunuz
4. Domain'lerin tüm **subdomain'lerini** buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP'leri** (CDN'lerden gelen ve **gelmeyen**) buldunuz.
6. Tüm **web server'ları** buldunuz ve ekran görüntülerini aldınız (daha derin bir incelemeye değer tuhaf bir şey var mı?)
7. Şirkete ait tüm **potansiyel public cloud asset'lerini** buldunuz.
8. Size **çok kolay bir şekilde büyük bir kazanım** sağlayabilecek **e-postaları**, **credential leaks** ve **secret leaks**'i buldunuz.
9. Bulduğunuz tüm web'lerde **Pentesting** gerçekleştirdiniz

## **Full Recon Automatic Tools**

Verilen bir scope'a karşı önerilen eylemlerin bir kısmını gerçekleştiren çeşitli tool'lar vardır.

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
