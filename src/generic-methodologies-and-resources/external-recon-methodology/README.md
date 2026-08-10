# Harici Recon Metodolojisi

## Varlık keşifleri

> Bir şirkete ait her şeyin kapsam dahilinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirkete ait tüm şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için:

1. Ana şirketin satın almalarını bulun; bu, kapsam dahilindeki şirketleri bize verecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını bize verecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois aramalarını kullanın (bu işlem özyinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi diğer teknikleri kullanın (`ssl` yöntemi özyinelemeli olarak kullanılabilir).

### **Satın almalar**

Öncelikle, **ana şirkete ait diğer şirketlerin hangileri olduğunu** bilmemiz gerekir.\
Bir seçenek, [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Küresel şirket yapıları ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam dahilindeki tüm şirketleri biliyor olmalısınız. Şimdi varlıklarını nasıl bulacağımızı öğrenelim.

### **ASN'ler**

Bir autonomous system number (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **autonomous system**'e (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen **IP adresi** **bloklarından** oluşur; ancak birden fazla operatörden meydana gelebilir.

**IP aralıklarını** bulmak için **şirkete herhangi bir ASN atanıp atanmadığını** öğrenmek ilginçtir. **Kapsam** içindeki tüm **host'lara** karşı bir **vulnerability test** gerçekleştirmek ve bu IP'ler içinde **domain'ler aramak** faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak daha fazla veri toplamak için bu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa).** Her durumda, muhtemelen tüm **faydalı bilgiler** (IP aralıkları ve Whois) zaten ilk bağlantıda görünmektedir.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un** enumeration işlemi taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.
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
Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) (ücretsiz API sunar) kullanarak da bulabilirsiniz.\
Bir domainin IP ve ASN bilgilerini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Zafiyetleri arama**

Bu noktada **scope içindeki tüm asset'leri** biliyoruz; bu nedenle izin veriliyorsa tüm host'lar üzerinde bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir **veya** açık port'ları **bulmak için** Shodan, Censys ya da ZoomEye gibi servisleri **kullanabilirsiniz**; **bulduklarınıza bağlı olarak,** çalışan olası çeşitli servislerin pentest'ini nasıl yapacağınızı görmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** parola **listeleri hazırlayıp** servisleri [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile **bruteforce** etmeyi denemenin de faydalı olabileceğini belirtmek gerekir.

## Domain'ler

> Scope içindeki tüm şirketleri ve asset'lerini biliyoruz; şimdi scope içindeki domain'leri bulma zamanı.

_Aşağıda önerilen tekniklerle subdomain'leri de bulabileceğinizi ve bu bilgilerin küçümsenmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana domain'ini** veya **ana domain'lerini** aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domain'lerin tüm IP aralıklarını bulduğunuza göre, **scope içinde daha fazla domain bulmak için** bu **IP'ler üzerinde reverse DNS lookup** gerçekleştirmeyi deneyebilirsiniz. Kurbanın bazı DNS sunucularını veya iyi bilinen DNS sunucularını (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için online bir tool da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi tool'lar reverse lookup'ları ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olan, **bu alanlardan herhangi biriyle reverse whois lookup'ları gerçekleştirerek** **şirketle ilişkili daha fazla varlık** bulabilmenizdir (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
Şu online tool'ları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Ücretsiz** (Web ve API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Web ücretsiz**, API ücretsiz değil.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretsiz değil
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretsiz değil (yalnızca **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretsiz değil
- [https://securitytrails.com/](https://securitytrails.com/) - Ücretsiz değil (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Ücretsiz değil (API)

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API anahtarı gerektirir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois keşifleri gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada aynı **tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın** da **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID'sini** veya aynı **Adsense ID'sini** görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve tool'lar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/tracker'lara göre ilişkili siteleri bulur)

### **Favicon**

Aynı favicon icon hash'ini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool'u tam olarak bunu yapar. Şu şekilde kullanabilirsiniz:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Basitçe ifade etmek gerekirse, favihash hedefimizle aynı favicon simge hash'ine sahip domain'leri keşfetmemizi sağlar.

Bilinen bir favicon hash'ini, aynı teknolojinin diğer exposed instance'larını bulmak için Shodan veya FOFA pivot'u olarak kullanın.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Bir web sitesinin **favicon hash değerini hesaplama** yöntemi şöyledir (**base64 ile kodlanmış** favicon baytları üzerinde MMH3):
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
Ölçekli olarak [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile favicon hash'leri de alabilir ve ardından Shodan/Censys üzerinde pivot yapabilirsiniz.

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevreleyen sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt olarak değil, gösterge olarak değerlendirin**: MMH3 kompakttır; çakışmalar, yeniden kullanılan icon'lar ve kasıtlı spoofing mümkündür.
- **`/favicon.ico` dışında da probe gerçekleştirin**: framework/build path'lerini, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL'lerini ve HTML `<link rel="icon">` tag'lerini inceleyin.
- **Static asset'lere WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: icon'a doğrudan request gönderin ve `ETag`, `Last-Modified`, redirect'ler ile cache header'larını inceleyin.
- **Eşleşmeleri çevreleyen sinyallerle doğrulayın**: title'ı, HTML/body hash'ini, header'ları, TLS certificate subject/SAN'larını, product component'lerini ve exposed port'ları karşılaştırın.
- **HTML/body hash'ine göre cluster oluşturun**: tutarlı bir template fingerprint'i güçlendirir; farklı template'ler generic veya paylaşılan bir icon olduğunu gösterir.
- **Farklı signature'lar, port'lar ve product'lar arasında görünen bir hash'i potansiyel honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz target'larda gerçek bir page ile mevcut olmayan bir path'i karşılaştırın**; örneğin `/_favicon_probe_<8-hex>`; eşleşen hosting veya parking response'ları paylaşılan icon'u açıklayabilir.
- **Favicon hash'lerini product'lara ve CPE'lere eşleyen Nuclei detection rule'larından veya public dataset'lerden triage sürecini başlatın.**
- **IP-centric coverage gap'i unutmayın**: CDN-fronted, SNI-routed, anycast ve yalnızca domain üzerinden erişilen surface'ler Shodan benzeri dataset'lerde bulunmayabilir.

### **Copyright / Uniq string**

Web sayfalarının içinde, **aynı kuruluşta farklı web siteleri arasında paylaşılabilecek string'leri** arayın. **Copyright string** buna iyi bir örnek olabilir. Ardından bu string'i **google**'da, diğer **browser**'larda veya hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şu tür bir cron job kullanılması yaygındır:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency log konumlarını ilişkilendirmek, ilişkili domain'leri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** log'larını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**Aynı dmarc bilgilerini paylaşan domain ve subdomain'leri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Diğer kullanışlı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud provider bir IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance provision ederek ve adresini passive DNS verileriyle ilişkilendirerek fırsatçı bir workflow ortaya koyar; takeover senaryolarını yalnızca yetkilendirilmiş kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yollar**

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten bildiğiniz için, Shodan'da şu veriyi kullanarak arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan host'ları, TLS sertifikasında yer alan yeni ve beklenmeyen domain'ler için kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişebilir, **Organisation name**'i alabilir ve ardından bu adı **Shodan** tarafından bilinen tüm web sayfalarının **TLS certificates**'ları içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), bir ana domain ile **related domain'leri** ve bunların **subdomain'lerini** arayan bir araçtır; oldukça etkileyici.

**Passive DNS / Historical DNS**

Passive DNS verileri, hâlâ çözümlenen veya takeover edilebilen **eski ve unutulmuş kayıtları** bulmak için harikadır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Zafiyet arama**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir domain kullanıyordur**, ancak **sahipliğini kaybetmiştir**. Yeterince ucuzsa domain'i kaydedin ve şirkete bildirin.

Daha önce assets discovery sırasında bulduklarınızdan **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) işlemleri gerçekleştirmelisiniz; **nmap/masscan/shodan** kullanabilirsiniz. Çalışan servislere bağlı olarak **bu kitapta bunlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Bazen domain'in client tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle kapsam içinde olmadığını unutmayın; dikkatli olun._

## Subdomain'ler

> Kapsam içindeki tüm şirketleri, her şirketin tüm asset'lerini ve şirketlerle ilişkili tüm domain'leri biliyoruz.

Bulduğumuz her domain'in olası tüm subdomain'lerini bulma zamanı.

> [!TIP]
> Domain bulmak için kullanılan bazı araç ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın

### **DNS**

**DNS** kayıtlarından **subdomain'leri** bulmaya çalışalım. Ayrıca **Zone Transfer** için de deneme yapmalıyız (zafiyetliyse raporlamalısınız).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu, dış kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):

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
**Alt alan adlarını bulma konusunda doğrudan uzmanlaşmamış olsalar bile**, alt alan adlarını bulmak için yararlı olabilecek **diğer ilgi çekici araçlar/API'ler** de vardır:

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
- [**gau**](https://github.com/lc/gau)**:** belirtilen bir domain için AlienVault'un Open Threat Exchange'inden, Wayback Machine'den ve Common Crawl'dan bilinen URL'leri getirir.
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

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz olarak** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak da erişebilir veya bu projenin kullandığı scope'a şu adresten erişebilirsiniz: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Bu araçların çoğunun bir **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larından oluşan bir liste oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu da kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır, ancak false positive'lere yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bu aracın yalnızca 1 resolver kullandığını düşünüyorum
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), `massdns` etrafında oluşturulmuş, go ile yazılmış bir sarmalayıcıdır; active bruteforce kullanarak geçerli alt alan adlarını enumerate etmenize ve wildcard işleme ile alt alan adlarını çözümlemenize, ayrıca kolay girdi-çıktı desteği sunmanıza olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute), alan adlarını eşzamansız olarak brute force yapmak için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynakları ve brute-force yöntemini kullanarak subdomain'leri bulduktan sonra, daha fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Alan adları ve subdomain'ler verildiğinde permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur.
- goaltdns permütasyonları için **wordlist**'i [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permutation'lar üretir. Bir permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permütasyonları oluşturmanın yanı sıra bunları çözümlemeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
- altdns permütasyonları için **wordlist**'i [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permutation, mutation ve alteration işlemlerini gerçekleştiren başka bir araç. Bu araç sonucu brute force yöntemiyle bulur (dns wild card desteği yoktur).
- dmut permutations wordlist'ini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, daha fazla alt alan adı keşfetmeyi denemek için belirtilen kalıplara göre **yeni olası alt alan adı isimleri oluşturur**.

#### Akıllı permutation oluşturma

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen alt alan adlarından regex benzeri kalıpları öğrenir ve çözümlenecek aday isimler oluşturur.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ancak etkili bir DNS response-guided algorithm ile birleştirilmiş bir subdomain brute-force fuzzer'dır. Tailored wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir input data kümesini kullanarak daha fazla karşılık gelen domain name'i doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını bir araya getirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, **OSINT kaynaklarında bir IP üzerindeki domain'leri arayarak** veya **o IP'deki VHost domain adlarını brute force uygulayarak**, **aynı IP'de web siteleri bulunan diğer subdomain'leri bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerde bazı VHost'ları bulabilirsiniz**.

**Brute Force**

Bir web server'da bazı subdomain'lerin gizlenmiş olabileceğinden şüpheleniyorsanız brute force uygulamayı deneyebilirsiniz:

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
> Bu teknikle dahili/gizli endpoint'lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** ararken bunlardan herhangi birinin bir **bucket** türüne **yönlenip yönlenmediğini** kontrol edin ve böyle bir durum varsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada scope içindeki tüm domain'leri biliyor olacağınız için [**olası bucket isimlerini brute force ile deneyin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

**Certificate Transparency** Logs'u izleyerek bir domain'in **yeni subdomain'lerinin** oluşturulup oluşturulmadığını [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)'in yaptığı gibi **izleyebilirsiniz**.

### **Zafiyet arama**

Olası [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**subdomain** herhangi bir **S3 bucket**'ına yönleniyorsa [**izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset discovery sırasında bulduklarınızdan **farklı bir IP'ye sahip herhangi bir subdomain** bulursanız, **temel bir zafiyet taraması** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Çalışan servislere bağlı olarak, **bu kitapta bunlara "saldırmak" için bazı trick'ler bulabilirsiniz**.\
_Bazen subdomain'in client tarafından kontrol edilmeyen bir IP üzerinde barındırıldığını ve bu nedenle scope içinde olmadığını unutmayın; dikkatli olun._

## IP'ler

İlk adımlarda bazı **IP range'leri, domain'ler ve subdomain'ler bulmuş olabilirsiniz**.\
Bu **range'lerdeki tüm IP'leri** ve **domain/subdomain'ler için DNS sorgularından elde edilen IP'leri** toplamanın zamanı geldi.

Aşağıdaki **free API'lerdeki** servisleri kullanarak **domain'ler ve subdomain'ler tarafından daha önce kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine yönlenen domain'leri de kontrol edebilirsiniz.

### **Zafiyet arama**

**CDN'lere ait olmayan tüm IP'leri port scan ile tarayın** (çünkü büyük olasılıkla bunlarda ilgi çekici bir şey bulamazsınız). Tespit edilen çalışan servislerde **zafiyetler bulabilirsiniz**.

Host'ları nasıl tarayacağınızı anlatan bir [**guide**](../pentesting-network/index.html) **bulun**.

## Web server hunting

> Tüm şirketleri ve asset'lerini bulduk; scope içindeki IP range'lerini, domain'leri ve subdomain'leri biliyoruz. Şimdi web server'ları arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domain'ler üzerinde bazı **recon** işlemleri gerçekleştirdiniz; dolayısıyla **olası tüm web server'ları zaten bulmuş olabilirsiniz**. Ancak bulmadıysanız, şimdi scope içindeki web server'ları aramak için bazı **hızlı trick'ler** göreceğiz.

Lütfen bunun **web app discovery** için **odaklandığını** unutmayın; bu nedenle scope tarafından **izin veriliyorsa**, **zafiyet** ve **port scanning** işlemlerini de gerçekleştirmelisiniz.

[**masscan** kullanılarak web server'larla ilişkili **açık port'ları** keşfetmeye yönelik **hızlı bir yöntem burada bulunabilir**](../pentesting-network/index.html#http-port-discovery).\
Web server'ları aramak için kullanılabilecek bir diğer kullanıcı dostu araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araç port 80'e (http) ve 443'e (https) bağlanmayı deneyecektir. Ayrıca, başka portları da denemesini belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsamda bulunan **tüm web sunucularını** (şirketin **IP'leri** ile tüm **domain** ve **subdomain'leri** arasından) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Öyleyse bunu basitleştirelim ve sadece hepsinin ekran görüntülerini alarak başlayalım. **Ana sayfaya** yalnızca **bakarak**, **savunmasız olma** ihtimali daha yüksek **garip** endpoint'ler bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Bunun yanı sıra, tüm **ekran görüntülerini** inceleyerek **hangilerinin güvenlik açığı barındırma ihtimalinin yüksek olduğunu** ve hangilerinin olmadığını söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilirsiniz.

## Genel Bulut Varlıkları

Bir şirkete ait olabilecek cloud varlıklarını bulmak için **şirketi tanımlayan anahtar kelimelerden oluşan bir listeyle başlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca **bucket'larda kullanılan yaygın kelimelerin** wordlist'lerine de ihtiyacınız olacaktır:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permutations** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken AWS'deki bucket'lardan daha fazlasını aramanız gerektiğini unutmayın.

### **Güvenlik açıklarını arama**

**Açık bucket'lar veya dışarıya açılmış cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, size neler sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## E-postalar

Kapsam dahilindeki **domain** ve **subdomain'lerle**, **e-posta aramaya başlamak** için temelde ihtiyacınız olan her şeye sahipsiniz. Bunlar, bir şirkete ait e-postaları bulmak için benim için en iyi sonuç veren **API'ler** ve **araçlardır**:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Güvenlik açıklarını arama**

E-postalar daha sonra web login'lerini ve auth servislerini (SSH gibi) **brute-force** etmek için işinize yarayacaktır. Ayrıca **phishing** için de gereklidirler. Bunun yanı sıra bu API'ler, e-postanın arkasındaki **kişi hakkında daha fazla bilgi** sağlayarak phishing campaign için faydalı olabilir.

## Credential Leaks

**Domain'ler,** **subdomain'ler** ve **e-postalarla**, geçmişte bu e-postalara ait olarak **leak edilmiş credential'ları** aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Güvenlik açıklarını arama**

**Geçerli leak edilmiş** credential'lar bulursanız bu, çok kolay bir kazanımdır.

## Secrets Leaks

Credential leaks, **hassas bilgilerin leak edilip satıldığı** şirket hack'leriyle ilişkilidir. Ancak şirketler, bilgileri bu database'lerde bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credential'lar ve API'ler, **şirketin** veya bu Github şirketinde çalışan **kullanıcıların** **public repository'lerinde** leak edilmiş olabilir.\
Tüm **public repo'ları** bir **organization** ve onun **developer'ları** için **download** etmek ve üzerlerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **tool**'unu kullanabilirsiniz.

**Leakos**, kendisine verilen **URL'lerin sağladığı tüm **text** üzerinde de **gitleaks** çalıştırmak için kullanılabilir; çünkü bazen **web sayfaları da secret'lar içerir**.

#### Github Dorks

Organization'da arama yapmak için kullanabileceğiniz olası **GitHub dork'ları** için [GitHub dorks and leaks page](github-leaked-secrets.md) sayfasına bakın.

### Pastes Leaks

Bazen saldırganlar veya sadece çalışanlar **şirket içeriğini bir paste sitesinde yayınlar**. Bu içerik **hassas bilgiler** barındırabilir veya barındırmayabilir; ancak aramak oldukça ilginçtir.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama etkili Google dork'ları, **orada bulunmaması gereken açığa çıkmış bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in manuel olarak çalıştıramayacağınız **binlerce** olası sorgu içermesidir. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Düzenli Google browser'ını kullanarak tüm database'i çalıştırmayı bekleyen araçların hiçbir zaman bitmeyeceğini unutmayın; çünkü Google sizi çok kısa süre içinde engelleyecektir._

### **Güvenlik açıklarını arama**

**Geçerli leak edilmiş** credential'lar veya API token'ları bulursanız bu, çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code** kullandığını fark ederseniz bunu **analiz edebilir** ve içindeki **güvenlik açıklarını** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca aşağıdakiler gibi **public repository'leri taramanıza** olanak tanıyan ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **güvenlik açıklarının** **çoğunluğu web application'ların** içinde yer alır. Bu nedenle bu noktada bir **web application testing methodology** hakkında konuşmak ve [**bu bilgiyi burada bulabileceğinizi**](../../network-services-pentesting/pentesting-web/index.html) belirtmek istiyorum.

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünden özellikle bahsetmek istiyorum; çok hassas güvenlik açıkları bulmalarını beklememeniz gerekse de, **workflow'lara uygulanarak başlangıç niteliğinde web bilgileri edinmek için kullanışlıdırlar.**

## Recapitulation

> Tebrikler! Bu noktada **tüm temel enumeration** işlemlerini zaten gerçekleştirdiniz. Bunun temel olmasının nedeni, çok daha fazla enumeration yapılabilmesidir (daha fazla trick'i ileride göreceğiz).

Artık şunları yaptınız:

1. Kapsam dahilindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset'leri** buldunuz (kapsam dahilindeyse bazı vuln scan işlemleri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain'leri** buldunuz
4. Domain'lerin tüm **subdomain'lerini** buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam dahilindeki tüm **IP'leri** (CDN'lerden gelen ve **gelmeyen**) buldunuz.
6. Tüm **web server'ları** buldunuz ve bunların **ekran görüntülerini** aldınız (daha derinlemesine incelenmeye değer garip bir şey var mı?)
7. Şirkete ait tüm **potential public cloud asset'lerini** buldunuz.
8. Size çok kolay bir şekilde **büyük bir kazanım** sağlayabilecek **e-postaları**, **credential leak'lerini** ve **secret leak'lerini** buldunuz.
9. Bulduğunuz tüm web'lerde **pentesting** yaptınız

## **Full Recon Automatic Tools**

Belirli bir scope'a karşı önerilen işlemlerin bir kısmını gerçekleştiren çeşitli araçlar bulunmaktadır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

## References

- [1] [Jason Haddix – Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicon'lar Hakkında: Browser Icon'larından Attack Surface Intelligence'a](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties, OSINT ve Daha Fazlası için favicon.ico'yu Weaponize Etmek](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency Üzerinde Time-Correlation Attack ile Domain'leri Keşfetmek](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Pahalı Bir Subdomain Takeover Campaign'ini Ortaya Çıkarmak (ve Taklit Etmek)](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Subdomain Enumeration için Benzersiz Bir Method](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflow Kullanarak Full Subdomain Brute Force Discovery, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
{{#include ../../banners/hacktricks-training.md}}
