# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset keşfi

> Yani bir şirkete ait her şeyin scope içinde olduğu söylendi ve bu şirketin gerçekte nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, **ana şirketin sahip olduğu tüm şirketleri** ve ardından bu şirketlerin tüm **asset**'lerini elde etmektir. Bunu yapmak için:<sup>[[1]](#references)</sup>

1. Ana şirketin satın almalarını bulun; bu, scope içindeki şirketleri verecektir.
2. Her şirketin ASN'sini (varsa) bulun; bu, her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlk şirketle ilişkili diğer kayıtları (kuruluş adları, domain'ler...) aramak için reverse whois lookup'larını kullanın (bu işlem recursive olarak yapılabilir).
4. Diğer asset'leri aramak için shodan `org` ve `ssl` filtreleri gibi teknikleri kullanın (`ssl` yöntemi recursive olarak uygulanabilir).

### **Satın almalar**

Öncelikle, **ana şirketin sahip olduğu diğer şirketleri** bilmemiz gerekir.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) adresini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" seçeneğine **tıklamaktır**. Burada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** araması yapmaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket sicillerini (ör. Birleşik Krallık'taki **Companies House**) kontrol edin.\
Global şirket hiyerarşileri ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada scope içindeki tüm şirketleri biliyor olmalısınız. Şimdi asset'lerini nasıl bulacağımıza bakalım.

### **ASN'ler**

Bir autonomous system number (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **autonomous system**'e (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, harici network'lere erişim için açıkça tanımlanmış bir politikaya sahip olan ve tek bir kuruluş tarafından yönetilen **IP adresi bloklarından** oluşur; ancak birden fazla operatörden meydana gelebilir.

Şirketin **IP aralıklarını** bulmak için herhangi bir **ASN atanmış olup olmadığını** öğrenmek ilginçtir. **Scope** içindeki tüm **host'lara** karşı bir **vulnerability test** gerçekleştirmek ve bu IP'lerin içindeki **domain'leri** aramak faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak daha fazla veri toplamak için şu bağlantılar faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** Her durumda, muhtemelen tüm **faydalı bilgiler** (**IP aralıkları** ve **Whois**) zaten ilk bağlantıda yer almaktadır.
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
Bir kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) kullanarak da bulabilirsiniz (ücretsiz API sunar).\
Bir domainin IP ve ASN bilgilerini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Güvenlik açıklarını arama**

Bu noktada **scope içindeki tüm asset'leri** biliyoruz; bu nedenle izin veriliyorsa tüm hostlar üzerinde bir **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir veya açık portları **bulmak için** Shodan, Censys ya da ZoomEye **gibi servisleri kullanabilirsiniz**; **bulduklarınıza bağlı olarak**, çalışan çeşitli olası servislerin nasıl pentest edileceğini öğrenmek için bu kitaba göz atmalısınız.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** parola **listeleri hazırlayıp** servisleri [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile **bruteforce** etmeyi denemenin de faydalı olabileceğini belirtmek gerekir.

## Domainler

> Scope içindeki tüm şirketleri ve asset'lerini biliyoruz; şimdi scope içindeki domainleri bulma zamanı.

_Lütfen aşağıda önerilen tekniklerle subdomainleri de bulabileceğinizi ve bu bilgilerin küçümsenmemesi gerektiğini unutmayın._

Öncelikle her şirketin **ana domain**(ler)ini aramalısınız. Örneğin _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Domainlerin tüm IP aralıklarını bulduğunuza göre, **scope içinde daha fazla domain bulmak için** bu **IP'ler üzerinde reverse DNS lookup** gerçekleştirmeyi deneyebilirsiniz. Mağdurun bir DNS sunucusunu veya bilinen bir DNS sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için yöneticinin PTR'yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrim içi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar reverse lookup'ları ve zenginleştirmeyi otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organizasyon adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginç olan, bu alanlardan herhangi biriyle **reverse whois lookup'ları** gerçekleştirerek **şirketle ilişkili daha fazla asset** bulabilmenizdir (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
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

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API anahtarı gerekir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile otomatik reverse whois keşfi gerçekleştirebilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada aynı **tracker**'ın **aynı ID**'sini bulursanız, **her iki sayfanın** da **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birden fazla sayfada aynı **Google Analytics ID**'sini veya aynı **Adsense ID**'sini görürseniz.

Bu tracker'lar ve daha fazlasıyla arama yapmanıza olanak tanıyan bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/tracker'lar üzerinden ilişkili siteleri bulur)

### **Favicon**

Aynı favicon simgesi hash'ini arayarak hedefimizle ilişkili domain ve subdomain'leri bulabileceğimizi biliyor muydunuz? [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından geliştirilen [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. İşte nasıl kullanacağınız:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![Aynı favicon hash değerini paylaşan domain'leri keşfetmek için kullanılan Favihash sonuçları](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash değerine sahip domain'leri keşfetmemizi sağlar.

![Aynı favicon hash değerine sahip domain'leri keşfetmek için kullanılan favihash çıktısı](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Aynı technology'nin internete açık diğer örneklerini bulmak için bilinen bir favicon hash değerini Shodan veya FOFA pivot'u olarak kullanın.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Bir web sitesinin **favicon hash değerini hesaplamanın** yolu şöyledir (**base64 ile kodlanmış** favicon baytları üzerinde MMH3):
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
Ayrıca [**httpx**](https://github.com/projectdiscovery/httpx) ile favicon hash'lerini büyük ölçekte alabilir (`httpx -l targets.txt -favicon`) ve ardından Shodan/Censys üzerinde pivot edebilirsiniz.

Favicon fingerprint'lerini ipucu olarak değerlendirin ve çevredeki sinyallerle doğrulayın.<sup>[[3]](#references)[[4]](#references)</sup>

- **Hash'i kanıt olarak değil, gösterge olarak değerlendirin**: MMH3 compact'tır; çakışmalar, yeniden kullanılan ikonlar ve kasıtlı spoofing mümkündür.
- **`/favicon.ico` dışında da probe gerçekleştirin**: framework/build path'lerini, manifest dosyalarını, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL'lerini ve HTML `<link rel="icon">` tag'lerini inceleyin.
- **Static asset'lere WAF/SSO/IdP kontrollerinin arkasından hâlâ erişilebilir olabilir**: İkonu doğrudan request edin ve `ETag`, `Last-Modified`, redirect'leri ve cache header'larını inceleyin.
- **Eşleşmeleri çevredeki sinyallerle doğrulayın**: title, HTML/body hash'i, header'lar, TLS certificate subject/SAN'leri, product component'leri ve exposed port'ları karşılaştırın.
- **HTML/body hash'ine göre cluster oluşturun**: Tutarlı bir template fingerprint'i güçlendirir; karışık template'ler generic veya paylaşılan bir ikonu gösterir.
- **Bir hash'in ilgisiz signature'lar, port'lar ve product'lar arasında göründüğü durumları potansiyel bir honeypot veya placeholder olarak değerlendirin.**
- **Belirsiz target'larda gerçek bir page'i `/_favicon_probe_<8-hex>` gibi mevcut olmayan bir path ile karşılaştırın**; eşleşen hosting veya parking response'ları paylaşılan ikonu açıklayabilir.
- **Favicon hash'lerini product'lara ve CPE'lere eşleyen Nuclei detection rule'larından veya public dataset'lerden triage sürecini başlatın.**
- **IP-centric coverage gap'i unutmayın**: CDN-fronted, SNI-routed, anycast ve domain-only surface'ler Shodan benzeri dataset'lerde eksik olabilir.

### **Copyright / Uniq string**

Web page'lerin içinde **aynı organisation'daki farklı web siteleri arasında paylaşılabilecek string'leri** arayın. **Copyright string** buna iyi bir örnek olabilir. Ardından bu string'i **google** üzerinde, diğer **browser**'larda veya hatta **shodan** üzerinde arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Bir cron job'ının aşağıdaki gibi olması yaygındır
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm sertifikaları aynı anda yenilemek için. Sertifika zaman damgalarını veya certificate-transparency log konumlarını ilişkilendirmek, ilişkili domain'leri ortaya çıkarabilir.<sup>[[6]](#references)</sup>

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

**aynı dmarc bilgilerini paylaşan domain ve subdomain'leri** bulmak için [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) gibi bir web sitesini veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir aracı kullanabilirsiniz.\
Diğer kullanışlı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)'dır.

### **Passive Takeover**

Terk edilmiş bir A kaydı, bir cloud sağlayıcısı bir IP'yi yeniden atadığında erişilebilir hâle gelebilir. Atıfta bulunulan araştırma, bir instance oluşturan ve adresini passive DNS verileriyle ilişkilendiren fırsatçı bir iş akışını gösterir; takeover senaryolarını yalnızca yetkilendirilmiş kapsam içinde test edin.<sup>[[7]](#references)</sup>

### **Diğer yöntemler**

Yeni bir domain bulduğunuzda, geçerli discovery pivot'larını tekrarlayın: her sonuç, orijinal seed'den görünmeyen ek sertifika adlarını, passive-DNS ilişkilerini, favicon eşleşmelerini ve kuruluş tanımlayıcılarını ortaya çıkarabilir.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP alanının sahibi olan kuruluşun adını zaten bildiğiniz için, Shodan'da bu veriyi kullanarak şu şekilde arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan host'larda TLS sertifikasında yer alan yeni ve beklenmeyen domain'leri kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişip **Organisation name** bilgisini elde edebilir ve ardından bu adı **shodan** tarafından bilinen tüm web sayfalarının **TLS certificates**'ları içinde şu filtreyle arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ana domain ile **ilişkili domain'leri** ve bunların **subdomain'lerini** arayan bir araçtır; oldukça etkileyici.

**Passive DNS / Historical DNS**

Passive DNS verileri, hâlâ çözümlenen veya takeover yapılabilen **eski ve unutulmuş kayıtları** bulmak için harikadır. Şunlara göz atın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir domain kullanıyordur**, ancak **sahipliğini kaybetmiştir**. Yeterince ucuzsa domain'i kaydedin ve şirkete bildirin.

Daha önce asset discovery sırasında bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **port scan** gerçekleştirmelisiniz ([**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)). Bunun yanı sıra **nmap/masscan/shodan** kullanın. Çalışan servislere bağlı olarak **bu kitapta bunlara "saldırmak" için bazı yöntemler** bulabilirsiniz.\
_Domain'in bazen client tarafından kontrol edilmeyen bir IP içinde barındırıldığını ve bu nedenle kapsamda olmadığını unutmayın; dikkatli olun._

## Subdomains

> Kapsam içindeki tüm şirketleri, her şirketin tüm asset'lerini ve şirketlerle ilişkili tüm domain'leri biliyoruz.

Bulunan her domain'in olası tüm subdomain'lerini bulmanın zamanı geldi.

> [!TIP]
> Domain bulmak için kullanılan bazı araç ve tekniklerin subdomain bulmaya da yardımcı olabileceğini unutmayın

### **DNS**

**DNS** kayıtlarından **subdomain'leri** elde etmeye çalışalım. Ayrıca **Zone Transfer** için de deneme yapmalıyız (vulnerable ise rapor etmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu external sources içinde arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API keys yapılandırın):

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
**subdomain bulma konusunda doğrudan uzmanlaşmamış olsalar bile** subdomain bulmak için yararlı olabilecek **diğer ilginç araçlar/API'ler** şunlardır:

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
- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault'un Open Threat Exchange, Wayback Machine ve Common Crawl kaynaklarındaki bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): JS dosyalarını aramak için web'i tarar ve buradan alt alan adlarını çıkarırlar.
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
- [**securitytrails.com**](https://securitytrails.com/) subdomain'leri ve IP geçmişini aramak için ücretsiz bir API'ye sahiptir
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomain'leri ücretsiz olarak** sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak erişebilir veya bu projenin kullandığı scope'a [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) üzerinden erişebilirsiniz.

Bu araçların çoğunun bir **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain adlarını kullanarak DNS sunucularına brute-force uygulayıp yeni **subdomain'ler** bulmayı deneyelim.

Bu işlem için bazı **yaygın subdomain wordlist'lerine** ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'larının IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının bir listesini oluşturmak için resolver'ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirebilir ve filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Alternatif olarak şunu da kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili DNS brute-force gerçekleştiren ilk araç buydu. Çok hızlıdır ancak false positive'lere yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bunun yalnızca 1 resolver kullandığını düşünüyorum.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), go ile yazılmış, `massdns` etrafında çalışan bir wrapper'dır; active bruteforce kullanarak geçerli subdomain'leri enumerate etmenize, ayrıca wildcard handling ve kolay input-output desteğiyle subdomain'leri resolve etmenize olanak tanır.
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

Open source'ları kullanarak ve brute-force yaparak subdomain'leri bulduktan sonra, daha fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaçla çeşitli araçlar kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Domain ve subdomain'leri girdi olarak alarak permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomain'leri kullanarak permutations oluşturur.
- goaltdns permutations **wordlist**'ini [**burada**](https://github.com/subfinder/goaltdns/blob/master/words.txt) bulabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Alan adları ve alt alan adları verildiğinde permütasyonlar oluşturur. Bir permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Subdomain permutation'ları üretmenin yanı sıra bunları resolve etmeyi de deneyebilir (ancak önceki yorum satırına alınmış araçları kullanmak daha iyidir).
- altdns permutation **wordlist**'ini [**burada**](https://github.com/infosec-au/altdns/blob/master/words.txt) bulabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Subdomain'lerin permutation, mutation ve alteration işlemlerini gerçekleştiren başka bir tool. Bu tool sonucu brute force ile arar (dns wild card desteği yoktur).
- dmut permutations wordlist'ini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) edinebilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain temelinde, belirtilen pattern'lere göre **yeni potansiyel subdomain adları üretir** ve daha fazla subdomain keşfetmeyi dener.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Keşfedilen subdomain'lerden regex benzeri pattern'leri öğrenir ve çözümlenebilecek aday adlar üretir.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ancak etkili, DNS yanıtları tarafından yönlendirilen bir algoritmayla birleştirilmiş bir subdomain brute-force fuzzer'ıdır. Özel olarak hazırlanmış bir wordlist veya geçmiş DNS/TLS kayıtları gibi sağlanan bir input data kümesini kullanarak, daha fazla karşılık gelen domain name'i doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow örnekleri, tekrarlanabilir subdomain enumeration için OSINT, DNS brute force ve permutation aşamalarını birleştirir.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP adresi bulduysanız, **OSINT kaynaklarında bir IP üzerindeki domain'leri arayarak** veya **o IP'deki VHost domain adlarını brute force uygulayarak**, **aynı IP'de web siteleri bulunan diğer subdomain'leri bulmayı** deneyebilirsiniz.

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'leri kullanarak IP'lerde bazı** **VHosts** **bulabilirsiniz**.

**Brute Force**

Bir web server'da bazı subdomain'lerin gizlenmiş olabileceğinden şüpheleniyorsanız, brute force uygulamayı deneyebilirsiniz:

Name-based vhost'lar için `Host` header'ını fuzz'layın ve varsayılan response'u filtrelemek üzere ffuf'un auto-calibration özelliğini kullanın.<sup>[[2]](#references)</sup>
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
> Bu teknikle internal/gizli endpoint'lere erişmeniz bile mümkün olabilir.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulabilirsiniz. Bu senaryolarda, yeni **subdomain**'leri **keşfetmek** için bu davranışı kötüye kullanabilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** ararken bunların herhangi bir **bucket** türüne **pointing** yapıp yapmadığını kontrol edin ve böyle bir durum varsa [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu aşamada scope içindeki tüm domainleri biliyor olacağınız için olası bucket adlarını [**brute force edin ve izinleri kontrol edin**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorizasyon**

**Certificate Transparency** Logs'u izleyerek bir domain için **new subdomains** oluşturulup oluşturulmadığını [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)'in yaptığı şekilde **monitor** edebilirsiniz.

### **Looking for vulnerabilities**

Olası [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) durumlarını kontrol edin.\
**subdomain** herhangi bir **S3 bucket**'ına pointing yapıyorsa [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Asset discovery sırasında bulduklarınızdan **farklı bir IP'ye sahip subdomain** bulursanız, **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz; bunun için **nmap/masscan/shodan** kullanabilirsiniz. Çalışan servislere bağlı olarak, **this book** içinde bu servislere nasıl **"attack"** edileceğine dair bazı yöntemler bulabilirsiniz.\
_Bazen subdomain'in client tarafından kontrol edilmeyen bir IP üzerinde barındırılabileceğini ve bu nedenle scope içinde olmayabileceğini unutmayın; dikkatli olun._

## IPs

İlk adımlarda muhtemelen bazı **IP aralıkları, domainler ve subdomainler** buldunuz.\
Şimdi bu aralıklardaki tüm IP'leri ve **domain/subdomain**'ler için (DNS sorguları aracılığıyla) IP'leri **toplama** zamanı.

Aşağıdaki **free apis** servislerini kullanarak **domain ve subdomain'ler tarafından daha önce kullanılmış IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir).

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine pointing yapan domainleri de kontrol edebilirsiniz.

### **Looking for vulnerabilities**

**CDN'lere ait olmayan tüm IP'lerde port scan gerçekleştirin** (çünkü büyük olasılıkla burada ilginç bir şey bulamazsınız). Keşfedilen çalışan servislerde **vulnerabilities** bulabilirsiniz.

Host'ların nasıl taranacağı hakkında bir [**guide**](../pentesting-network/index.html) **bulun.**

## Web servers hunting

> Tüm şirketleri ve bunların asset'lerini bulduk; scope içindeki IP aralıklarını, domainleri ve subdomainleri biliyoruz. Şimdi web server'ları arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP ve domainler üzerinde bazı **recon** işlemleri gerçekleştirdiniz; bu nedenle **olası tüm web server'ları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi scope içindeki web server'ları aramak için bazı **fast tricks** göreceğiz.

Bunun **web apps discovery** odaklı olacağını unutmayın; bu nedenle scope tarafından **izin veriliyorsa**, **vulnerability** ve **port scanning** de gerçekleştirmelisiniz.

[**masscan** kullanarak **web** server'larıyla ilişkili **open ports** keşfetmeye yönelik **fast method** [burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web server'ları aramak için kullanılabilecek bir diğer kullanıcı dostu araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Bir domain listesi vermeniz yeterlidir; araç port 80'e (http) ve 443'e (https) bağlanmayı dener. Ayrıca başka portları denemesini de belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Artık kapsamda bulunan **tüm web sunucularını** (şirketin **IP'leri** ile tüm **domain** ve **subdomain**'ler arasında) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. Öyleyse bunu basitleştirelim ve önce hepsinin ekran görüntülerini alalım. Sadece **ana sayfaya** bir **bakış atarak**, daha **savunmasız** olma ihtimali bulunan **tuhaf** endpoint'ler bulabilirsiniz.

Önerilen fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca tüm **ekran görüntülerini** incelemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanarak hangilerinin **vulnerability** içermesinin muhtemel olduğunu ve hangilerinin olmadığını belirleyebilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek cloud asset'lerini bulmak için **şirketi tanımlayan keyword'lerden oluşan bir listeyle başlamalısınız**. Örneğin, bir crypto şirketi için `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gibi kelimeler kullanabilirsiniz.

Ayrıca **bucket'larda kullanılan yaygın kelimelerin** wordlist'lerine de ihtiyacınız olacaktır:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Ardından bu kelimelerle **permutation'lar** oluşturmalısınız (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Asset'lerini ararken AWS'de yalnızca bucket'ları aramamanız gerektiğini unutmayın.

### **Looking for vulnerabilities**

**Açık bucket'lar veya dışarıya açık cloud function'lar** gibi şeyler bulursanız bunlara **erişmeli**, size ne sunduklarını ve kötüye kullanılıp kullanılamayacaklarını görmeye çalışmalısınız.

## Emails

Kapsam içindeki **domain** ve **subdomain**'lerle, temel olarak **email aramaya başlamak** için ihtiyacınız olan her şeye sahipsiniz. Bunlar, bir şirketin email'lerini bulmak için benim için en iyi çalışan **API'ler** ve **araçlardır**:

- [**theHarvester**](https://github.com/laramies/theHarvester) - API'lerle
- [**https://hunter.io/**](https://hunter.io/) API'si (free version)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (free version)
- [**https://minelead.io/**](https://minelead.io/) API'si (free version)

### **Looking for vulnerabilities**

Email'ler daha sonra web login'lerini ve auth servislerini (SSH gibi) **brute-force** etmek için işinize yarayacaktır. Ayrıca **phishing** için de gereklidirler. Bunun yanında bu API'ler, email'in arkasındaki **kişi hakkında daha fazla bilgi** sağlayarak phishing campaign için faydalı olabilir.

## Credential Leaks

**Domain**, **subdomain** ve **email**'lerle, geçmişte bu email'lere ait **leak edilmiş credential'ları** aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**Geçerli leak edilmiş** credential'lar bulursanız bu çok kolay bir kazanımdır.

## Secrets Leaks

Credential leak'leri, şirketlerin **hassas bilgilerinin leak edildiği ve satıldığı** hack'lerle ilgilidir. Ancak şirketler, bilgileri bu database'lerde bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credential'lar ve API'ler, şirketin veya söz konusu github şirketinde çalışan **kullanıcıların public repository'lerinde** leak edilmiş olabilir.\
Şirketin bir **organization'ına** ve **developer'larına** ait tüm **public repo'ları download** etmek ve üzerlerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **tool'unu** kullanabilirsiniz.

**Leakos**, kendisine verilen **URL'lerden** sağlanan tüm **text** üzerinde de **gitleaks** çalıştırmak için kullanılabilir; çünkü bazen **web sayfaları da secret'lar içerir**.

#### Github Dorks

Organization'da aranabilecek potansiyel **GitHub dork'ları** için [GitHub dorks and leaks page](github-leaked-secrets.md) sayfasına bakın.

### Pastes Leaks

Bazen saldırganlar veya yalnızca çalışanlar **şirket içeriğini bir paste sitesinde publish eder**. Bu içerik **hassas bilgiler** barındırabilir veya barındırmayabilir, ancak aramak oldukça ilginçtir.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) tool'unu kullanabilirsiniz.

### Google Dorks

Eski ama etkili Google dork'ları, **orada bulunmaması gereken expose edilmiş bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in manuel olarak çalıştıramayacağınız **binlerce** olası query içermesidir. Bu nedenle en sevdiğiniz 10 tanesini seçebilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir tool** kullanabilirsiniz.

_Tüm database'i normal Google browser'ını kullanarak çalıştırmayı bekleyen tool'ların, Google sizi çok kısa süre içinde engelleyeceği için asla sona ermeyeceğini unutmayın._

### **Looking for vulnerabilities**

**Geçerli leak edilmiş** credential'lar veya API token'ları bulursanız bu çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**'a sahip olduğunu bulursanız bunu **analiz edebilir** ve üzerinde **vulnerability** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **tool'lar** vardır; [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) listesine bakın.

Ayrıca aşağıdakiler gibi **public repository'leri scan etmenize** izin veren ücretsiz servisler de vardır:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'lar tarafından bulunan **vulnerability'lerin çoğu** **web application'larının** içinde yer alır. Bu nedenle bu noktada bir **web application testing methodology** hakkında konuşmak istiyorum; bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümünden özellikle bahsetmek istiyorum. Çok hassas vulnerability'ler bulmalarını beklememeniz gerekse de, bazı başlangıç düzeyinde web bilgileri edinmek amacıyla bunları **workflow'lara eklemek** kullanışlıdır.

## Recapitulation

> Tebrikler! Bu noktada **tüm temel enumeration** işlemlerini zaten gerçekleştirdiniz. Evet, bu temel seviyededir; çünkü çok daha fazla enumeration yapılabilir (daha fazla trick'i ileride göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsam içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset'leri** buldunuz (kapsamdaysa bazı vuln scan'leri gerçekleştirdiniz)
3. Şirketlere ait tüm **domain'leri** buldunuz
4. Domain'lerin tüm **subdomain'lerini** buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP'leri** (CDN'lerden gelen ve **gelmeyen**) buldunuz.
6. Tüm **web sunucularını** buldunuz ve bunların **ekran görüntülerini** aldınız (daha yakından incelenmeye değer tuhaf bir şey var mı?)
7. Şirkete ait tüm **potansiyel public cloud asset'lerini** buldunuz.
8. Size çok kolay bir şekilde **büyük bir kazanım** sağlayabilecek **email'leri**, **credential leak'lerini** ve **secret leak'lerini** buldunuz.
9. Bulduğunuz tüm web'lerde **Pentesting yaptınız**

## **Full Recon Automatic Tools**

Önerilen işlemlerin bir kısmını belirli bir scope'a karşı gerçekleştirecek çeşitli tool'lar vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

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
