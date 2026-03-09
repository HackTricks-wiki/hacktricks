# Dış Keşif Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlık Keşifleri

> Size bir şirkete ait her şeyin kapsamda olduğu söylendi; şimdi bu şirketin gerçekte hangi varlıklara sahip olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı, ana şirkete ait tüm **şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için şunları yapacağız:

1. Ana şirketin satın almalarını (acquisitions) bulun — bu bize kapsam içindeki şirketleri verir.
2. Her şirketin varsa ASN'sini bulun — bu bize her şirketin sahip olduğu IP aralıklarını verir.
3. İlk girişle ilişkili diğer kayıtları (organization isimleri, domainler...) aramak için reverse whois lookups kullanın (bu işlem recursive yapılabilir).
4. Diğer varlıkları bulmak için shodan `org` ve `ssl` filters gibi teknikleri kullanın (`ssl` hilesi recursive olarak yapılabilir).

### **Acquisitions**

Öncelikle, ana şirketin sahip olduğu **diğer şirketlerin** hangileri olduğunu bilmemiz gerekiyor.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com)'u ziyaret edip **ana şirketi** aramak ve "**acquisitions**"e tıklamaktır. Orada ana şirket tarafından edinilen diğer şirketleri göreceksiniz.\
Diğer bir seçenek ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** bölümünü aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfaları veya yerel ticaret sicilleri (ör. Birleşik Krallık'ta **Companies House**) kontrol edin.\
Küresel kurumsal ağaçlar ve iştirakler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri biliyor olmalısınız. Şimdi bu şirketlerin varlıklarını nasıl bulacağımıza bakalım.

### **ASNs**

An autonomous system number (**ASN**) is a **unique number** assigned to an **autonomous system** (AS) by the **Internet Assigned Numbers Authority (IANA)**.\
Bir **AS**, dış ağlara erişim için belirlenmiş politika ile yönetilen **IP adresleri bloklarından** oluşur; tek bir kuruluş tarafından yönetilir ancak birden fazla operatörden oluşabilir.

Şirketin herhangi bir ASN atayıp atamadığını bulmak, **IP aralıklarını** tespit etmek için ilginçtir. Kapsam içindeki tüm **hosts** üzerinde bir **zafiyet testi** yapmak ve bu IP'ler içindeki domainleri aramak ilginç olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) veya [**https://ipinfo.io/**](https://ipinfo.io/) üzerinde şirket **ismi**, **IP** veya **domain** ile arama yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak şu linkler daha fazla veri toplamada faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Her halükarda muhtemelen tüm kullanışlı bilgiler (IP ranges ve Whois) ilk linkte zaten görünmektedir.**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration tarama sonunda ASNs'i otomatik olarak birleştirir ve özetler.
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
Bir kuruluşun IP aralıklarını ayrıca [http://asnlookup.com/](http://asnlookup.com) kullanarak bulabilirsiniz (ücretsiz API'si vardır).\
Bir domainin IP'sini ve ASN'ini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Güvenlik Açıklarını Arama**

Bu noktada kapsam içindeki **tüm varlıkları** biliyoruz, bu yüzden izinliyseniz tüm hostlar üzerinde bazı **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir veya açık portları bulmak için Shodan, Censys veya ZoomEye gibi servisleri kullanabilirsiniz ve bulduklarınıza bağlı olarak bu kitaptaki ilgili bölümlere bakarak çeşitli çalışıyor olabilecek servisleri nasıl pentest edeceğinizi incelemelisiniz.\
**Ayrıca, belirtmek gerekir ki bazı** varsayılan kullanıcı adı **ve** şifreler **listeleri hazırlayıp denemeyi** bruteforce servisleri ile [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) deneyebilirsiniz.

## Alan Adları

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz, şimdi kapsam içindeki alan adlarını bulma zamanı.

_Lütfen, aşağıda önerilen tekniklerde alt alan adlarını da (subdomains) bulabileceğinizi ve bu bilginin küçümsenmemesi gerektiğini unutmayın._

Her şirket için öncelikle **ana domain**(ler)ini aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Reverse DNS**

Tüm domainlerin IP aralıklarını bulduğunuza göre, kapsam içindeki daha fazla domaini bulmak için bu **reverse dns lookups** işlemini bu **IP'ler üzerinde kapsam içindeki daha fazla domaini bulmak için** denemeyi düşünebilirsiniz. Hedefin bir dns sunucusunu veya iyi bilinen bir dns sunucusunu (1.1.1.1, 8.8.8.8) kullanmayı deneyin.
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için, yönetici PTR'yi manuel olarak etkinleştirmelidir.\
Bu bilgi için ayrıca çevrimiçi bir araç kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Geniş aralıklar için, ters DNS sorgularını ve zenginleştirmeyi otomatikleştirmek amacıyla [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar faydalıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e‑postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginci, bu alanlardan herhangi biriyle **reverse whois lookups** yaparsanız şirkete ait **daha fazla varlık** bulabilirsiniz (örneğin aynı e‑postanın geçtiği diğer whois kayıtları).\
Aşağıdaki çevrimiçi araçları kullanabilirsiniz:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Ücretsiz** web, API ücretli.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **Ücretli**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **Ücretli** (sadece **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - **Ücretli**
- [https://securitytrails.com/](https://securitytrails.com/) - **Ücretli** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **Ücretli** (API)

Bu görevi otomatikleştirmek için [**DomLink** ](https://github.com/vysecurity/DomLink)(whoxy API anahtarı gerektirir) kullanabilirsiniz.\
Ayrıca bazı otomatik reverse whois keşifleri için [amass](https://github.com/OWASP/Amass) kullanabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde bu tekniği daha fazla alan adı keşfetmek için kullanabileceğinizi unutmayın.**

### **Trackers**

Eğer iki farklı sayfada **aynı tracker'ın aynı ID'sini** bulursanız, **her iki sayfanın da** **aynı ekip tarafından yönetildiğini** varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görmeniz durumunda.

Bu tracker'lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar/araçlar şunlardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/trackers ile ilişkili siteleri bulur)

### **Favicon**

Aynı favicon icon hash'ini arayarak hedefinize ilişkin ilişkili domain ve alt domainleri bulabileceğimizi biliyor muydunuz? Bu, [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılmış [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracının tam olarak yaptığı şeydir. Kullanımı şöyle:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon icon hash'e sahip alan adlarını keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizin favicon icon hash'iyle aynı olan alan adlarını keşfetmemizi sağlar.

Moreover, you can also search technologies using the favicon hash as explained in [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Bu, eğer **zafiyetli bir web teknolojisinin sürümünün favicon hash'ini** biliyorsanız shodan'da arama yapıp **daha fazla zayıf yer** bulabileceğiniz anlamına gelir:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
İşte bir web sitesinin **favicon hash**'ini nasıl hesaplayabileceğiniz:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
Ayrıca favicon hash'lerini ölçekli olarak [**httpx**](https://github.com/projectdiscovery/httpx) ile alabilir (`httpx -l targets.txt -favicon`) ve sonra Shodan/Censys'te pivot yapabilirsiniz.

### **Telif hakkı / Benzersiz dize**

Web sayfalarının içinde **aynı organizasyondaki farklı web sitelerinde paylaşılabilecek dizeleri** arayın. **Telif hakkı dizesi** iyi bir örnek olabilir. Sonra bu dizeyi **google**'da, diğer **tarayıcılarda** veya hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Genellikle şu tür bir cron job bulunur:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Görünüşe göre insanlar alt domainleri cloud sağlayıcılarına ait IP'lere atama eğilimindeler ve bir noktada **o IP adresini kaybedip DNS kaydını silmeyi unutuyorlar**. Bu nedenle, sadece bir bulutta (örneğin Digital Ocean) **bir VM başlatmak** bazı alt domainlerin fiilen **üstlenilmesine** yol açabilir.

[**This post**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir örnek anlatıyor ve **DigitalOcean'da bir VM başlatan**, yeni makinenin **IPv4** adresini alan ve ona işaret eden alt domain kayıtlarını **Virustotal**'da arayan bir script öneriyor.

### **Other ways**

**Yeni bir domain bulduğunuz her seferinde daha fazla domain adı keşfetmek için bu tekniği kullanabileceğinizi unutmayın.**

**Shodan**

IP alanına sahip organizasyonun adını zaten biliyorsanız. Bu veriye göre shodan'da şu sorguyla arama yapabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları TLS sertifikasındaki yeni/beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation name**'i elde edebilir ve sonra bu ismi **shodan**'ın bildiği tüm web sayfalarının **TLS sertifikalarında** şu filtre ile arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) ana domain ile ilişkili **domainleri** ve bunların **alt domainlerini** arayan bir araçtır, oldukça kullanışlı.

**Passive DNS / Historical DNS**

Passive DNS verisi, hâlâ çözümlenen veya üstlenilebilecek **eski ve unutulmuş kayıtları** bulmak için çok iyidir. Bakabileceğiniz servisler:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Belki bazı şirketler bir domaini kullanıyor fakat **sahipliğini kaybetmişlerdir**. Eğer (yeterince ucuzsa) domaini kaydederek şirkete haber verebilirsiniz.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.
>
> It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Bu araçların ve domain bulma tekniklerinin bazıları aynı zamanda subdomain bulmada da yardımcı olabilir

### **DNS**

DNS kayıtlarından **alt alan adlarını** almaya çalışalım. Ayrıca **Zone Transfer**'ı da denemeliyiz (Eğer zafiyetliyse, bunu raporlayın).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Birçok alt alan adı elde etmenin en hızlı yolu harici kaynaklarda aramaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):

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
Doğrudan subdomains bulmada uzman olmasalar bile subdomains bulmakta yine de faydalı olabilecek **diğer ilginç araçlar/APIs** şunlardır:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanarak subdomains elde eder
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
- [**gau**](https://github.com/lc/gau)**:** herhangi bir alan adı için AlienVault's Open Threat Exchange, the Wayback Machine ve Common Crawl kaynaklarından bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayıp JS dosyalarını ararlar ve buradan alt alan adlarını çıkarırlar.
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
- [**securitytrails.com**](https://securitytrails.com/) subdomains ve IP geçmişini aramak için ücretsiz bir API sunar
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, bug-bounty programs ile ilgili tüm subdomains'i ücretsiz olarak sunar. Bu verilere ayrıca [chaospy](https://github.com/dr-0x0x/chaospy) ile de erişebilir veya bu projenin kullandığı scope'a şu adresten erişebilirsiniz: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Bu araçların birçoğunun bir **karşılaştırmasını** şurada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası subdomain isimlerini kullanarak DNS sunucularını brute-forcing yaparak yeni **subdomains** bulmaya çalışalım.

Bu işlem için aşağıdaki gibi bazı yaygın subdomains wordlists'e ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ve ayrıca iyi DNS resolvers IP'lerine de ihtiyacınız var. Güvenilir DNS resolvers listesi oluşturmak için resolvers'ı [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden indirip [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) ile filtreleyebilirsiniz. Ya da şu adresi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

En çok tavsiye edilen DNS brute-force araçları şunlardır:

- [**massdns**](https://github.com/blechschmidt/massdns): Bu, etkili bir DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır; ancak yanlış pozitiflere meyillidir.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bence bu sadece 1 resolver kullanıyor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` etrafında go ile yazılmış bir sarmalayıcıdır; aktif bruteforce kullanarak geçerli alt alan adlarını listelemenize ve wildcard işleme ile alt alan adlarını çözmenize ve kolay giriş-çıkış desteği sağlamanıza olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) alan adlarını eşzamansız olarak brute force etmek için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynaklar ve brute-forcing kullanarak subdomains bulduktan sonra, bulunan subdomains varyasyonlarını üreterek daha fazlasını bulmayı deneyebilirsiniz. Bu amaç için birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domains ve subdomains için permutasyonlar üretir.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domain ve subdomainlerden permütasyonlar oluşturur.
- goaltdns permütasyonları için **wordlist**'i [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) adresinden alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domains ve subdomains için permutations oluşturur. Eğer herhangi bir permutations dosyası belirtilmemişse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations üretmenin yanı sıra, bunları çözmeyi de deneyebilir (ancak önceki bahsedilen araçları kullanmak daha iyidir).
- altdns permutations **wordlist**'i [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) adresinden edinebilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adlarının permutasyonlarını, mutasyonlarını ve değişikliklerini gerçekleştirmek için başka bir araç. Bu araç sonucu brute force ile dener (dns wild card desteklenmiyor).
- dmut permutations wordlist'ini [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) adresinden edinebilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain'e dayanarak, belirtilen desenlere göre daha fazla subdomains keşfetmeye çalışmak için **yeni potansiyel subdomains isimleri üretir**.

#### Akıllı permütasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**post**](https://cramppet.github.io/regulator/index.html)u okuyun ama temelde **keşfedilen subdomains** içinden **ana parçaları** alacak ve bunları karıştırarak daha fazla subdomains bulacak.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ son derece basit ama etkili bir DNS yanıt-yönlendirmeli algoritmayla entegre edilmiş bir subdomain brute-force fuzzer'dır. Sağlanan giriş veri setlerini (ör. özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları) kullanarak, daha fazla ilgili alan adını doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları döngüsel şekilde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Bir alan adından **automate the subdomain discovery** işlemini **Trickest workflows** kullanarak nasıl yaptığımı anlattığım bu blog yazısını inceleyin; böylece bilgisayarımda birçok aracı elle başlatmama gerek kalmaz:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Eğer bir IP adresinde subdomain'lere ait **bir veya birkaç web sayfası** bulduysanız, o IP'de web barındıran diğer subdomain'leri IP içindeki domainlere bakarak **OSINT** kaynaklarından veya o IP'de **VHost** domain adlarını **brute-forcing** yaparak bulmayı deneyebilirsiniz.

#### OSINT

Bazı **VHosts**'ları IP'lerde [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya diğer API'ler** kullanarak bulabilirsiniz.

**Brute Force**

Eğer bazı subdomain'lerin bir web sunucusunda gizlenmiş olabileceğini düşünüyorsanız, bunları brute force etmeyi deneyebilirsiniz:

When the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> Bu teknikle internal/hidden endpoints'e bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, geçerli bir domain/subdomain _**Origin**_ header'ı olarak ayarlandığında sayfaların yalnızca _**Access-Control-Allow-Origin**_ header'ını döndürdüğünü görürsünüz. Bu senaryolarda, bu davranışı kötüye kullanarak yeni **subdomains** keşfedebilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

subdomains ararken herhangi bir tür **bucket**'a işaret edip etmediğine dikkat edin ve bu durumda [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ayrıca, bu noktada kapsam içindeki tüm domainleri bildiğiniz için, [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **İzleme**

Bir domainin **new subdomains**'inin oluşturulup oluşturulmadığını **Certificate Transparency** Logs'u izleyerek, [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) aracının yaptığı gibi kontrol edebilirsiniz.

### **Zafiyet Arama**

Olası [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) kontrol edin.\
Eğer **subdomain** bir **S3 bucket**'a işaret ediyorsa, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Eğer assets discovery'de zaten bulduğunuzlardan farklı bir IP'ye sahip herhangi bir **subdomain** bulursanız, **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) yapmalı ve **nmap/masscan/shodan** ile bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) gerçekleştirmelisiniz. Hangi servislerin çalıştığına bağlı olarak bu kitapta onları "attack" etmek için bazı hileler bulabilirsiniz.\
_Not: bazen subdomain, müşterinin kontrol etmediği bir IP içinde barındırılıyor olabilir, dolayısıyla kapsam dışında olabilir, dikkatli olun._

## IPs

İlk adımlarda **bazı IP aralıkları, domainler ve subdomains** bulmuş olabilirsiniz.\
Şimdi bu aralıklardan **tüm IP'leri toplama** ve **domainler/subdomains (DNS queries)** için sorgular yapma zamanı.

Aşağıdaki **free apis** servislerini kullanarak domainler ve subdomains tarafından önceden kullanılan **IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ müşteri tarafından sahiplenilmiş olabilir (ve size [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulma imkanı sağlayabilir)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca belirli bir IP adresine işaret eden domainleri [**hakip2host**](https://github.com/hakluke/hakip2host) aracıyla da kontrol edebilirsiniz

### **Zafiyet Arama**

**CDN'lere ait olmayan tüm IP'lerde port scan yapın** (buralarda muhtemelen ilginizi çekecek bir şey bulamayacaksınız). Bulunan çalışan servislerde **zafiyetler bulabilirsiniz**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Tüm şirketleri ve varlıklarını bulduk ve kapsam içindeki IP aralıklarını, domainleri ve subdomains'i biliyoruz. Web sunucularını arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domainler üzerinde bazı **recon** işlemleri yaptınız, bu yüzden muhtemelen **tüm olası web sunucularını** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi kapsam içinde web sunucusu aramak için bazı **hızlı yöntemlere** göz atacağız.

Lütfen unutmayın, bunun amacı **web apps discovery** odaklı olacak, bu yüzden ayrıca **vulnerability** ve **port scanning** yapmalısınız (**eğer kapsam izin veriyorsa**).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Web sunucularını aramak için diğer kullanışlı araçlar [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx) dir. Sadece bir domain listesi verirsiniz ve bu araçlar port 80 (http) ve 443 (https) ile bağlanmayı deneyeceklerdir. Ayrıca, diğer portları denemesini de belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsam içinde bulunan **tüm web sunucularını** (şirketin **IPs**'i ve tüm **domains** ve **subdomains** arasında) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O zaman basit tutalım ve hepsinin sadece ekran görüntülerini almaya başlayın. Sadece **ana sayfaya bakarak** daha **alışılmadık** endpoints'ler bulabilirsiniz; bunlar güvenlik açığı içerebilecek yerlerdir.

Bu fikri gerçekleştirmek için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ayrıca, tüm **ekran görüntüleri** üzerinde çalıştırmak için [**eyeballer**](https://github.com/BishopFox/eyeballer) kullanabilir ve size **nerelerin muhtemelen güvenlik açığı içerdiğini**, hangilerinin içermediğini söylemesini sağlayabilirsiniz.

## Genel Bulut Varlıkları

Bir şirkete ait potansiyel cloud assets'leri bulmak için o şirketi tanımlayan anahtar kelimelerden oluşan bir listeyle **başlamalısınız**. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: "crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">.

Ayrıca **buckets** içinde kullanılan ortak kelimelere ait wordlist'lere ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permutasyonlar** üretmelisiniz (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) bölümüne bakın).

Elde ettiğiniz wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken yalnızca AWS'deki buckets'lara bakmamanız gerektiğini unutmayın.

### **Zafiyet Arama**

Eğer **açık buckets** veya **exposed cloud functions** gibi şeyler bulursanız, bunlara **erişmeli** ve size ne sunduklarını, bunları suistimal edip edemeyeceğinizi görmeye çalışmalısınız.

## E-postalar

Kapsam içindeki **domains** ve **subdomains** ile temelde e-posta aramaya başlamak için ihtiyacınız olan her şeye sahip olursunuz. Bir şirketin e-postalarını bulmak için benim için en iyi çalışan **API'ler** ve **araçlar** şunlardır:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Zafiyet Arama**

E-postalar daha sonra **brute-force web logins and auth services** (ör. SSH) için işe yarayacaktır. Ayrıca **phishings** için de gereklidir. Bu API'ler aynı zamanda e-postanın arkasındaki kişi hakkında daha fazla **info** verebilir ki bu da phishing kampanyası için kullanışlıdır.

## Credential Leaks

Kapsam içindeki **domains**, **subdomains** ve **emails** ile bu e-postalara ait geçmişte leaked olmuş credentials'ları aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet Arama**

Eğer **valid leaked** credentials bulursanız, bu çok kolay bir kazançtır.

## Secrets Leaks

Credential leaks, şirketlerin hacklenmesi sonucu **sensitive information was leaked and sold** ile ilişkilidir. Ancak şirketler, bu veritabanlarında olmayan **other leaks**'lerden de etkilenmiş olabilir:

### Github Leaks

Credentials ve API'ler şirketin veya o github şirketinde çalışan kullanıcıların **public repositories**'inde leaked olmuş olabilir. Bir organizasyonun ve geliştiricilerinin tüm **public repos**'larını **download** edip otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) aracını kullanabilirsiniz.

**Leakos** ayrıca kendisine geçirilen tüm **text** sağlanan **URLs passed** üzerinde **gitleaks** çalıştırmak için de kullanılabilir; çünkü bazen **web pages** de secrets içerir.

#### Github Dorks

Ayrıca saldırdığınız organizasyonda arayabileceğiniz potansiyel **github dorks** için şu **sayfayı** da kontrol edin:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar veya çalışanlar şirket içeriğini paste sitelerinde yayınlar. Bu, içinde **sensitive information** barındırabilir veya barındırmayabilir, ama aramak ilginçtir. Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama etkili Google dorks her zaman **exposed information that shouldn't be there** bulmak için kullanışlıdır. Sorun şu ki [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) binlerce sorgu içerir ve bunları manuel çalıştıramazsınız. Bu yüzden favori 10'unuzu alabilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir **tool** kullanabilirsiniz.

_Not: Tüm veritabanını normal Google tarayıcısı üzerinden çalıştırmayı bekleyen araçlar asla bitmez, çünkü Google sizi çok kısa sürede engelleyecektir._

### **Zafiyet Arama**

Eğer **valid leaked** credentials veya API token'ları bulursanız, bu çok kolay bir kazançtır.

## Açık Kod Zafiyetleri

Eğer şirketin **open-source code**'u olduğunu fark ederseniz, bunu **analiz** edip üzerinde **vulnerabilities** arayabilirsiniz.

**Kullandığınız dile bağlı olarak** farklı **araçlar** mevcut:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca public repositories taramanıza izin veren ücretsiz servisler de vardır, örneğin:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'ların bulduğu **vulnerabilities**'ların çoğunluğu web uygulamaları içinde yer alır, bu yüzden şimdi bir **web application testing methodology** hakkında konuşmak istiyorum; bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özel bir atıf yapmak istiyorum; bunların çok hassas zafiyetler bulmasını beklememelisiniz, fakat bazı başlangıç web bilgilerini almak için workflow'lara entegre etmek kullanışlıdır.

## Özet

> Tebrikler! Bu noktada **tüm temel enumeration**'ı zaten gerçekleştirdiniz. Evet, temel çünkü çok daha fazla enumeration yapılabilir (daha sonra daha fazla numara göreceğiz).

Yani zaten:

1. Kapsam içindeki tüm **companies**'ları buldunuz
2. Şirketlere ait tüm **assets**'leri buldunuz (ve scope dahilindeyse bazı vuln taramaları yaptınız)
3. Şirketlere ait tüm **domains**'leri buldunuz
4. Domain'lerin tüm **subdomains**'lerini buldunuz (herhangi bir subdomain takeover?)
5. Kapsam içindeki tüm **IPs**'leri (CDN'den ve CDN dışından) buldunuz
6. Tüm **web servers**'ı buldunuz ve bunların **screenshot**'larını aldınız (herhangi bir gariplik daha derin inceleme gerektirir mi?)
7. Şirkete ait potansiyel tüm **public cloud assets**'leri buldunuz
8. **Emails**, **credentials leaks**, ve **secret leaks** — bunlar size çok kolay bir büyük kazanç sağlayabilir
9. Bulduğunuz tüm web'leri **Pentesting** yaptınız

## Tam Recon Otomatik Araçlar

Belirli bir scope'a karşı önerilen eylemlerin bir kısmını gerçekleştirecek birkaç araç mevcut.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncel olmayan bir proje

## Referanslar

- @Jhaddix'in tüm ücretsiz kursları, ör. [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
