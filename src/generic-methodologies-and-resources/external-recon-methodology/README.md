# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Varlık keşifleri

> Yani size bir şirkete ait olan her şeyin kapsam içinde olduğu söylendi ve bu şirketin gerçekte neleri kontrol ettiğini öğrenmek istiyorsunuz.

Bu aşamanın amacı, ana şirkete ait tüm **şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için şunları yapacağız:

1. Ana şirketin acquisitions bilgilerini bulun, bu bize kapsam içindeki şirketleri verecek.
2. Her şirketin ASN (varsa) bilgisini bulun, bu bize her şirkete ait IP aralıklarını verecek
3. İlk sonuçla ilişkili diğer kayıtları (organisation isimleri, domains...) aramak için reverse whois lookups kullanın (bu işlem recursive olarak yapılabilir)
4. Diğer varlıkları aramak için shodan `org`ve `ssl`filtreleri gibi diğer teknikleri kullanın (`ssl` hilesi recursive olarak yapılabilir).

### **Acquisitions**

Öncelikle, ana şirketin sahip olduğu **diğer şirketleri** bilmemiz gerekiyor.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) sitesini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" üzerine **tıklamak**tır. Orada ana şirketin satın aldığı diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **acquisitions** kısmını aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'ta **Companies House**) kontrol edin.\
Küresel şirket yapıları ve bağlı şirketler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri bilmelisiniz. Şimdi varlıklarını nasıl bulacağımızı çıkaralım.

### **ASNs**

Bir autonomous system number (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **autonomous system** (AS)'e atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için belirgin şekilde tanımlanmış bir politikaya sahip **IP addresses** **bloklarından** oluşur ve tek bir organisation tarafından yönetilir, ancak birkaç operatörden oluşabilir.

Şirketin **atanmış herhangi bir ASN**'i olup olmadığını bulmak ve **IP aralıklarını** keşfetmek ilginçtir.\
Kapsam içindeki tüm **host**lara karşı bir **vulnerability test** yapmak ve bu IP'lerin içinde **domain** aramak faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **veya** [**https://ipinfo.io/**](https://ipinfo.io/) içinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
Şirketin bölgesine bağlı olarak daha fazla veri toplamak için bu bağlantılar yararlı olabilir: [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Her neyse, muhtemelen tüm** yararlı bilgiler **(IP aralıkları ve Whois)** zaten ilk bağlantıda görünür.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un**
enumeration işlemi taramanın sonunda ASN'leri otomatik olarak toplar ve özetler.
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
Bir kuruluşun IP aralıklarını ayrıca [http://asnlookup.com/](http://asnlookup.com) kullanarak da bulabilirsiniz (ücretsiz API’si var).\
Bir alan adının IP ve ASN bilgisini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Zafiyetleri aramak**

Bu noktada kapsam içindeki **tüm varlıkları** biliyoruz, bu yüzden izin varsa tüm ana makineler üzerinde bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir **veya** Shodan, Censys ya da ZoomEye gibi hizmetleri **kullanarak** açık portları bulabilirsiniz **ve bulduklarınıza bağlı olarak** bu kitapta çalışan olası çeşitli servisleri nasıl pentest yapacağınızı incelemelisiniz.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** parola **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servislerde bruteforce denemeleri yapmanın da değebileceğini belirtmekte fayda var.

## Alan adları

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz, şimdi kapsam içindeki alan adlarını bulma zamanı.

_Ayrıca, aşağıdaki amaçlanan tekniklerde alt alan adlarını da bulabileceğinizi ve bu bilginin küçümsenmemesi gerektiğini lütfen unutmayın._

Her şeyden önce her şirketin **ana alan adı**(larını) aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Ters DNS**

Alan adlarının tüm IP aralıklarını bulduğunuz için, kapsam içindeki daha fazla alan adını bulmak amacıyla bu **IP’ler** üzerinde **ters dns sorguları** yapmayı deneyebilirsiniz. Kurbanın bazı dns sunucularını veya bilinen dns sunucularını (1.1.1.1, 8.8.8.8) kullanmayı deneyin
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için, yöneticinin PTR’yi manuel olarak etkinleştirmesi gerekir.\
Bu bilgi için çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için, [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar reverse lookup ve enrichment işlemlerini otomatikleştirmek için kullanışlıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organisation name**, **address**, **emails**, phone numbers... gibi birçok ilginç **information** bulabilirsiniz. Ancak daha da ilginç olan, bu alanlardan herhangi biriyle **reverse whois lookups** yaparsanız şirkete ait **daha fazla asset** bulabilmenizdir (örneğin aynı email'in göründüğü diğer whois kayıtları).\
Şu gibi çevrimiçi araçları kullanabilirsiniz:

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (whoxy API key gerektirir).\
[amass](https://github.com/OWASP/Amass) ile de bazı otomatik reverse whois keşfi yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde bu tekniği daha fazla domain name keşfetmek için kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada aynı tracker’ın aynı ID’sini bulursanız, **her iki sayfanın** da aynı ekip tarafından **managed** edildiğini varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görürseniz.

Bu tracker’lara ve daha fazlasına göre arama yapmanızı sağlayan bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (ortak analytics/trackers ile ilişkili siteleri bulur)

### **Favicon**

Aynı favicon icon hash’ine bakarak hedefimize ait ilişkili domain’leri ve subdomain’leri bulabileceğimizi biliyor muydunuz? İşte [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılan [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tam olarak bunu yapar. Nasıl kullanacağınız burada:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon icon hash’e sahip domainleri keşfedin](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kısacası, favihash bize hedefimizle aynı favicon icon hash’e sahip domainleri keşfetmemizi sağlar.

Ayrıca, [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) içinde açıklandığı gibi, favicon hash kullanarak teknolojileri de arayabilirsiniz. Bu, bir web tech’in savunmasız bir versiyonunun **favicon hash’ini** biliyorsanız shodan’da arama yapıp **daha fazla savunmasız yer** bulabileceğiniz anlamına gelir:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Bir web’in **favicon hash**’ini şu şekilde **hesaplayabilirsiniz**:
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
Ayrıca favicon hashlerini [**httpx**](https://github.com/projectdiscovery/httpx) ile ölçekli olarak da alabilirsiniz (`httpx -l targets.txt -favicon`) ve ardından Shodan/Censys içinde pivot yapabilirsiniz.

### **Copyright / Uniq string**

Web sayfalarının içinde **aynı organizasyondaki farklı web siteleri arasında paylaşılabilecek stringleri** arayın. **copyright string** iyi bir örnek olabilir. Sonra bu stringi **google** içinde, diğer **browser**larda veya hatta **shodan** içinde arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

Şunun gibi bir cron job olması yaygındır:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **aynı şirkete ait domainleri certificate transparency loglarında bulmak**.\
Daha fazla bilgi için bu [**writeup**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)a göz atın.

Ayrıca **certificate transparency** loglarını doğrudan kullanın:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Bir web sitesi olarak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir araç kullanarak **aynı dmarc bilgilerini paylaşan domainleri ve subdomainleri** bulabilirsiniz.\
Diğer faydalı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/)dır.

### **Passive Takeover**

Görünüşe göre insanlar için subdomainleri cloud sağlayıcılarına ait IP'lere yönlendirmek yaygın ve bir noktada **o IP adresini kaybedip DNS kaydını silmeyi unutmak** da sık görülüyor. Bu nedenle, bir cloud içinde (Digital Ocean gibi) sadece **bir VM başlatarak** aslında bazı subdomainleri **ele geçirebilirsiniz**.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bununla ilgili bir hikaye anlatır ve **DigitalOcean'da bir VM başlatan**, yeni makinenin **IPv4** adresini **alan** ve Virustotal içinde ona işaret eden subdomain kayıtlarını **aran** bir betik önerir.

### **Other ways**

**Dikkat edin, bu tekniği her yeni domain bulduğunuzda daha fazla domain adı keşfetmek için kullanabilirsiniz.**

**Shodan**

Zaten IP alanına sahip organizasyonun adını biliyorsunuz. Bu veriyi shodan içinde `org:"Tesla, Inc."` kullanarak arayabilirsiniz. Bulunan hostları TLS sertifikasında yeni ve beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS sertifikasına** erişip **Organisation** adını alabilir ve ardından shodan tarafından bilinen tüm web sayfalarının **TLS sertifikaları** içinde bu adı `ssl:"Tesla Motors"` filtresiyle arayabilirsiniz ya da [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder), ana domainle ilişkili **domainleri** ve onların **subdomainlerini** arayan oldukça etkileyici bir araçtır.

**Passive DNS / Historical DNS**

Passive DNS verisi, hâlâ çözümlenen veya ele geçirilebilecek **eski ve unutulmuş kayıtları** bulmak için harikadır. Şunlara bakın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) kontrolleri yapın. Belki bir şirket **bir domain kullanıyordur** ama **mülkiyetini kaybetmiştir**. Sadece onu kaydedin (yeterince ucuzsa) ve şirketi bilgilendirin.

Bulduğunuz asset keşfinde daha önce bulduğunuz IP'lerden **farklı bir IP'ye sahip herhangi bir domain** bulursanız, **temel bir vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) işlemleri yapmalısınız. Çalışan servislere bağlı olarak **bu kitapta onları "saldırmak" için bazı numaralar** bulabilirsiniz.\
_Not: Bazen domain, client tarafından kontrol edilmeyen bir IP üzerinde barındırılır; yani kapsamda değildir, dikkatli olun._

## Subdomains

> Kapsamdaki tüm şirketleri, her şirketin tüm assetlerini ve şirketlerle ilişkili tüm domainleri biliyoruz.

Şimdi bulunan her domainin mümkün olan tüm subdomainlerini bulma zamanı.

> [!TIP]
> Dikkat edin, domain bulmak için kullanılan bazı araçlar ve teknikler subdomain bulmaya da yardımcı olabilir.

### **DNS**

DNS kayıtlarından **subdomain** almaya çalışalım. Ayrıca **Zone Transfer** için de denemeliyiz (Eğer zafiyetliyse, bunu rapor etmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu harici kaynaklarda aramaktır. En çok kullanılan **tools** şunlardır (daha iyi sonuçlar için API anahtarlarını yapılandırın):

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
There are **other interesting tools/APIs** that even if not directly specialised in finding subdomains could be useful to find subdomains, like:

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
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** verilen herhangi bir domain için AlienVault'un Open Threat Exchange, Wayback Machine ve Common Crawl kaynaklarından bilinen URL'leri çeker.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web’i JS dosyaları aramak için tarar ve oradan alt alan adlarını çıkarır.
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
- [**securitytrails.com**](https://securitytrails.com/) alt alan adları ve IP geçmişini aramak için ücretsiz bir API sunar
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm subdomains**i **ücretsiz** olarak sunar. Bu veriye [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak da erişebilirsiniz veya bu projenin kullandığı scope’a da erişebilirsiniz [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Bu araçların çoğunun bir **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

DNS sunucularına olası subdomain adlarını kullanarak brute-force yapıp yeni **subdomains** bulmaya çalışalım.

Bu işlem için bazı **yaygın subdomains wordlists gibi** şunlara ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver’ların IP’leri gerekir. Güvenilir bir DNS resolver listesi oluşturmak için, resolver’ları [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) adresinden indirip [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) ile filtreleyebilirsiniz. Ya da şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force yapan ilk araç buydu. Çok hızlıdır ancak false positive üretmeye yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bunun sadece 1 resolver kullandığını düşünüyorum
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` etrafında yazılmış, go ile yazılmış bir wrapper'dır; aktif bruteforce kullanarak geçerli subdomain'leri enumerate etmenizi sağlar, ayrıca wildcard handling ve kolay input-output desteğiyle subdomain'leri resolve etmenizi sağlar.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): O da `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) alan adlarını asenkron olarak brute force etmek için asyncio kullanır.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynaklar ve brute-forcing kullanarak subdomain'leri bulduktan sonra, daha da fazlasını bulmayı denemek için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaç için birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain'lerden permütasyonlar oluşturur.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domainler ve subdomainler için permütasyonlar oluşturur.
- goaltdns permütasyonları için **wordlist**'i [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domainler ve subdomainler için permutasyonlar oluşturur. Eğer bir permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları üretmenin yanı sıra, bunları çözümlemeyi de deneyebilir (ancak önce yorumda geçen araçları kullanmak daha iyidir).
- [**altdns**] permütasyonları için **wordlist**'i [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adları üzerinde permütasyon, mutasyon ve değiştirme işlemleri yapmak için başka bir araç. Bu araç sonucu brute force eder (dns wild card desteklemez).
- dmut permütasyon kelime listesini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain'e dayanarak, belirtilen pattern'lere göre **yeni olası subdomain isimleri** üretir; daha fazla subdomain keşfetmeye çalışmak için.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**post**](https://cramppet.github.io/regulator/index.html) yazısını okuyun; temel olarak **keşfedilen subdomain**'lerden **ana parçaları** alır ve daha fazla subdomain bulmak için bunları karıştırır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ son derece basit ama etkili bir DNS yanıtı rehberli algoritma ile birleştirilmiş bir subdomain brute-force fuzzer'dır. DNS taraması sırasında toplanan bilgilere dayanarak, özel bir wordlist veya tarihsel DNS/TLS kayıtları gibi sağlanan bir girdi veri kümesini kullanır; daha fazla karşılık gelen domain name'leri doğru şekilde üretir ve bunları döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Bir alan adından **subdomain keşfini** nasıl **otomatikleştireceğime** dair **Trickest workflows** kullanarak yazdığım şu blog yazısına bakın; böylece bilgisayarımda bir sürü aracı elle başlatmam gerekmiyor:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Eğer subdomain'lere ait **bir veya birkaç web sayfası** içeren bir IP address bulduysanız, o IP’deki **web’leri olan başka subdomain'leri bulmayı** deneyebilirsiniz; bunun için bir IP içindeki domain'leri bulmak üzere **OSINT kaynaklarına** bakabilir ya da o IP’de **VHost domain name'lerini brute-force ederek** arayabilirsiniz.

#### OSINT

Bazı **VHost'ları IP'lerde** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **veya başka APIs kullanarak** bulabilirsiniz.

**Brute Force**

Eğer bazı subdomain'lerin bir web server içinde gizlenmiş olabileceğinden şüpheleniyorsanız, brute force etmeyi deneyebilirsiniz:

**IP bir hostname'e yönlendirdiğinde** (name-based vhosts), `Host` header'ını doğrudan fuzz edin ve ffuf'un **auto-calibrate** etmesine izin verin; böylece default vhost'tan farklı yanıtları öne çıkarabilirsiniz:
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
> Bu teknikle hatta iç/gizli endpointlere erişim sağlayabilirsiniz.

### **CORS Brute Force**

Bazen yalnızca _**Origin**_ başlığında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulursunuz. Bu senaryolarda, bu davranışı kötüye kullanarak yeni **subdomain**'leri **keşfedebilirsiniz**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**Subdomainler**ı ararken herhangi bir **bucket** türüne **işaret edip etmediğine** dikkat edin ve bu durumda [**permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**'ı kontrol edin.**\
Ayrıca, bu noktada kapsam içindeki tüm domainleri bileceğiniz için, olası bucket adlarını [**brute force** etmeyi ve permissions'ı kontrol etmeyi](../../network-services-pentesting/pentesting-web/buckets/index.html) deneyin.

### **Monitorization**

Bir domainin **yeni subdomain**lerinin oluşturulup oluşturulmadığını, **Certificate Transparency** loglarını izleyerek **monitor** edebilirsiniz; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) bunu yapar.

### **Looking for vulnerabilities**

Olası [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) için kontrol edin.\
Eğer **subdomain** bir **S3 bucket**'a işaret ediyorsa, [**permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)'ı kontrol edin.

Kapsam keşfinde bulduğunuzlardan **farklı bir IP'ye** sahip herhangi bir **subdomain** bulursanız, **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) işlemleri yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta** onları "attack" etmek için bazı püf noktaları bulabilirsiniz.\
_Not: bazen subdomain, client tarafından kontrol edilmeyen bir IP içinde barındırılır, yani kapsam dışında olabilir; dikkatli olun._

## IPs

İlk adımlarda bazı **IP range'leri, domainler ve subdomainler** bulmuş olabilirsiniz.\
Şimdi bu range'lerden tüm **IP'leri** ve **domain/subdomain**ler için (DNS sorguları) yeniden toplama zamanı.

Aşağıdaki **free apis** servislerini kullanarak, domain ve subdomainler tarafından daha önce kullanılmış **IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanıza izin verebilir)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine işaret eden domainleri de kontrol edebilirsiniz.

### **Looking for vulnerabilities**

**CDN'lere ait olmayan** tüm IP'lerde **port scan** yapın (çünkü orada ilginç bir şey bulma olasılığınız oldukça düşüktür). Tespit edilen çalışan servislerde **vulnerabilities** bulabilirsiniz.

**Hostları nasıl scan edeceğinize dair bir** [**guide**](../pentesting-network/index.html) **bulun.**

## Web servers hunting

> Tüm şirketleri ve varlıklarını bulduk; kapsam içindeki IP range'lerini, domainleri ve subdomainleri biliyoruz. Şimdi web server arama zamanı.

Önceki adımlarda muhtemelen keşfedilen IP'ler ve domainler üzerinde zaten bazı **recon** işlemleri yaptınız, dolayısıyla **olası tüm web serverları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi kapsam içinde **web server aramak** için bazı **fast tricks** göreceğiz.

Lütfen bunun **web app discovery** odaklı olacağını unutmayın; bu yüzden **vulnerability** ve **port scanning** işlemlerini de (**kapsam izin veriyorsa**) yapmalısınız.

[**masscan** kullanarak **web** serverlarla ilgili **açık portları** keşfetmek için hızlı bir yöntem burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web server aramak için başka bir kullanışlı araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx)'tir. Sadece bir domain listesi verirsiniz ve 80 (http) ile 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portları da denemesini belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsam içinde bulunan **tüm web sunucularını** (şirketin **IP'leri** ve tüm **domain** ile **subdomain**'leri arasında) keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde işi basitleştirelim ve hepsinin ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya bir göz atarak** daha **garip** ve daha **savunmasız olma ihtimali yüksek** endpoint'ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** kullanabilirsiniz.**

Ayrıca, ardından tüm **ekran görüntüleri** üzerinde çalıştırmak ve size **hangi hedeflerin zafiyet içermesi muhtemel** olduğunu ve hangilerinin olmadığını söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer)'ı da kullanabilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek potansiyel cloud assets bulmak için öncelikle o şirketi tanımlayan **anahtar kelimelerin bir listesinden** başlamalısınız. Örneğin, bir crypto şirketi için `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` gibi kelimeler kullanabilirsiniz.

Ayrıca **bucket'larda kullanılan yaygın kelimelerden** oluşan wordlist'lere de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permütasyonlar** üretmelisiniz (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) kısmına bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken yalnızca **AWS'deki bucket'ları değil daha fazlasını** aramanız gerektiğini unutmayın.

### **Zafiyet Arama**

Eğer **açık bucket'lar** veya **açığa çıkmış cloud function'lar** gibi şeyler bulursanız, bunlara **erişmeli** ve size ne sunduklarını ve bunları kötüye kullanıp kullanamayacağınızı görmeye çalışmalısınız.

## Emails

Kapsam içindeki **domain** ve **subdomain**'lerle, şirketin email'lerini aramaya başlamak için temel olarak ihtiyacınız olan her şeye sahipsiniz. Bir şirketin email'lerini bulmada benim için en iyi çalışan **API'ler** ve **araçlar** şunlardır:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- [**https://hunter.io/**](https://hunter.io/) API'si (ücretsiz sürüm)
- [**https://app.snov.io/**](https://app.snov.io/) API'si (ücretsiz sürüm)
- [**https://minelead.io/**](https://minelead.io/) API'si (ücretsiz sürüm)

### **Zafiyet Arama**

Email'ler daha sonra **web login'lerine ve auth servislerine brute-force uygulamak** için (SSH gibi) işinize yarar. Ayrıca, **phishing** için de gereklidirler. Dahası, bu API'ler size email'in arkasındaki kişi hakkında daha fazla **bilgi** verecektir; bu da phishing kampanyası için faydalıdır.

## Credential Leaks

**Domain'ler**, **subdomain'ler** ve **email'ler** ile, geçmişte bu email'lere ait sızdırılmış credentials aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet Arama**

Eğer **geçerli sızdırılmış** credentials bulursanız, bu çok kolay bir kazanımdır.

## Secrets Leaks

Credential leak'ler, **hassas bilginin sızdırıldığı ve satıldığı** şirket hack'leriyle ilişkilidir. Ancak şirketler, bu veritabanlarında bilgisi bulunmayan **başka leak'lerden** de etkilenebilir:

### Github Leaks

Credentials ve API'ler, **şirketin** ya da o github şirketinde çalışan **kullanıcıların public repository'lerinde** sızmış olabilir.\
**Leakos** aracını kullanarak bir **organizasyonun** ve geliştiricilerinin tüm **public repo'larını** **indirebilir** ve üzerlerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırabilirsiniz.

**Leakos**, ayrıca kendisine verilen tüm **metin** içeren **URL'ler** üzerinde de **gitleaks** çalıştırmak için kullanılabilir; çünkü bazen **web sayfaları da secrets içerir**.

#### Github Dorks

Saldırdığınız organizasyonda arayabileceğiniz olası **github dorks** için bu **sayfaya** da bakın:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar ya da çalışanlar şirket içeriğini bir paste sitesinde **yayınlar**. Bu durum **hassas bilgi** içerebilir ya da içermeyebilir, ancak aramak çok ilginçtir.\
Aynı anda 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki google dorks, orada olmaması gereken **açığa çıkmış bilgileri** bulmak için her zaman faydalıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in manuel olarak çalıştıramayacağınız birkaç **binlerce** olası sorgu içermesidir. Bu yüzden favori 10 tanesini seçebilir ya da hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir **araç** kullanabilirsiniz.

_Not: Google'ın normal tarayıcısını kullanarak tüm veritabanını çalıştırması beklenen araçlar asla tamamlanmaz; çünkü google sizi çok ama çok kısa sürede engelleyecektir._

### **Zafiyet Arama**

Eğer **geçerli sızdırılmış** credentials veya API token'ları bulursanız, bu çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**'a sahip olduğunu keşfettiyseniz, bunu **analiz** edip üzerindeki **zafiyetleri** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca public repository'leri **taramanıza** izin veren ücretsiz servisler de vardır; örneğin:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bug hunter'lar tarafından bulunan **zafiyetlerin çoğu** web uygulamalarının içinde yer alır; bu yüzden bu noktada bir **web application testing methodology**'den bahsetmek istiyorum ve bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özel olarak değinmek istiyorum; çünkü çok hassas zafiyetler bulmalarını beklememeniz gerekse de, **iş akışlarına** entegre edilerek başlangıç seviyesinde web bilgisi elde etmek için oldukça işe yararlar.

## Recapitulation

> Tebrikler! Bu noktada zaten **tüm temel enumeration** işlemlerini tamamlamış oldunuz. Evet, bu temel çünkü çok daha fazla enumeration yapılabilir (ileride daha fazla teknik göreceğiz).

Şimdiye kadar şunları yaptınız:

1. Kapsam içindeki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **asset**'leri buldunuz (ve kapsam içindeyse bir vuln scan yaptınız)
3. Şirketlere ait tüm **domain**'leri buldunuz
4. Domain'lerin tüm **subdomain**'lerini buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP**'leri (CDN'lerden olan ve **olmayan**) buldunuz.
6. Tüm **web sunucularını** buldunuz ve onların bir **screenshot**'ını aldınız (daha derin incelemeye değer garip bir şey var mı?)
7. Şirkete ait olabilecek tüm **potansiyel public cloud assets**'i buldunuz.
8. Çok kolay bir şekilde size **büyük bir kazanım** sağlayabilecek **email**'ler, **credentials leak'leri** ve **secret leak'leri**.
9. Bulduğunuz tüm web'lerde **Pentesting** yaptınız

## **Full Recon Automatic Tools**

Belirli bir kapsam üzerinde önerilen eylemlerin bir kısmını gerçekleştirecek birkaç araç vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix) tarafından sunulan tüm ücretsiz kurslar, örneğin [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
