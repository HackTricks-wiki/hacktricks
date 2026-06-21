# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset keşifleri

> Yani sana, bir şirkete ait olan her şeyin kapsam içinde olduğu söylendi ve sen de bu şirketin gerçekte neleri sahip olduğunu bulmak istiyorsun.

Bu aşamanın amacı, ana şirkete ait tüm **şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için:

1. Ana şirketin satın alımlarını bulacağız, bu bize kapsam içindeki şirketleri verecek.
2. Her şirketin ASN'sini (varsa) bulacağız, bu bize her şirketin sahip olduğu IP aralıklarını verecek
3. İlk kayıtla ilişkili diğer girdileri (organisation names, domains...) aramak için reverse whois lookups kullanacağız (bu işlem özyinelemeli olarak yapılabilir)
4. Diğer varlıkları aramak için shodan `org` ve `ssl` filtreleri gibi başka teknikler kullanacağız (`ssl` hilesi özyinelemeli olarak yapılabilir).

### **Satın almalar**

İlk olarak, ana şirketin sahip olduğu **diğer şirketlerin** hangileri olduğunu bilmemiz gerekiyor.\
Bir seçenek [https://www.crunchbase.com/](https://www.crunchbase.com) sitesini ziyaret etmek, **ana şirketi** **aramak** ve "**acquisitions**" üzerine **tıklamak**. Orada ana şirket tarafından satın alınan diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret etmek ve **acquisitions** aramaktır.\
Halka açık şirketler için **SEC/EDGAR filings**, **investor relations** sayfalarını veya yerel şirket kayıtlarını (ör. Birleşik Krallık'ta **Companies House**) kontrol edin.\
Küresel şirket yapıları ve alt şirketler için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri bilmelisiniz. Şimdi bunların varlıklarını nasıl bulacağımızı anlayalım.

### **ASN'ler**

Bir autonomous system number (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **autonomous system** (AS)'e atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için belirgin şekilde tanımlanmış bir politikaya sahip **IP address** **bloklarından** oluşur ve tek bir organisation tarafından yönetilir, ancak birkaç operatörden oluşabilir.

Şirketin **herhangi bir ASN atayıp atamadığını** bulmak, onun **IP aralıklarını** bulmak için ilginçtir. Kapsam içindeki tüm **host**lara karşı bir **vulnerability test** yapmak ve bu IP'lerin içinde **domain**ler aramak faydalı olacaktır.\
[**https://bgp.he.net/**](https://bgp.he.net), [**https://bgpview.io/**](https://bgpview.io/) veya [**https://ipinfo.io/**](https://ipinfo.io/) içinde şirket **adı**, **IP** veya **domain** ile **arama** yapabilirsiniz.\
Şirketin bölgesine **bağlı olarak**, daha fazla veri toplamak için bu bağlantılar faydalı olabilir: [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** appears already in the first link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'un**
enumeration işlemi, taramanın sonunda ASNs'leri otomatik olarak toplar ve özetler.
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
Kuruluşun IP aralıklarını [http://asnlookup.com/](http://asnlookup.com) kullanarak da bulabilirsiniz (ücretsiz API’si vardır).\
Bir alan adının IP ve ASN’sini [http://ipv4info.com/](http://ipv4info.com) kullanarak bulabilirsiniz.

### **Zafiyetleri aramak**

Bu noktada **kapsam içindeki tüm varlıklara** sahibiz, bu yüzden izin veriliyorsa tüm host’lar üzerinde bir **zafiyet tarayıcısı** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca, [**port taramaları**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapabilir **veya açık portları bulmak için** Shodan, Censys ya da ZoomEye gibi hizmetleri kullanabilirsiniz; **ve bulduklarınıza bağlı olarak** bu kitapta çalışan olası çeşitli servislerin nasıl pentest edileceğine bakmalısınız.\
**Ayrıca, bazı** varsayılan kullanıcı adı **ve** parola **listeleri hazırlayıp** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile servisleri **bruteforce etmeyi** deneyebileceğinizi de belirtmek faydalı olabilir.

## Domainler

> Kapsam içindeki tüm şirketleri ve varlıklarını biliyoruz, şimdi kapsam içindeki domainleri bulma zamanı.

_Aşağıdaki amaçlanan tekniklerde subdomain’leri de bulabileceğinizi ve bu bilginin küçümsenmemesi gerektiğini lütfen unutmayın._

Öncelikle her şirketin **ana domain**(ler)ini aramalısınız. Örneğin, _Tesla Inc._ için bu _tesla.com_ olacaktır.

### **Ters DNS**

Domainlerin tüm IP aralıklarını bulduğunuza göre, kapsam içinde daha fazla domain bulmak için bu **IP’ler üzerinde ters dns sorguları** yapmayı deneyebilirsiniz. Hedefin bazı dns sunucularını veya iyi bilinen dns sunucularını (1.1.1.1, 8.8.8.8) kullanmayı deneyin
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için, yönetici PTR’yi manuel olarak etkinleştirmek zorundadır.\
Bu bilgi için ayrıca çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Büyük aralıklar için, [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar reverse lookup ve enrichment işlemlerini otomatikleştirmek için faydalıdır.

### **Reverse Whois (loop)**

Bir **whois** içinde **organisation name**, **address**, **emails**, telefon numaraları gibi birçok ilginç **information** bulabilirsiniz... Ancak daha da ilginci, bu alanlardan herhangi biriyle **reverse whois lookups** yaparsanız şirketle ilişkili **daha fazla asset** bulabilmenizdir (örneğin aynı email’in göründüğü diğer whois kayıtları).\
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

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink) kullanarak otomatikleştirebilirsiniz (bir whoxy API key gerektirir).\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois keşifleri de yapabilirsiniz: `amass intel -d tesla.com -whois`

**Bu tekniği, her yeni domain bulduğunuzda daha fazla domain name keşfetmek için kullanabileceğinizi unutmayın.**

### **Trackers**

2 farklı sayfada **aynı tracker’ın aynı ID’sini** bulursanız, **her iki sayfanın da aynı team** tarafından **managed** edildiğini varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görürseniz.

Bu tracker’lar ve daha fazlası üzerinden arama yapmanıza izin veren bazı sayfalar ve araçlar vardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (paylaşılan analytics/trackers üzerinden ilişkili siteleri bulur)

### **Favicon**

Aynı favicon ikon hash’ine bakarak hedefimize ait ilişkili domain ve subdomain’leri bulabileceğimizi biliyor muydunuz? Tam olarak [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılan [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı bunu yapar. İşte nasıl kullanılacağı:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - aynı favicon icon hash’e sahip domainleri keşfet](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Basitçe söylemek gerekirse, favihash hedefimizle aynı favicon icon hash’e sahip domainleri keşfetmemizi sağlar.

Ayrıca, [**bu blog postunda**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklandığı gibi favicon hash’i kullanarak teknolojileri de arayabilirsiniz. Bu, eğer bir web tech’in savunmasız bir sürümünün **favicon hash’ini** biliyorsanız, bunu shodan’da aratıp **daha fazla savunmasız yer** bulabileceğiniz anlamına gelir:
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
Ayrıca favicon hash’lerini büyük ölçekte [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) ile elde edebilir ve ardından Shodan/Censys içinde pivot yapabilirsiniz.

### **Copyright / Uniq string**

Web sayfalarının içinde **aynı organizasyondaki farklı web’ler arasında paylaşılabilecek stringler** arayın. **copyright string** iyi bir örnek olabilir. Sonra o string’i **google**’da, diğer **browsers**’larda ve hatta **shodan**’da arayın: `shodan search http.html:"Copyright string"`

### **CRT Time**

`cron job` gibi bir şeyin olması yaygındır, örneğin
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

Bir web sitesi kullanabilirsiniz, örneğin [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) veya [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) gibi bir araç kullanarak **aynı dmarc bilgilerini paylaşan domainleri ve subdomainleri** bulabilirsiniz.\
Diğer yararlı araçlar [**spoofcheck**](https://github.com/BishopFox/spoofcheck) ve [**dmarcian**](https://dmarcian.com/) aracıdır.

### **Passive Takeover**

Görünüşe göre insanların subdomainleri cloud sağlayıcılarına ait IP'lere ataması yaygın ve bir noktada **o IP adresini kaybedip DNS kaydını silmeyi unutuyorlar**. Bu nedenle, bir cloud içinde (Digital Ocean gibi) sadece **bir VM başlatarak** aslında bazı subdomain(s)'leri **ele geçirmiş** olursunuz.

[**Bu yazı**](https://kmsec.uk/blog/passive-takeover/) bunun hakkında bir öykü anlatır ve **DigitalOcean'da bir VM başlatan**, yeni makinenin **IPv4** adresini **alan** ve ona işaret eden subdomain kayıtlarını bulmak için Virustotal'de **arama yapan** bir script önerir.

### **Other ways**

**Dikkat edin, yeni bir domain bulduğunuz her seferinde bu tekniği kullanarak daha fazla domain adı keşfedebilirsiniz.**

**Shodan**

Zaten IP alanını sahip olan organizasyonun adını biliyorsunuz. Bu veriyi shodan'da şöyle arayabilirsiniz: `org:"Tesla, Inc."` Bulunan hostları TLS sertifikasında yeni beklenmeyen domainler için kontrol edin.

Ana web sayfasının **TLS certificate**'ına erişip **Organisation** adını elde edebilir ve sonra bu adı, shodan tarafından bilinen tüm web sayfalarının **TLS certificates** içinde şu filtre ile arayabilirsiniz: `ssl:"Tesla Motors"` veya [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) gibi bir araç kullanabilirsiniz.

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)ana domain ile ilişkili **domainleri** ve onların **subdomainlerini** arayan oldukça etkileyici bir araçtır.

**Passive DNS / Historical DNS**

Passive DNS verisi, hâlâ çözümlenen veya ele geçirilebilecek **eski ve unutulmuş kayıtları** bulmak için çok iyidir. Şunlara bakın:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Bazı [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) durumlarını kontrol edin. Belki bir şirket **bir domain kullanıyordur** ama **sahipliğini kaybetmiştir**. Sadece onu kaydedin (yeterince ucuzsa) ve şirketi bilgilendirin.

Eğer varlık keşfinde zaten bulduğunuzlardan **farklı bir IP'ye sahip herhangi bir domain** bulursanız, bir **temel vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bazı [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) işlemleri yapmalısınız. Çalışan servislere bağlı olarak bu kitapta onları "saldırmak" için bazı taktikler bulabilirsiniz.\
_Not: Bazen domain, istemci tarafından kontrol edilmeyen bir IP içinde barındırılır, bu yüzden kapsam dışında olabilir, dikkatli olun._

## Subdomains

> Kapsamdaki tüm şirketleri, her şirketin tüm varlıklarını ve şirketlerle ilişkili tüm domainleri biliyoruz.

Şimdi bulunan her domainin mümkün olan tüm subdomainlerini bulma zamanı.

> [!TIP]
> Domainleri bulmak için kullanılan bazı araçlar ve teknikler subdomainleri bulmaya da yardımcı olabilir

### **DNS**

**DNS** kayıtlarından **subdomains** almaya çalışalım. Ayrıca **Zone Transfer** için de denemeliyiz (Eğer zafiyetliyse, bunu rapor etmelisiniz).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu external sources içinde arama yapmaktır. En çok kullanılan **tools** şunlardır (daha iyi sonuçlar için API keys yapılandırın):

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
Bulmak için doğrudan alt alan adlarını bulmaya uzmanlaşmamış olsalar bile, alt alan adlarını bulmada faydalı olabilecek **başka ilginç tools/APIs** da vardır, örneğin:

- [**IP.THC.ORG**](https://ip.thc.org) free API
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
- [**gau**](https://github.com/lc/gau)**:** herhangi bir verilen domain için AlienVault's Open Threat Exchange, the Wayback Machine ve Common Crawl'dan bilinen URL'leri çeker.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i JS dosyaları aramak için tararlar ve oradan subdomain’leri çıkarırlar.
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
- [**securitytrails.com**](https://securitytrails.com/) alt alan adları ve IP geçmişini aramak için ücretsiz bir API’ye sahiptir
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje, **bug-bounty programlarıyla ilişkili tüm alt alan adlarını ücretsiz** olarak sunar. Bu veriye ayrıca [chaospy](https://github.com/dr-0x0x/chaospy) ile erişebilir veya bu projenin kullandığı kapsamı [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) üzerinden görebilirsiniz

Bu araçların çoğunun bir **karşılaştırmasını** burada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Olası alt alan adı isimlerini kullanarak DNS sunucularına brute-force uygulayıp yeni **alt alan adları** bulmaya çalışalım.

Bu işlem için bazı **yaygın alt alan adı wordlist’lerine** ihtiyacınız olacak, örneğin:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS çözücülerinin IP’lerine de ihtiyacınız olacak. Güvenilir bir DNS çözücü listesi oluşturmak için çözücüleri [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden indirebilir ve bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şunu kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force için en çok önerilen araçlar:

- [**massdns**](https://github.com/blechschmidt/massdns): Etkili bir DNS brute-force gerçekleştiren ilk araç buydu. Çok hızlıdır ancak false positive üretmeye yatkındır.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bence bu yalnızca 1 resolver kullanıyor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns), `massdns` etrafında yazılmış, go ile geliştirilen bir wrapper’dır; aktif bruteforce kullanarak geçerli subdomain’leri enumerate etmenize, ayrıca wildcard handling ile subdomain’leri resolve etmenize ve kolay input-output desteği kullanmanıza olanak tanır.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio kullanarak alan adlarını asenkron şekilde brute force eder.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynaklar ve brute-forcing kullanarak subdomain'leri bulduktan sonra, daha da fazlasını bulmaya çalışmak için bulunan subdomain'lerin varyasyonlarını oluşturabilirsiniz. Bu amaç için birkaç araç kullanışlıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen domain ve subdomain'lerden permütasyonlar üretir.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domainler ve alt domainler için permütasyonlar oluşturur.
- [**goaltdns**] için permütasyon **wordlist**ini [**buradan**](https://github.com/subfinder/goaltdns/blob/master/words.txt) alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domainler ve subdomainler ile permutations oluşturur. Eğer permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Alt alan adı permütasyonları üretmenin yanı sıra, bunları çözümlemeyi de deneyebilir (ancak önceki yorum satırıyla belirtilen araçları kullanmak daha iyidir).
- altdns permütasyon **wordlist**’ini [**buradan**](https://github.com/infosec-au/altdns/blob/master/words.txt) alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Alt alan adları üzerinde permütasyon, mutasyon ve değişiklikler gerçekleştirmek için başka bir araç. Bu araç sonucu brute force ile dener (dns wild card desteklemez).
- dmut permütasyon kelime listesini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) alabilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domain'e dayanarak belirtilen kalıplara göre **yeni potansiyel subdomain adları** üretir ve daha fazla subdomain keşfetmeye çalışır.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**post**](https://cramppet.github.io/regulator/index.html)u okuyun; temelde **keşfedilen subdomain**lerden **ana parçaları** alır ve daha fazla subdomain bulmak için bunları birbiriyle karıştırır.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ bir alt alan adı brute-force fuzzer’ıdır ve son derece basit ama etkili bir DNS yanıtı yönlendirmeli algoritma ile birlikte çalışır. DNS taraması sırasında toplanan bilgilere dayanarak, sağlanan bir giriş veri kümesini — örneğin özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları — kullanır; böylece daha fazla karşılık gelen alan adı üretir ve bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Bir domainden **subdomain discovery** işlemini **Trickest workflows** kullanarak nasıl **otomatikleştireceğim** hakkında yazdığım bu blog yazısına göz atın; böylece bilgisayarımda bir sürü aracı elle çalıştırmam gerekmiyor:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Eğer subdomain'lere ait **bir veya birkaç web page** içeren bir IP address bulduysanız, **o IP'deki webs** için **başka subdomain'leri bulmayı** deneyebilirsiniz; bunu **OSINT sources** içinde bir IP'deki domain'lere bakarak veya o IP'de **VHost domain names brute-force** ederek yapabilirsiniz.

#### OSINT

Bazı **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs** ile bulabilirsiniz.

**Brute Force**

Eğer bazı subdomain'lerin bir web server içinde gizlenmiş olabileceğinden şüpheleniyorsanız, brute force etmeyi deneyebilirsiniz:

**IP bir hostname'e redirect ediyorsa** (name-based vhosts), `Host` header'ını doğrudan fuzz edin ve ffuf'un default vhost'tan farklı yanıtları öne çıkarması için **auto-calibrate** etmesine izin verin:
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
> Bu teknikle bazen internal/hidden endpoint'lere bile erişebilirsiniz.

### **CORS Brute Force**

Bazen, yalnızca _**Origin**_ header'ında geçerli bir domain/subdomain ayarlandığında _**Access-Control-Allow-Origin**_ header'ını döndüren sayfalar bulursunuz. Bu senaryolarda, bu davranışı kötüye kullanarak yeni **subdomain**'leri **discover** edebilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomain**ları araştırırken herhangi bir **bucket** türüne işaret edip etmediğine dikkat edin; böyle bir durumda [**permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**'ı kontrol edin.**\
Ayrıca, bu noktada scope içindeki tüm domainleri biliyor olacağınız için, olası bucket isimlerine karşı [**brute force** deneyip **permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) kontrol edin.

### **Monitorization**

Bir domainin **yeni subdomain**lerinin oluşturulup oluşturulmadığını, **Certificate Transparency** Loglarını izleyerek **monitor** edebilirsiniz; bunu [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) yapar.

### **Looking for vulnerabilities**

Olası [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) için kontrol edin.\
Eğer **subdomain** bir **S3 bucket**'a işaret ediyorsa, [**permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)'ı kontrol edin.

Eğer asset discovery sırasında bulduğunuzlardan **farklı IP**'ye sahip bir **subdomain** bulursanız, bir **basic vulnerability scan** (Nessus veya OpenVAS kullanarak) ve **nmap/masscan/shodan** ile bir [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) yapmalısınız. Çalışan servislere bağlı olarak, **bu kitapta** onları "saldırmak" için bazı taktikler bulabilirsiniz.\
_Not: bazen subdomain, client tarafından kontrol edilmeyen bir IP üzerinde host edilir; yani scope içinde değildir, dikkatli olun._

## IPs

Başlangıç adımlarında bazı **IP aralıkları, domainler ve subdomainler** bulmuş olabilirsiniz.\
Şimdi o aralıklardaki tüm **IP'leri** ve **domain/subdomain**ler için (**DNS queries**) yeniden toplama zamanı.

Aşağıdaki **free apis** servislerini kullanarak domainler ve subdomainler tarafından daha önce kullanılan **IP'leri** de bulabilirsiniz. Bu IP'ler hâlâ client'a ait olabilir (ve [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) bulmanızı sağlayabilir)

- [**https://securitytrails.com/**](https://securitytrails.com/)

Ayrıca [**hakip2host**](https://github.com/hakluke/hakip2host) aracını kullanarak belirli bir IP adresine işaret eden domainleri de kontrol edebilirsiniz.

### **Looking for vulnerabilities**

CDN'lere ait olmayan tüm **IP**'lerde **port scan** yapın (çünkü orada ilginç bir şey bulmanız büyük olasılıkla beklenmez). Tespit edilen çalışan servislerde **vulnerabilities** bulabilirsiniz.

**Host'ları nasıl tarayacağınıza dair bir** [**guide**](../pentesting-network/index.html) **bulun.**

## Web servers hunting

> Scope içindeki tüm şirketleri ve asset'leri bulduk; IP aralıklarını, domainleri ve subdomainleri biliyoruz. Artık web server'ları arama zamanı.

Önceki adımlarda muhtemelen zaten keşfedilen IP ve domainler üzerinde bazı **recon** işlemleri yaptınız; dolayısıyla **olası tüm web server'ları** zaten bulmuş olabilirsiniz. Ancak bulmadıysanız, şimdi scope içinde **web server aramak için bazı hızlı taktikler** göreceğiz.

Lütfen bunun **web app keşfine yönelik** olduğunu unutmayın; bu yüzden (**scope izin veriyorsa**) **vulnerability** ve **port scanning** de yapmalısınız.

[**masscan** kullanarak web server'larla ilgili **açık portları** keşfetmek için hızlı bir yöntem burada bulunabilir](../pentesting-network/index.html#http-port-discovery).\
Web server aramak için bir başka kullanışlı araç [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) ve [**httpx**](https://github.com/projectdiscovery/httpx). Sadece bir domain listesi verirsiniz ve bu araç 80 (http) ve 443 (https) portlarına bağlanmayı dener. Ayrıca, başka portları da denemesini belirtebilirsiniz:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsam içinde bulunan **tüm web sunucularını** keşfettiğinize göre (şirketin **IP’leri** ve tüm **domain** ve **subdomain**’leri arasında) muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde bunu basitleştirelim ve hepsinin sadece ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya bir göz atarak** daha **garip** ve daha **savunmasız olma ihtimali yüksek** endpoint’ler bulabilirsiniz.

Önerilen fikri uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ayrıca, ardından tüm **ekran görüntüleri** üzerinde çalıştırıp size **hangilerinin zafiyet içermesi muhtemel olduğunu** ve hangilerinin olmadığını söylemesi için [**eyeballer**](https://github.com/BishopFox/eyeballer)’ı kullanabilirsiniz.

## Public Cloud Assets

Bir şirkete ait olabilecek potansiyel cloud varlıklarını bulmak için önce o şirketi tanımlayan **anahtar kelimelerin bir listesini** oluşturmalısınız. Örneğin, bir crypto şirketi için şu kelimeleri kullanabilirsiniz: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca buckets içinde kullanılan **yaygın kelimelerin wordlist’lerine** de ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permutations** üretmelisiniz (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)’a bakın).

Ortaya çıkan wordlist’lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları kullanabilirsiniz.**

Cloud Assets ararken sadece AWS’deki buckets’lara değil, **daha fazlasına bakmanız gerektiğini** unutmayın.

### **Zafiyet Arama**

**Açık buckets** veya **ifşa edilmiş cloud functions** gibi şeyler bulursanız, bunlara **erişmeli** ve size neler sunduklarını görmeye çalışmalı, bunları kötüye kullanıp kullanamayacağınızı denemelisiniz.

## Emails

Kapsam içindeki **domain** ve **subdomain**’lerle birlikte, temelde **email aramaya başlamak için ihtiyacınız olan her şeye** sahipsiniz. Bir şirketin email’lerini bulmak için benim için en iyi çalışan **APIs** ve **araçlar** şunlar:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Zafiyet Arama**

Email’ler daha sonra **web girişlerini ve auth servislerini** (SSH gibi) **brute-force etmek** için kullanışlı olacaktır. Ayrıca, **phishing** için de gereklidirler. Dahası, bu APIs size email’in arkasındaki kişi hakkında daha da fazla **bilgi** verecektir; bu da phishing kampanyası için faydalıdır.

## Credential Leaks

**Domain**, **subdomain** ve **email**’lerle, geçmişte o email’lere ait sızdırılmış credentials aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet Arama**

Eğer **geçerli sızdırılmış** credentials bulursanız, bu çok kolay bir kazanımdır.

## Secrets Leaks

Credential leak’leri, **hassas bilginin sızdırılıp satıldığı** şirket hack’leriyle ilişkilidir. Ancak şirketler, bilgisi bu veritabanlarında olmayan **başka leak’lerden** de etkilenmiş olabilir:

### Github Leaks

Credentials ve APIs, **şirketin** veya o github şirketinde çalışan **kullanıcıların public repository**’lerinde sızmış olabilir.\
Bir organizasyonun ve geliştiricilerinin tüm **public repos**’larını **indirmek** ve üzerlerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için [**Leakos**](https://github.com/carlospolop/Leakos) **aracını** kullanabilirsiniz.

**Leakos**, bazen **web sayfaları da secrets içerdiğinden**, kendisine verilen tüm **metin** tabanlı **URL’ler** üzerinde de **gitleaks** çalıştırmak için kullanılabilir.

#### Github Dorks

Saldırdığınız organizasyonda ayrıca arayabileceğiniz potansiyel **github dorks** için bu **sayfayı** da kontrol edin:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar ya da çalışanlar şirket içeriğini bir paste sitesinde **yayınlayabilir**. Bu, **hassas bilgi** içerebilir de içermeyebilir de, ancak bunu aramak çok ilginçtir.\
Aynı anda 80’den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama altın değerindeki google dorks, olmaması gereken **ifşa edilmiş bilgileri** bulmak için her zaman kullanışlıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)’in manuel olarak çalıştırılamayacak kadar çok, **binlerce** olası sorgu içermesidir. Bu yüzden en sevdiğiniz 10 tanesini seçebilir ya da hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) gibi bir **araç** kullanabilirsiniz.

_Not: Veritabanının tamamını normal Google tarayıcısıyla çalıştırması beklenen araçlar asla bitmeyecektir; çünkü Google sizi çok ama çok kısa sürede engelleyecektir._

### **Zafiyet Arama**

Eğer **geçerli sızdırılmış** credentials veya API token’ları bulursanız, bu çok kolay bir kazanımdır.

## Public Code Vulnerabilities

Şirketin **open-source code**’u olduğunu fark ederseniz, bunu **analiz** edip üzerindeki **zafiyetleri** arayabilirsiniz.

**Dile bağlı olarak** kullanabileceğiniz farklı **araçlar** vardır:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca public repository’leri **taramanıza** izin veren ücretsiz servisler de vardır, örneğin:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

Bulunan **zafiyetlerin çoğu**, bug hunter’ların bulduğu şeyler, **web uygulamalarının** içindedir; bu yüzden bu noktada bir **web uygulaması test metodolojisinden** bahsetmek istiyorum ve bu bilgiyi [**burada bulabilirsiniz**](../../network-services-pentesting/pentesting-web/index.html).

Ayrıca [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) bölümüne özel olarak değinmek istiyorum; çünkü çok hassas zafiyetler bulmalarını beklememelisiniz, ancak bazı ilk web bilgilerini elde etmek için bunları **iş akışlarına** eklemek kullanışlıdır.

## Recapitulation

> Tebrikler! Bu noktada zaten **tüm temel enumeration** işlemini yapmış oldunuz. Evet, bunun temel olmasının nedeni, çok daha fazla enumeration yapılabilmesidir (ileride daha fazla numara göreceğiz).

Yani artık şunları yaptınız:

1. Kapsam içindeki tüm **companies**’i buldunuz
2. Şirketlere ait tüm **assets**’leri buldunuz (ve kapsam dahilindeyse bazı vuln scan işlemleri yaptınız)
3. Şirketlere ait tüm **domain**’leri buldunuz
4. Domain’lerin tüm **subdomain**’lerini buldunuz (herhangi bir subdomain takeover var mı?)
5. Kapsam içindeki tüm **IP**’leri (CDN’lerden olan ve **olmayan**) buldunuz.
6. Tüm **web sunucularını** buldunuz ve onların bir **screenshot**’ını aldınız (daha derin bakmaya değer garip bir şey var mı?)
7. Şirkete ait olabilecek tüm **potansiyel public cloud assets**’leri buldunuz.
8. Size çok kolay bir şekilde **büyük bir kazanç** sağlayabilecek **Emails**, **credentials leaks** ve **secret leaks**.
9. Bulduğunuz tüm webs üzerinde **Pentesting** yaptınız

## **Full Recon Automatic Tools**

Belirli bir kapsam karşısında önerilen eylemlerin bir kısmını gerçekleştirecek birçok araç vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmiyor

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix) tarafından verilen tüm ücretsiz kurslar, örneğin [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
