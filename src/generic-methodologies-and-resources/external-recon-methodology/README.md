# Harici Recon Metodolojisi

{{#include ../../banners/hacktricks-training.md}}

## Varlık keşifleri

> Size bir şirkete ait her şeyin kapsam içinde olduğu söylendi ve bu şirketin aslında nelerin sahibi olduğunu öğrenmek istiyorsunuz.

Bu aşamanın amacı tüm **ana şirket tarafından sahip olunan şirketleri** ve ardından bu şirketlerin tüm **varlıklarını** elde etmektir. Bunu yapmak için şunları yapacağız:

1. Ana şirketin satın almalarını bulun; bu bize kapsam içindeki şirketleri verecektir.
2. Her şirketin (varsa) ASN'sini bulun; bu bize her şirketin sahip olduğu IP aralıklarını verecektir.
3. İlkine bağlı başka kayıtları (organizasyon isimleri, domainler...) aramak için reverse whois lookups kullanın (bu işlem özyinelemeli olarak yapılabilir).
4. Diğer varlıkları aramak için shodan `org`and `ssl`filters gibi diğer teknikleri kullanın (`ssl` hilesi özyinelemeli olarak yapılabilir).

### **Satın Almalar**

İlk olarak, ana şirket tarafından sahip olunan **diğer şirketlerin** hangileri olduğunu bilmemiz gerekiyor.\
Bir seçenek https://www.crunchbase.com/ adresini ziyaret etmek, **ana şirket** için **arama** yapmak ve **"acquisitions"** öğesine **tıklamaktır**. Orada ana şirket tarafından edinilmiş diğer şirketleri göreceksiniz.\
Diğer bir seçenek, ana şirketin **Wikipedia** sayfasını ziyaret edip **satın almalar** için aramaktır.\
Halka açık şirketler için SEC/EDGAR filings, investor relations sayfalarını veya yerel ticaret sicillerini (ör. Birleşik Krallık'ta Companies House) kontrol edin.\
Küresel şirket ağaçları ve bağlı kuruluşlar için **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) ve **GLEIF LEI** veritabanını ([https://www.gleif.org/](https://www.gleif.org/)) deneyin.

> Tamam, bu noktada kapsam içindeki tüm şirketleri biliyor olmalısınız. Şimdi onların varlıklarını nasıl bulacağımızı belirleyelim.

### **ASN'ler**

Özerk sistem numarası (**ASN**), **Internet Assigned Numbers Authority (IANA)** tarafından bir **özerk sisteme** (AS) atanan **benzersiz bir numaradır**.\
Bir **AS**, dış ağlara erişim için belirlenmiş bir politikaya sahip **IP adresi bloklarından** oluşur ve tek bir kuruluş tarafından yönetilir ancak birden fazla operatörden oluşabilir.

Şirketin herhangi bir **ASN** atayıp atamadığını bulmak, onun **IP aralıklarını** tespit etmek için önemlidir. Kapsam içindeki tüm **hosts**'a karşı bir **vulnerability test** gerçekleştirmek ve bu IP'ler içindeki **domain**'leri aramak ilginç olacaktır.\
https://bgp.he.net, https://bgpview.io/ veya https://ipinfo.io/ üzerinde şirket ismine, IP'ye veya domaine göre arama yapabilirsiniz.\
**Şirketin bulunduğu bölgeye bağlı olarak bu linkler daha fazla veri toplamak için faydalı olabilir:** [**AFRINIC**](https://www.afrinic.net) **(Afrika),** [**Arin**](https://www.arin.net/about/welcome/region/) **(Kuzey Amerika),** [**APNIC**](https://www.apnic.net) **(Asya),** [**LACNIC**](https://www.lacnic.net) **(Latin Amerika),** [**RIPE NCC**](https://www.ripe.net) **(Avrupa).** Her neyse, muhtemelen tüm yararlı bilgiler (IP aralıkları ve Whois) zaten ilk linkte görünmektedir.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ayrıca, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration scan sonunda ASNs'i otomatik olarak toplar ve özetler.
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Zafiyet Arama**

Bu noktada kapsam içindeki **tüm varlıkları** biliyoruz, bu yüzden izinliyseniz tüm hostlar üzerinde bazı **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) çalıştırabilirsiniz.\
Ayrıca bazı [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) başlatabilir veya Shodan, Censys ya da ZoomEye gibi servisleri kullanarak açık portları bulabilir ve bulduklarınıza bağlı olarak bu kitapta çalışan çeşitli servisleri nasıl pentest edeceğinize bakmalısınız.\
Ayrıca, bazı varsayılan kullanıcı adı ve parola listeleri hazırlayıp servisleri [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) ile bruteforce etmeyi denemenin de faydalı olacağını belirtmek gerekir.

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_Lütfen, aşağıda önerilen tekniklerle subdomains de bulunabileceğini ve bu bilginin küçümsenmemesi gerektiğini unutmayın._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Bunun çalışması için yöneticinin PTR'yi elle etkinleştirmesi gerekir.\
Bu bilgi için ayrıca çevrimiçi bir araç da kullanabilirsiniz: [http://ptrarchive.com/](http://ptrarchive.com).\
Geniş aralıklar için, reverse lookups ve zenginleştirmeyi otomatikleştirmek amacıyla [**massdns**](https://github.com/blechschmidt/massdns) ve [**dnsx**](https://github.com/projectdiscovery/dnsx) gibi araçlar faydalıdır.

### **Reverse Whois (loop)**

Bir **whois** kaydında **kuruluş adı**, **adres**, **e-postalar**, telefon numaraları gibi birçok ilginç **bilgi** bulabilirsiniz... Ancak daha da ilginci, bu alanların herhangi biriyle **reverse whois lookups** yaparsanız şirkete ait **daha fazla varlık** bulabilirsiniz (örneğin aynı e-postanın göründüğü diğer whois kayıtları).\
Şu çevrimiçi araçları kullanabilirsiniz:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Ücretsiz**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Ücretsiz**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Ücretsiz**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Ücretsiz** web, API ücretli.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Ücretli
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Ücretli (sadece **100 ücretsiz** arama)
- [https://www.domainiq.com/](https://www.domainiq.com) - Ücretli
- [https://securitytrails.com/](https://securitytrails.com/) - Ücretli (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Ücretli (API)

Bu görevi [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key) kullanarak otomatikleştirebilirsiniz.\
Ayrıca [amass](https://github.com/OWASP/Amass) ile bazı otomatik reverse whois keşifleri yapabilirsiniz: `amass intel -d tesla.com -whois`

**Yeni bir domain bulduğunuz her seferinde bu tekniği kullanarak daha fazla domain adı keşfedebileceğinizi unutmayın.**

### **Trackers**

Aynı tracker'ın aynı **ID**'sini iki farklı sayfada bulursanız, **her iki sayfanın** **aynı ekip** tarafından yönetildiğini varsayabilirsiniz.\
Örneğin, birkaç sayfada aynı **Google Analytics ID** veya aynı **Adsense ID** görürseniz.

Bu tracker'lara ve daha fazlasına göre arama yapmanıza izin veren bazı sayfalar ve araçlar şunlardır:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Hedefimizle ilişkili domainleri ve alt alan adlarını aynı favicon ikon hash'ini arayarak bulabileceğinizi biliyor muydunuz? Bu, [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) aracı tarafından [@m4ll0k2](https://twitter.com/m4ll0k2) tarafından yapılan şeydir. İşte nasıl kullanıldığı:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Kısacası, favihash hedefimizle aynı favicon icon hash'e sahip domainleri keşfetmemizi sağlar.

Ayrıca, favicon hash'ini kullanarak teknolojileri arayabilirsiniz; bunun nasıl yapılacağını [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) açıklıyor. Bu, eğer bir web teknolojisinin zayıf bir sürümünün favicon'unun **hash'ini** biliyorsanız, bunu shodan'da arayıp **daha fazla zafiyetli yer** bulabileceğiniz anlamına gelir:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
İşte bir web sitesinin **favicon hash'ini hesaplayabileceğiniz**:
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

### **Copyright / Benzersiz dize**

Web sayfaları içinde **aynı organizasyondaki farklı sitelerde paylaşılabilecek dizeleri** arayın. **copyright dizesi** iyi bir örnek olabilir. Sonra bu dizeyi **google**'da, diğer **tarayıcılarda** veya hatta **shodan**'da arayın: `shodan search http.html:"Copyright string"`

### **CRT Zamanı**

Genellikle şu tür bir cron job bulunur:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
sunucudaki tüm domain sertifikalarını yenilemek için. Bu, kullanılan CA Validity zamanına oluşturulma zamanını koymasa bile, certificate transparency loglarında aynı şirkete ait domainleri bulmanın mümkün olduğu anlamına gelir.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC bilgileri

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Diğer yollar**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Zafiyetleri Arama**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Çok sayıda subdomain elde etmenin en hızlı yolu harici kaynaklarda arama yapmaktır. En çok kullanılan **araçlar** şunlardır (daha iyi sonuç için API anahtarlarını yapılandırın):

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
Doğrudan subdomains bulmaya odaklanmamış olsalar bile subdomains bulmada faydalı olabilecek **diğer ilginç araçlar/API'ler** şunlardır:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io) API'sini kullanarak subdomains elde eder
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
- [**gau**](https://github.com/lc/gau)**:** herhangi bir domain için AlienVault's Open Threat Exchange, the Wayback Machine ve Common Crawl'dan bilinen URL'leri getirir.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Web'i tarayıp JS dosyalarını ararlar ve oradan subdomains çıkarırlar.
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
- [**securitytrails.com**](https://securitytrails.com/) subdomains ve IP geçmişini aramak için ücretsiz bir API sağlar
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Bu proje bug-bounty programs ile ilgili tüm subdomains verilerini ücretsiz sunar. Bu verilere [chaospy](https://github.com/dr-0x0x/chaospy) kullanarak da erişebilir veya bu projenin kullandığı scope'a şu adresten erişebilirsiniz: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Bu araçların birçoğunun bir karşılaştırmasını şurada bulabilirsiniz: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off]

### **DNS Brute force**

Muhtemel subdomain isimlerini kullanarak DNS sunucularına brute-forcing yaparak yeni subdomains bulmaya çalışalım.

Bu işlem için aşağıdaki gibi bazı common subdomains wordlists'e ihtiyacınız olacak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Ayrıca iyi DNS resolver'ların IP'lerine de ihtiyacınız olacak. Güvenilir DNS resolver'larının bir listesini oluşturmak için resolver'ları [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) adresinden indirip bunları filtrelemek için [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) kullanabilirsiniz. Ya da şu listeyi kullanabilirsiniz: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): Bu, etkili bir DNS brute-force gerçekleştiren ilk araçtı. Çok hızlıdır; ancak false positives'e eğilimlidir.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Bence bu sadece 1 resolver kullanıyor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) `massdns` etrafında bir wrapper olup, go ile yazılmıştır; active bruteforce kullanarak geçerli alt alan adlarını enumerate etmenizi ve wildcard handling ile alt alan adlarını resolve etmenizi sağlar; ayrıca kolay input-output desteği sunar.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Ayrıca `massdns` kullanır.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) asyncio kullanarak alan adlarını eşzamansız olarak brute force eder.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### İkinci DNS Brute-Force Turu

Açık kaynaklar ve brute-forcing kullanarak alt alan adlarını bulduktan sonra, bulunan alt alan adlarının varyasyonlarını oluşturarak daha fazlasını bulmayı deneyebilirsiniz. Bu amaç için birkaç araç faydalıdır:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Verilen alan adları ve alt alan adları için permütasyonlar üretir.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Verilen domains ve subdomains için permütasyonlar üretir.
- goaltdns permütasyonları için **wordlist**'i [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) adresinden alabilirsiniz.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Verilen domain ve subdomain'lerden permutations üretir. Eğer bir permutations dosyası belirtilmezse gotator kendi dosyasını kullanır.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations üretmesinin yanı sıra, onları resolve etmeye de çalışabilir (ama önceki bahsedilen araçları kullanmak daha iyidir).
- altdns permutations **wordlist**'ini [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) adresinden alabilirsiniz.
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Subdomains üzerinde permutations, mutations ve alteration gerçekleştirmek için başka bir araç. Bu araç sonucu brute force ile deneyecektir (dns wild card'ı desteklemiyor).
- dmut permutations wordlist'ini [**buradan**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) edinebilirsiniz.
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Bir domaine dayanarak, belirtilen desenlere göre daha fazla subdomain keşfetmeye çalışmak için **yeni potansiyel subdomain isimleri üretir**.

#### Akıllı permutasyon üretimi

- [**regulator**](https://github.com/cramppet/regulator): Daha fazla bilgi için bu [**post**](https://cramppet.github.io/regulator/index.html)u okuyun; ancak temelde **keşfedilmiş subdomains**'lerden **ana parçaları** alır ve bunları karıştırarak daha fazla subdomain bulur.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_, son derece basit ama etkili bir DNS yanıtı yönlendirmeli algoritmayla birleşmiş bir subdomain brute-force fuzzer'ıdır. Sağlanan bir girdi kümesini — örneğin özelleştirilmiş bir wordlist veya geçmiş DNS/TLS kayıtları — kullanarak daha fazla ilgili domain adını doğru şekilde sentezler ve DNS scan sırasında toplanan bilgilere dayanarak bunları bir döngü içinde daha da genişletir.
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Bilgisayarımda bir sürü aracı elle başlatmam gerekmemesi için, bir domain'den subdomain discovery'yi **Trickest workflows** kullanarak nasıl otomatikleştirdiğimi anlattığım bu blog yazısına göz at:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Eğer bir IP adresinde subdomain'lere ait **bir veya birkaç web sayfası** bulduysanız, **o IP'de web barındıran diğer subdomain'leri bulmayı** IP içindeki domain'lere bakmak için **OSINT kaynakları** kullanarak veya **o IP'deki VHost domain isimlerini brute-force ederek** deneyebilirsiniz.

#### OSINT

Bazı **VHosts**'u IP'lerde [**HostHunter**](https://github.com/SpiderLabs/HostHunter) veya diğer API'leri kullanarak bulabilirsiniz.

**Brute Force**

Eğer bazı subdomain'lerin bir web sunucusunda gizlenmiş olabileceğinden şüpheleniyorsanız, onları brute-force ile denemeyi deneyebilirsiniz:
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

Bazen yalnızca geçerli bir domain/subdomain Origin başlığına ayarlandığında _**Access-Control-Allow-Origin**_ başlığını döndüren sayfalar bulabilirsiniz. Bu durumlarda, bu davranışı yeni **subdomains** **keşfetmek** için kötüye kullanabilirsiniz.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

While looking for **subdomains** keep an eye to see if it is **pointing** to any type of **bucket**, and in that case [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Also, as at this point you will know all the domains inside the scope, try to [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

You can **monitor** if **new subdomains** of a domain are created by monitoring the **Certificate Transparency** Logs [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)does.

### **Looking for vulnerabilities**

Check for possible [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
If the **subdomain** is pointing to some **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

If you find any **subdomain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

In the initial steps you might have **found some IP ranges, domains and subdomains**.\
It’s time to **recollect all the IPs from those ranges** and for the **domains/subdomains (DNS queries).**

Using services from the following **free apis** you can also find **previous IPs used by domains and subdomains**. These IPs might still be owned by the client (and might allow you to find [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

You can also check for domains pointing a specific IP address using the tool [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (as you highly probably won’t find anything interested in there). In the running services discovered you might be **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

In the previous steps you have probably already performed some **recon of the IPs and domains discovered**, so you may have **already found all the possible web servers**. However, if you haven't we are now going to see some **fast tricks to search for web servers** inside the scope.

Please, note that this will be **oriented for web apps discovery**, so you should **perform the vulnerability** and **port scanning** also (**if allowed** by the scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Another friendly tool to look for web servers is [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) and [**httpx**](https://github.com/projectdiscovery/httpx). You just pass a list of domains and it will try to connect to port 80 (http) and 443 (https). Additionally, you can indicate to try other ports:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Ekran Görüntüleri**

Artık kapsam içinde bulunan (şirketin **IP'leri** ve tüm **alan adları** ve **alt alan adları** arasında) mevcut **tüm web sunucularını** keşfettiğinize göre muhtemelen **nereden başlayacağınızı bilmiyorsunuz**. O halde basitleştirelim ve hepsinin sadece ekran görüntülerini almaya başlayalım. Sadece **ana sayfaya** bir göz atarak daha **hassas** olabilecek garip endpoint'ler bulabilirsiniz.

Bu fikri uygulamak için [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) veya [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**'i** kullanabilirsiniz.

Ayrıca, tüm **ekran görüntüleri** üzerinde çalışıp size **muhtemelen nerelerin zafiyet içerebileceğini** söyleyecek [**eyeballer**](https://github.com/BishopFox/eyeballer)'ı da kullanabilirsiniz.

## Genel Bulut Varlıkları

Bir şirkete ait potansiyel bulut varlıklarını bulmak için **o şirketi tanımlayan bir anahtar kelime listesiyle başlamalısınız**. Örneğin, bir kripto şirketi için kullanabileceğiniz kelimeler: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Ayrıca **bucket'larda sık kullanılan kelimeler** için wordlist'lere ihtiyacınız olacak:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sonra, bu kelimelerle **permutasyonlar** üretmelisiniz (daha fazla bilgi için [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)'a bakın).

Ortaya çıkan wordlist'lerle [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **veya** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** gibi araçları** kullanabilirsiniz.

Cloud Assets ararken sadece AWS'deki bucket'lara bakmamanız gerektiğini unutmayın.

### **Zafiyet Aramak**

Eğer **open buckets** ya da **cloud functions** gibi dışa açık şeyler bulursanız, onlara **erişmeli**, neler sunduklarını görmeli ve bunları kötüye kullanıp kullanamayacağınızı denemelisiniz.

## E-postalar

Kapsamdaki **alan adları** ve **alt alan adları** ile temelde **e-posta aramaya başlamak için gereken her şeye** sahipsiniz. Bir şirketin e-postalarını bulmak için benim için en iyi çalışan **API'ler** ve **araçlar** şunlardır:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Zafiyet Aramak**

E-postalar sonradan **web girişlerini ve auth servislerini brute-force etmek** (ör. SSH) için kullanışlı olacaktır. Ayrıca **phishings** için gereklidir. Bu API'ler size e-postanın arkasındaki kişi hakkında daha fazla **bilgi** de verir; bu da phishing kampanyası için faydalıdır.

## Credential Leaks

Kapsamdaki **alan adları**, **alt alan adları** ve **e-postalar** ile bu e-postalara ait geçmişte leaked olmuş kimlik bilgilerini aramaya başlayabilirsiniz:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Zafiyet Aramak**

Eğer **geçerli leaked** kimlik bilgileri bulursanız, bu çok kolay bir kazançtır.

## Secrets Leaks

Credential leaks, şirketlerin hacklendiği ve **hassas bilgilerin leaked edilip satıldığı** durumlarla ilgilidir. Ancak, şirketler bu veritabanlarında yer almayan **başka leak'lerden** de etkilenmiş olabilir:

### Github Leaks

Kimlik bilgileri ve API'ler şirketin **public repositories**'inde veya o şirkette çalışan **kullanıcıların** public repo'larında leaked olabilir.\
Tüm bir organizasyonun ve geliştiricilerinin **public repos**larını **download** etmek ve üzerinde otomatik olarak [**gitleaks**](https://github.com/zricethezav/gitleaks) çalıştırmak için **Leakos** [**Leakos**](https://github.com/carlospolop/Leakos) aracını kullanabilirsiniz.

**Leakos**, bazen **web sayfalarında da secret'lar** bulunduğu için kendisine verilen **URL'ler** üzerindeki **text**leri alıp üzerinde **gitleaks** çalıştırmak için de kullanılabilir.

#### Github Dorks

Saldırdığınız organizasyonda arayabileceğiniz potansiyel **github dorks** için şu **sayfayı** de kontrol edin:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Bazen saldırganlar veya sadece çalışanlar şirket içeriğini bir paste sitesinde yayınlarlar. Bu bilgiler hassas olabilir veya olmayabilir, ancak aramaya değerdir.\
Bir seferde 80'den fazla paste sitesinde arama yapmak için [**Pastos**](https://github.com/carlospolop/Pastos) aracını kullanabilirsiniz.

### Google Dorks

Eski ama etkili google dork'lar, **oraya olmaması gereken bilgileri** bulmak için her zaman faydalıdır. Tek sorun, [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)'in binlerce sorgu içermesi ve bunları elle çalıştırmanın mümkün olmamasıdır. Bu yüzden favori 10 sorgunuzu alabilir veya hepsini çalıştırmak için [**Gorks**](https://github.com/carlospolop/Gorks) **gibi bir araç** kullanabilirsiniz.

_Not: düzenli Google tarayıcısını kullanarak tüm veritabanını çalıştırmayı bekleyen araçlar çok kısa sürede Google tarafından engellenecektir._

### **Zafiyet Aramak**

Eğer **geçerli leaked** kimlik bilgileri veya API token'ları bulursanız, bu çok kolay bir kazançtır.

## Public Code Vulnerabilities

Şirketin **open-source code**'u olduğunu tespit ederseniz, bunu **analiz edip** üzerinde **zafiyetler** arayabilirsiniz.

**Dil bazında** kullanabileceğiniz farklı **araçlar** vardır:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Ayrıca public repository'leri **taramanıza** izin veren ücretsiz hizmetler de vardır, örneğin:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

The **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

I also want to do a special mention to the section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), as, if you shouldn't expect them to find you very sensitive vulnerabilities, they come handy to implement them on **workflows to have some initial web information.**

## Özet

> Tebrikler! Bu noktada **tüm temel keşfi** zaten gerçekleştirdiniz. Evet, temel çünkü çok daha fazla keşif yapılabilir (daha sonra daha fazla hile göreceğiz).

Yani zaten:

1. Kapsamdaki tüm **şirketleri** buldunuz
2. Şirketlere ait tüm **varlıkları** buldunuz (ve kapsam dahilindeyse bazı vuln taramaları yaptınız)
3. Şirketlere ait tüm **alan adlarını** buldunuz
4. Alan adlarının tüm **alt alan adlarını** buldunuz (herhangi bir subdomain takeover?)
5. Kapsam içindeki **tüm IP'leri** (CDN'lerden olanlar ve olmayanlar) buldunuz.
6. Tüm **web sunucularını** buldunuz ve bunların **ekran görüntülerini** aldınız (daha derin bakmaya değer garip bir şey var mı?)
7. Şirkete ait tüm potansiyel **public cloud varlıklarını** buldunuz.
8. **E-postalar**, **credential leaks**, ve **secret leaks** — bunlar size **çok kolay bir büyük kazanç** sağlayabilir.
9. Bulduğunuz tüm web'lerin **pentest'ini** yaptınız

## **Tam Otomatik Recon Araçları**

Belirtilen kapsam üzerinde önerilen eylemlerin bir kısmını gerçekleştirecek birkaç araç vardır.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Biraz eski ve güncellenmemiş

## **Referanslar**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
