# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano ci, że wszystko należące do pewnej firmy jest w zakresie, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. Aby to zrobić, zamierzamy:

1. Znaleźć przejęcia głównej firmy — to pokaże nam firmy objęte zakresem.
2. Znaleźć ASN (jeśli istnieje) każdej firmy — to da nam zakresy IP należące do każdej firmy.
3. Użyć reverse whois lookups, aby wyszukać inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszą — można to robić rekurencyjnie.
4. Użyć innych technik, jak shodan `org` i `ssl` filtry, aby wyszukać inne zasoby (sztuczka z `ssl` może być wykonywana rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy wiedzieć, które **inne firmy należą do głównej firmy**.\
Jedną opcją jest odwiedzić [https://www.crunchbase.com/](https://www.crunchbase.com/), **wyszukać** **główną firmę**, i **kliknąć** na "acquisitions". Tam zobaczysz inne firmy przejęte przez główną.\
Inną opcją jest odwiedzić stronę **Wikipedia** głównej firmy i wyszukać **acquisitions**.\
Dla spółek publicznych sprawdź zgłoszenia **SEC/EDGAR**, strony **investor relations**, lub lokalne rejestry korporacyjne (np. **Companies House** w UK).\
Dla globalnych drzew korporacyjnych i spółek zależnych wypróbuj **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazę **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, na tym etapie powinieneś znać wszystkie firmy objęte zakresem. Zobaczmy, jak znaleźć ich zasoby.

### **ASNs**

Autonomous System Number (**ASN**) to unikalny numer przypisany systemowi autonomicznemu (**AS**) przez Internet Assigned Numbers Authority (IANA).\
AS składa się z bloków adresów IP, które mają jasno określoną politykę dostępu do sieci zewnętrznych i są zarządzane przez jedną organizację, choć mogą być obsługiwane przez kilku operatorów.

Warto sprawdzić, czy firma ma przypisane jakieś **ASN**, aby znaleźć jej **zakresy IP**. Przydatne będzie przeprowadzenie **vulnerability test** przeciwko wszystkim hostom w obrębie zakresu i poszukiwanie domen przypisanych do tych adresów IP.\
Możesz **wyszukiwać** po nazwie firmy, po IP lub po domenie na [https://bgp.he.net/](https://bgp.he.net/), [https://bgpview.io/](https://bgpview.io/) lub [https://ipinfo.io/](https://ipinfo.io/).\
**W zależności od regionu firmy te linki mogą być przydatne do zebrania dodatkowych danych:** [**AFRINIC**](https://www.afrinic.net) (Afryka), [**Arin**](https://www.arin.net/about/welcome/region/) (Ameryka Północna), [**APNIC**](https://www.apnic.net) (Azja), [**LACNIC**](https://www.lacnic.net) (Ameryka Łacińska), [**RIPE NCC**](https://www.ripe.net) (Europa). W każdym razie prawdopodobnie wszystkie **przydatne informacje (zakresy IP i Whois)** pojawiają się już w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ponadto enumeracja [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatycznie agreguje i podsumowuje ASNs na końcu skanowania.
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
Możesz znaleźć zakresy IP organizacji również używając [http://asnlookup.com/](http://asnlookup.com) (ma darmowe API).\
Możesz znaleźć IP i ASN domeny używając [http://ipv4info.com/](http://ipv4info.com).

### **Szukając podatności**

W tym momencie znamy **wszystkie zasoby w zakresie**, więc jeśli masz pozwolenie możesz uruchomić jakiś **skaner podatności** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Możesz też uruchomić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub użyć usług takich jak** Shodan, Censys, czy ZoomEye **aby znaleźć** otwarte porty **i w zależności od tego, co znajdziesz powinieneś** zajrzeć do tej książki, aby dowiedzieć się, jak pentestować różne możliwe działające usługi.\
**Warto też wspomnieć, że możesz przygotować** listy domyślnych username **i** passwords **i spróbować** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy wszystkie firmy w zakresie i ich zasoby, czas znaleźć domeny w zakresie.

_Proszę zauważyć, że w poniższych proponowanych technikach możesz także znaleźć subdomeny i ta informacja nie powinna być lekceważona._

Przede wszystkim powinieneś poszukać **głównej domeny** każdej firmy. Na przykład dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Po znalezieniu wszystkich zakresów IP domen możesz spróbować wykonać **reverse dns lookups** na tych **IPs, aby znaleźć więcej domen w zakresie**. Spróbuj użyć serwera dns ofiary lub jakiegoś dobrze znanego serwera dns (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
Możesz też użyć narzędzia online dla tych informacji: [http://ptrarchive.com/](http://ptrarchive.com).\
Dla dużych zakresów przydatne są narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) do automatyzacji reverse lookups i wzbogacania danych.

### **Reverse Whois (loop)**

W obrębie **whois** można znaleźć wiele interesujących **informacji** takich jak **nazwa organizacji**, **adres**, **emaile**, numery telefonów... Jeszcze ciekawsze jest to, że wykonując **reverse whois lookups po któregokolwiek z tych pól** (np. inne whoisy, gdzie pojawia się ten sam email) możesz znaleźć **więcej zasobów powiązanych z firmą**.\
Możesz użyć narzędzi online takich jak:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Darmowe**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Darmowe**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Darmowe**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Darmowe** web, API płatne.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Płatne
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Płatne (tylko **100 darmowych** wyszukań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Płatne
- [https://securitytrails.com/](https://securitytrails.com/) - Płatne (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Płatne (API)

Zadanie to możesz zautomatyzować używając [**DomLink** ](https://github.com/vysecurity/DomLink) (wymaga whoxy API key).\
Możesz też wykonać automatyczne odkrywanie reverse whois za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Zauważ, że możesz użyć tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackery**

Jeżeli znajdziesz ten **sam ID tego samego trackera** na 2 różnych stronach, możesz przypuszczać, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli widzisz ten sam **Google Analytics ID** lub ten sam **Adsense ID** na kilku stronach.

Istnieją strony i narzędzia, które pozwalają wyszukiwać po tych trackerach i nie tylko:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (znajduje powiązane strony przez współdzielone analytics/trackery)

### **Favicon**

Czy wiedziałeś, że można znaleźć powiązane domeny i subdomeny naszego celu, szukając tego samego hash'a ikony favicon? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) autorstwa [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go użyć:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - odkryj domeny z tym samym hashem ikony favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Prościej mówiąc, favihash pozwoli nam odkryć domeny, które mają ten sam hash ikony favicon co nasz cel.

Ponadto możesz także przeszukiwać technologie przy użyciu hasha favicon, jak wyjaśniono w [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To oznacza, że jeśli znasz **hash favicon podatnej wersji technologii webowej** możesz wyszukać go w shodan i **znaleźć więcej podatnych miejsc**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Oto jak możesz **obliczyć favicon hash** strony WWW:
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
Możesz też pobrać favicon hashes na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i potem pivot w Shodan/Censys.

### **Copyright / Uniq string**

Szukaj na stronach internetowych **ciągów, które mogą być współdzielone między różnymi stronami tej samej organizacji**. **Copyright string** może być dobrym przykładem. Następnie wyszukaj ten ciąg w **google**, w innych **przeglądarkach** lub nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się cron job taki jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
odnowić wszystkie certyfikaty domen na serwerze. Oznacza to, że nawet jeśli CA użyte do tego nie ustawia czasu wygenerowania w Validity time, możliwe jest **znaleźć domeny należące do tej samej firmy w certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje o DMARC w poczcie

Możesz użyć strony takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), żeby znaleźć **domeny i subdomeny dzielące te same informacje DMARC**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Wygląda na to, że często ludzie przypisują subdomeny do adresów IP należących do cloud providerów i w pewnym momencie **tracą ten adres IP, ale zapominają usunąć rekord DNS**. W związku z tym, po prostu **uruchamiając VM** w chmurze (np. DigitalOcean) faktycznie możesz **przejąć niektóre subdomeny**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) opisuje historię na ten temat i proponuje skrypt, który **spawns a VM in DigitalOcean**, **pobiera** **IPv4** nowej maszyny i **wyszukuje w Virustotal rekordy subdomen** wskazujące na nią.

### **Other ways**

**Zauważ, że możesz wykorzystać tę technikę, aby odkryć więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Ponieważ znasz już nazwę organizacji będącej właścicielem przestrzeni IP, możesz wyszukać po tej informacji w shodan używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w TLS certificate.

Możesz uzyskać dostęp do **TLS certificate** głównej strony, pozyskać **Organisation name**, a następnie wyszukać tę nazwę w **TLS certificates** wszystkich stron znanych przez **shodan** za pomocą filtra: `ssl:"Tesla Motors"` lub użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) to narzędzie, które wyszukuje **domeny powiązane** z główną domeną oraz ich **subdomeny**, całkiem przydatne.

**Passive DNS / Historical DNS**

Dane Passive DNS są świetne do znalezienia **starych i zapomnianych rekordów**, które nadal rozwiązują się lub które można przejąć. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Sprawdź pod kątem [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa jakiejś domeny**, ale **straciła jej własność**. Po prostu ją zarejestruj (jeśli wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz jakąkolwiek **domenę z IP różnym** od tych, które już znalazłeś podczas discovery assets, powinieneś przeprowadzić **basic vulnerability scan** (używając Nessus lub OpenVAS) oraz wykonć [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> Znamy wszystkie firmy objęte zakresem, wszystkie zasoby każdej firmy i wszystkie domeny powiązane z tymi firmami.

Czas znaleźć wszystkie możliwe subdomeny każdej znalezionej domeny.

> [!TIP]
> Zwróć uwagę, że niektóre narzędzia i techniki do znajdowania domen mogą także pomóc w znajdowaniu subdomen

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy także spróbować **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najszybszym sposobem na uzyskanie wielu subdomains jest przeszukiwanie źródeł zewnętrznych. Najczęściej używane **tools** to następujące (dla lepszych rezultatów skonfiguruj API keys):

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
Istnieją **inne interesujące narzędzia/APIs**, które, nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomains, mogą być przydatne przy znajdowaniu subdomains, takie jak:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do pozyskiwania subdomains
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC darmowe API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) darmowe API
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
- [**gau**](https://github.com/lc/gau)**:** pobiera znane adresy URL z AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl dla dowolnej domeny.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Przeszukują sieć w poszukiwaniu plików JS i wyodrębniają z nich subdomeny.
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
- [**securitytrails.com**](https://securitytrails.com/) ma darmowe API do wyszukiwania subdomains i historii IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ten projekt oferuje za **free wszystkie subdomains związane z bug-bounty programs**. Możesz uzyskać dostęp do tych danych również za pomocą [chaospy](https://github.com/dr-0x0x/chaospy) lub nawet uzyskać dostęp do scope użytego przez ten projekt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Możesz znaleźć **porównanie** wielu z tych narzędzi tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Let's try to find new **subdomains** brute-forcing DNS servers using possible subdomain names.

Do tej akcji będziesz potrzebować kilku **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

A także IP dobrych resolverów DNS. Aby wygenerować listę zaufanych DNS resolverów możesz pobrać resolvery z [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich przefiltrowania. Albo możesz użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej rekomendowane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To było pierwsze narzędzie, które przeprowadziło efektywne DNS brute-force. Jest bardzo szybkie, jednak podatne na fałszywe pozytywy.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ten, jak sądzę, używa tylko 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) jest wrapperem wokół `massdns`, napisanym w go, który pozwala enumerować prawidłowe subdomeny przy użyciu active bruteforce, a także rozwiązywać subdomeny z obsługą wildcard oraz łatwym wsparciem wejścia/wyjścia.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa także `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do brute force'owania nazw domen asynchronicznie.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS brute-force

Po znalezieniu subdomen przy użyciu otwartych źródeł i brute-forcingu, możesz wygenerować modyfikacje znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Kilka narzędzi jest przydatnych w tym celu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na podstawie domen i subdomen generuje permutacje.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dla podanych domains i subdomains generuje permutacje.
- Możesz pobrać goaltdns permutations **wordlist** tutaj: [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Generuje permutacje dla podanych domen i subdomen. Jeśli nie wskazano pliku permutacji, gotator użyje własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen, może także próbować je rozwiązać (ale lepiej użyć wcześniej wspomnianych narzędzi).
- Możesz pobrać **wordlist** permutacji altdns [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutations, mutations and alteration of subdomains. To narzędzie będzie brute force'ować wynik (nie obsługuje dns wild card).
- Możesz pobrać dmut permutations wordlist w [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domain **generuje nowe potencjalne subdomains** w oparciu o wskazane wzorce, aby spróbować odkryć więcej subdomains.

#### Generowanie inteligentnych permutacji

- [**regulator**](https://github.com/cramppet/regulator): Więcej informacji znajdziesz w tym [**post**](https://cramppet.github.io/regulator/index.html), ale w zasadzie pobierze **główne części** z **odkrytych subdomains** i wymiesza je, aby znaleźć więcej subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to subdomain brute-force fuzzer połączony z niezwykle prostym, ale skutecznym algorytmem sterowanym odpowiedziami DNS. Wykorzystuje dostarczony zestaw danych wejściowych, takich jak dopasowany wordlist lub historyczne DNS/TLS records, aby precyzyjnie generować więcej odpowiadających nazw domen i dalej je rozszerzać w pętli na podstawie informacji zebranych podczas DNS scan.
```
echo www | subzuf facebook.com
```
### **Przepływ pracy Subdomain Discovery**

Sprawdź ten wpis na blogu, który napisałem o tym, jak **automate the subdomain discovery** z domeny, używając **Trickest workflows**, dzięki czemu nie muszę ręcznie uruchamiać wielu narzędzi na moim komputerze:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron WWW** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z serwisami na tym IP** przeszukując **OSINT sources** w poszukiwaniu domen w danym IP lub przez **brute-forcing VHost domain names in that IP**.

#### OSINT

Możesz znaleźć niektóre **VHosts w adresach IP używając** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze WWW, możesz spróbować ją brute force'ować:

Kiedy **IP redirects to a hostname** (name-based vhosts), fuzzuj nagłówek `Host` bezpośrednio i pozwól ffuf **auto-calibrate** aby wyróżnić odpowiedzi, które różnią się od domyślnego vhosta:
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
> Dzięki tej technice możesz nawet uzyskać dostęp do wewnętrznych/ukrytych endpoints.

### **CORS Brute Force**

Czasami natrafisz na strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/poddomena. W takich scenariuszach możesz wykorzystać to zachowanie, aby **odkryć** nowe **poddomeny**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Podczas poszukiwań **subdomains** zwróć uwagę, czy **wskazuje** na jakiś rodzaj **bucket**, i w takim przypadku [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Również, gdy w tym momencie będziesz znać wszystkie domeny w scope, spróbuj [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Możesz **monitorować**, czy tworzone są **new subdomains** danej domeny, obserwując **Certificate Transparency** Logs, co robi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Sprawdź możliwe [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomain** wskazuje na jakiś **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz jakikolwiek **subdomain with an IP different** od tych, które już znalazłeś podczas assets discovery, powinieneś przeprowadzić **basic vulnerability scan** (używając Nessus lub OpenVAS) oraz jakiś [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **this book some tricks to "attack" them**.\
_Uwaga: czasami subdomain jest hostowane na IP, które nie jest kontrolowane przez klienta, więc nie należy do scope — bądź ostrożny._

## IPs

W początkowych krokach mogłeś znaleźć **some IP ranges, domains and subdomains**.\
Czas **zebrać wszystkie IP z tych zakresów** oraz dla **domains/subdomains (zapytania DNS).**

Korzystając z usług z poniższych **free apis** możesz także znaleźć **previous IPs used by domains and subdomains**. Te IP mogą nadal należeć do klienta (i mogą pozwolić na znalezienie [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz także sprawdzić domeny wskazujące na konkretny adres IP używając narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Wykonaj port scan wszystkich IP, które nie należą do CDNs** (ponieważ bardzo prawdopodobnie nic interesującego tam nie znajdziesz). W odkrytych działających usługach możesz **znaleźć podatności**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Znaleźliśmy wszystkie firmy i ich zasoby i znamy zakresy IP, domeny i subdomains w scope. Czas szukać web servers.

W poprzednich krokach prawdopodobnie już przeprowadziłeś jakieś **recon of the IPs and domains discovered**, więc możesz mieć **already found all the possible web servers**. Jednak jeśli nie, zobaczymy teraz kilka **szybkich trików, aby wyszukać web servers** w scope.

Zwróć uwagę, że to będzie **oriented for web apps discovery**, więc powinieneś także przeprowadzić **vulnerability** i **port scanning** (**jeśli allowed** przez scope).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Kolejne przyjazne narzędzie do wyszukiwania web servers to [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Przekazujesz listę domen, a narzędzie spróbuje połączyć się na port 80 (http) i 443 (https). Dodatkowo możesz wskazać inne porty do sprawdzenia:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery WWW** obecne w zakresie (wśród **IPs** firmy oraz wszystkich **domen** i **subdomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Zróbmy to prosto i zacznijmy od robienia zrzutów ekranu wszystkich z nich. Już samo **obejrzenie** **strony głównej** może ujawnić **dziwne** endpointy, które są bardziej **narażone na występowanie podatności**.

Aby zrealizować ten pomysł możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Dodatkowo możesz użyć [**eyeballer**](https://github.com/BishopFox/eyeballer) do przejrzenia wszystkich **zrzutów ekranu** i określenia, **co najprawdopodobniej zawiera podatności**, a co nie.

## Public Cloud Assets

Aby znaleźć potencjalne zasoby chmurowe należące do firmy, powinieneś **zacząć od listy słów kluczowych identyfikujących tę firmę**. Na przykład dla firmy z branży crypto możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Będziesz też potrzebować list słów zawierających **typowe wyrazy używane w buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie z tych słów powinieneś wygenerować **permutacje** (zobacz [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) po więcej informacji).

Z otrzymanych list słów możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając Cloud Assets powinieneś **szukać więcej niż tylko buckets w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz rzeczy takie jak **open buckets lub wystawione cloud functions**, powinieneś **uzyskać do nich dostęp** i sprawdzić, co Ci oferują i czy możesz je w jakiś sposób wykorzystać.

## E‑maile

Mając **domeny** i **subdomeny** w zakresie, zasadniczo masz wszystko, co potrzebne, aby **zacząć wyszukiwać e-maile**. Oto **API** i **narzędzia**, które najlepiej sprawdziły się u mnie przy znajdowaniu e-maili firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API of [**https://hunter.io/**](https://hunter.io/) (wersja darmowa)
- API of [**https://app.snov.io/**](https://app.snov.io/) (wersja darmowa)
- API of [**https://minelead.io/**](https://minelead.io/) (wersja darmowa)

### **Szukanie podatności**

E‑maile przydadzą się później do **brute-force web logins i auth services** (takich jak **SSH**). Są też niezbędne do **phishings**. Ponadto te API często dostarczą więcej **informacji o osobie** stojącej za danym e-mailem, co jest użyteczne przy kampanii phishingowej.

## Credential Leaks

With the **domains,** **subdomains**, and **emails** you can start looking for credentials leaked in the past belonging to those emails:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

If you find **valid leaked** credentials, this is a very easy win.

## Secrets Leaks

Credential leaks are related to hacks of companies where **sensitive information was leaked and sold**. However, companies might be affected for **other leaks** whose info isn't in those databases:

### Github Leaks

Credentials and **APIs** might be leaked in the **public repositories** of the **company** or of the **users** working by that github company.\
You can use the **tool** [**Leakos**](https://github.com/carlospolop/Leakos) to **download** all the **public repos** of an **organization** and of its **developers** and run [**gitleaks**](https://github.com/zricethezav/gitleaks) over them automatically.

**Leakos** can also be used to run **gitleaks** agains all the **text** provided **URLs passed** to it as sometimes **web pages also contains secrets**.

#### Github Dorks

Check also this **page** for potential **github dorks** you could also search for in the organization you are attacking:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Sometimes attackers or just workers will **publish company content in a paste site**. This might or might not contain **sensitive information**, but it's very interesting to search for it.\
You can use the tool [**Pastos**](https://github.com/carlospolop/Pastos) to search in more that 80 paste sites at the same time.

### Google Dorks

Old but gold google dorks are always useful to find **exposed information that shouldn't be there**. The only problem is that the [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contains several **thousands** of possible queries that you cannot run manually. So, you can get your favourite 10 ones or you could use a **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Szukanie podatności**

If you find **valid leaked** credentials or **API tokens**, this is a very easy win.

## Public Code Vulnerabilities

If you found that the company has **open-source code** you can **analyse** it and search for **vulnerabilities** on it.

**Depending on the language** there are different **tools** you can use:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

There are also free services that allow you to **scan public repositories**, such as:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

The **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

I also want to do a special mention to the section [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), as, if you shouldn't expect them to find you very sensitive vulnerabilities, they come handy to implement them on **workflows to have some initial web information.**

## Podsumowanie

> Gratulacje! W tym momencie wykonałeś już **wszystkie podstawowe czynności enumeracyjne**. Tak, to podstawowe, ponieważ można wykonać znacznie więcej enumeracji (zobaczymy więcej trików później).

Więc już:

1. Znalazłeś wszystkie **companies** w zakresie
2. Znalazłeś wszystkie **assets** należące do firm (i wykonałeś skan vuln, jeśli było w zakresie)
3. Znalazłeś wszystkie **domeny** należące do firm
4. Znalazłeś wszystkie **subdomeny** domen (czy istnieje subdomain takeover?)
5. Znalazłeś wszystkie **IPs** (z CDN i poza nimi) w zakresie.
6. Znalazłeś wszystkie **serwery WWW** i zrobiłeś ich **zrzuty ekranu** (czy coś dziwnego wartego głębszego sprawdzenia?)
7. Znalazłeś wszystkie **potencjalne public cloud assets** należące do firmy.
8. **E‑maile**, **credentials leaks**, i **secret leaks**, które mogą dać Ci **łatwy duży sukces**.
9. **Pentesting** wszystkich znalezionych webs

## **Full Recon Automatic Tools**

Istnieje kilka narzędzi, które wykonają część proponowanych działań przeciwko danemu zakresowi.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
