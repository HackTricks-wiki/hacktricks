# Metodologia zewnętrznego rozpoznania

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano ci, że wszystko należące do danej firmy jest w zakresie, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest pozyskanie wszystkich **firm należących do firmy macierzystej** i następnie wszystkich **zasobów** tych firm. W tym celu zamierzamy:

1. Znaleźć przejęcia firmy macierzystej — to dostarczy nam firm objętych zakresem.
2. Znaleźć ASN (jeśli istnieje) każdej firmy — to da nam zakresy IP należące do każdej firmy.
3. Użyć reverse whois lookups aby wyszukać inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszym (można to wykonywać rekurencyjnie).
4. Użyć innych technik, takich jak shodan `org`and `ssl`filters aby wyszukać inne zasoby (sztuczka z `ssl` może być wykonywana rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy wiedzieć, które **inne firmy są własnością firmy macierzystej**.\
Jedną z opcji jest odwiedzić [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukać** **firmę macierzystą**, i **kliknąć** na "**acquisitions**". Tam zobaczysz inne firmy przejęte przez firmę macierzystą.\
Inną opcją jest odwiedzić stronę **Wikipedia** firmy macierzystej i wyszukać **acquisitions**.\
Dla spółek publicznych sprawdź **SEC/EDGAR filings**, strony **investor relations**, lub lokalne rejestry korporacyjne (np. **Companies House** w Wielkiej Brytanii).\
Dla globalnych struktur korporacyjnych i spółek zależnych wypróbuj **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazę danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, w tym momencie powinieneś znać wszystkie firmy objęte zakresem. Ustalmy, jak znaleźć ich zasoby.

### **ASNs**

Autonomous system number (**ASN**) to **unikalny numer** przypisany do **Autonomous System** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
AS składa się z bloków **adresów IP**, które mają wyraźnie zdefiniowaną politykę dostępu do sieci zewnętrznych i są zarządzane przez jedną organizację, choć mogą obejmować kilku operatorów.

Warto sprawdzić, czy **firma przypisała jakiekolwiek ASN**, aby znaleźć jej **zakresy IP.** Warto przeprowadzić **test podatności** przeciwko wszystkim **hostom** w obrębie **zakresu** oraz **szukać domen** na tych adresach IP.\
Możesz **wyszukiwać** po **nazwie** firmy, po **IP** lub po **domenie** na [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu firmy te linki mogą być przydatne do zgromadzenia dodatkowych danych:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** Jednak prawdopodobnie wszystkie **przydatne informacje** (zakresy IP i Whois) są już dostępne w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Również, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeracja automatycznie agreguje i podsumowuje ASNs na końcu skanowania.
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
Możesz znaleźć zakresy IP organizacji także używając [http://asnlookup.com/](http://asnlookup.com) (ma darmowe API).\
Możesz znaleźć IP i ASN domeny używając [http://ipv4info.com/](http://ipv4info.com).

### **Szukanie podatności**

Na tym etapie znamy **wszystkie zasoby w zakresie**, więc jeśli masz pozwolenie możesz uruchomić jakiś **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Również możesz uruchomić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub użyć usług takich jak** Shodan, Censys, lub ZoomEye **by znaleźć** otwarte porty **i w zależności od tego, co znajdziesz powinieneś** zajrzeć do tej książki, aby dowiedzieć się jak pentest several possible services running.\
**Warto też wspomnieć, że możesz przygotować** default username **i** passwords **lists i spróbować** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy wszystkie firmy w zakresie oraz ich zasoby, czas znaleźć domeny w zakresie.

_Pamiętaj, że w poniższych proponowanych technikach możesz także znaleźć subdomeny i tej informacji nie należy lekceważyć._

Przede wszystkim powinieneś poszukać **main domain**(s) każdej firmy. Na przykład, dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Jeśli znalazłeś już wszystkie zakresy IP domen, możesz spróbować wykonać **reverse dns lookups** na tych **IP** aby znaleźć więcej domen w zakresie. Spróbuj użyć jakiegoś dns server of the victim lub dobrze znanego dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Aby to działało, administrator musi ręcznie włączyć PTR.\
Możesz też użyć narzędzia online do tych informacji: [http://ptrarchive.com/](http://ptrarchive.com).\
Dla dużych zakresów narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) są przydatne do automatyzacji reverse lookups i wzbogacania danych.

### **Reverse Whois (loop)**

W rekordzie **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **e-maile**, numery telefonów... Jednak jeszcze ciekawsze jest to, że można znaleźć **więcej zasobów związanych z firmą**, jeżeli wykonasz **reverse whois lookups po którymkolwiek z tych pól** (na przykład inne rejestry whois, gdzie pojawia się ten sam e-mail).\
Możesz użyć narzędzi online, takich jak:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Darmowe**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Darmowe**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Darmowe**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **Darmowe** web, nie darmowe API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - **Płatne**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **Płatne** (tylko **100 darmowych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - **Płatne**
- [https://securitytrails.com/](https://securitytrails.com/) - **Płatne** (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **Płatne** (API)

Możesz zautomatyzować to zadanie używając [**DomLink** ](https://github.com/vysecurity/DomLink) (wymaga klucza API whoxy).\
Możesz także wykonać automatyczne odkrywanie reverse whois przy pomocy [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Zauważ, że możesz użyć tej techniki, aby odkryć więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackers**

Jeśli znajdziesz ten sam **ID tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli widzisz ten sam **Google Analytics ID** lub ten sam **Adsense ID** na kilku stronach.

Istnieją strony i narzędzia, które pozwalają wyszukiwać po tych trackerach i innych:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (znajduje powiązane serwisy przez wspólne analytics/trackery)

### **Favicon**

Czy wiedziałeś, że możemy znaleźć powiązane domeny i subdomeny względem naszego celu, szukając tego samego hash'a favikony? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go użyć:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - odkryj domeny z tym samym hashem favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc najprościej, favihash pozwoli nam odkryć domeny, które mają ten sam hash favicon co nasz cel.

Co więcej, możesz także wyszukiwać technologie używając hasha favicon, jak wyjaśniono w [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To oznacza, że jeśli znasz **hash favicon podatnej wersji danej technologii webowej** możesz wyszukać go w shodan i **znaleźć więcej podatnych miejsc**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Oto jak możesz **obliczyć favicon hash** strony:
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
Możesz też uzyskać hashe faviconów na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i następnie pivotować w Shodan/Censys.

### **Copyright / Unikalny ciąg**

Szukaj w stronach internetowych **ciągów, które mogą być współdzielone między różnymi serwisami tej samej organizacji**. **Ciąg z informacją o prawach autorskich** może być dobrym przykładem. Następnie wyszukaj ten ciąg w **google**, w innych **przeglądarkach** lub nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się zadanie cron takie jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
odnawiać wszystkie certyfikaty domen na serwerze. Oznacza to, że nawet jeśli CA użyta do tego nie ustawia czasu wygenerowania w polu Validity time, możliwe jest **znalezienie domen należących do tej samej firmy w certificate transparency logs**.\
Zobacz ten [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC (poczta)

Możesz użyć serwisu takiego jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny dzielące te same informacje DMARC**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Okazuje się, że często ludzie przypisują subdomeny do adresów IP należących do dostawców chmurowych i w pewnym momencie **tracą ten adres IP, ale zapominają usunąć rekord DNS**. W związku z tym samo **uruchomienie VM** w chmurze (np. Digital Ocean) może spowodować, że w praktyce **przejmiesz niektóre subdomeny**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) opisuje tę historię i proponuje skrypt, który **uruchamia VM w DigitalOcean**, **pobiera** **IPv4** nowej maszyny oraz **przeszukuje VirusTotal w poszukiwaniu rekordów subdomen** wskazujących na nią.

### **Inne sposoby**

**Zwróć uwagę, że możesz użyć tej techniki, aby odkrywać kolejne nazwy domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Jeżeli znasz już nazwę organizacji posiadającej przestrzeń adresową IP, możesz przeszukać shodan używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w TLS certificate.

Możesz uzyskać dostęp do **TLS certificate** głównej strony, pobrać **Organisation name**, a następnie wyszukać tę nazwę w **TLS certificates** wszystkich stron znanych przez **shodan** używając filtra: `ssl:"Tesla Motors"` lub użyć narzędzia jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) to narzędzie, które wyszukuje **powiązane domeny** z domeną główną oraz jej **subdomeny**, całkiem przydatne.

**Passive DNS / Historical DNS**

Passive DNS data są świetne do znajdowania **starych i zapomnianych rekordów**, które nadal rozwiązują się lub które można przejąć. Zobacz:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Poszukiwanie podatności**

Sprawdź pod kątem [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa pewnej domeny**, ale **straciła nad nią własność**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i powiadom firmę.

Jeśli znajdziesz jakąkolwiek **domenę z innym IP** niż te, które już znalazłeś podczas odkrywania assetów, powinieneś przeprowadzić **podstawowe skanowanie podatności** (używając Nessus lub OpenVAS) oraz [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług, w **tej książce** znajdziesz kilka sztuczek, jak je „zaatakować”.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomeny

> Wiemy wszystkie firmy w scope, wszystkie assety każdej firmy i wszystkie domeny powiązane z tymi firmami.

> [!TIP]
> Zauważ, że niektóre narzędzia i techniki do znajdowania domen mogą również pomóc w znalezieniu subdomen

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy także spróbować **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najszybszy sposób na uzyskanie wielu subdomains to wyszukiwanie w źródłach zewnętrznych. Najczęściej używane **narzędzia** to następujące (dla lepszych rezultatów skonfiguruj API keys):

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
Są **inne interesujące narzędzia/API**, które, nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomains, mogą być przydatne do znajdowania subdomains, takie jak:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskiwania subdomains
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
- [**gau**](https://github.com/lc/gau)**:** pobiera znane adresy URL z AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl dla dowolnej domeny.
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

Ten projekt oferuje **za darmo wszystkie subdomains związane z programami bug-bounty**. Możesz uzyskać dostęp do tych danych także używając [chaospy](https://github.com/dr-0x0x/chaospy) lub nawet uzyskać dostęp do scope używanego przez ten projekt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Możesz znaleźć **porównanie** wielu z tych narzędzi tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomains** brute-forcing serwery DNS przy użyciu możliwych nazw subdomain.

Do tej akcji będziesz potrzebować kilku **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebne będą też IP dobrych DNS resolvers. Aby wygenerować listę zaufanych DNS resolvers możesz pobrać resolvery z [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich filtrowania. Albo możesz użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej rekomendowane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To było pierwsze narzędzie, które wykonywało skuteczny DNS brute-force. Jest bardzo szybkie, jednak podatne na false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Wydaje mi się, że ten używa tylko 1 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper wokół `massdns`, napisany w go, który pozwala enumerować poprawne subdomeny przy użyciu active bruteforce, a także rozwiązywać subdomeny z wildcard handling oraz z prostym wsparciem input-output.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego brute force'owania nazw domen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS Brute-Force

Po znalezieniu subdomen przy użyciu otwartych źródeł i brute-forcingu możesz wygenerować warianty znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Kilka narzędzi jest przydatnych do tego celu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dla podanych domen i subdomen generuje permutacje.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Generuje permutacje na podstawie domen i subdomen.
- Możesz pobrać wordlist permutacji dla goaltdns w [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Generuje permutations dla podanych domen i subdomen. Jeśli nie wskazano pliku permutations, gotator użyje własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania subdomains permutations, może także próbować je resolve'ować (ale lepiej użyć wcześniej wspomnianych narzędzi).
- Możesz pobrać altdns permutations **wordlist** w [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutations, mutations i modyfikacji subdomen. To narzędzie wykonuje brute force na wynikach (nie obsługuje dns wild card).
- Możesz pobrać dmut permutations wordlist w [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domain **generuje nowe potencjalne nazwy subdomains** w oparciu o wskazane wzorce, aby odkryć więcej subdomains.

#### Inteligentne generowanie permutacji

- [**regulator**](https://github.com/cramppet/regulator): Po więcej informacji przeczytaj ten [**post**](https://cramppet.github.io/regulator/index.html), ale w praktyce pobiera **główne części** z **discovered subdomains** i miesza je, żeby znaleźć więcej subdomains.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to subdomain brute-force fuzzer sprzężony z niezwykle prostym, ale skutecznym DNS reponse-guided algorithm. Wykorzystuje dostarczony zestaw danych wejściowych, takich jak dostosowany wordlist lub historyczne DNS/TLS records, aby dokładnie syntetyzować więcej odpowiadających nazw domen i rozszerzać je jeszcze dalej w pętli na podstawie informacji zebranych podczas DNS scan.
```
echo www | subzuf facebook.com
```
### **Proces wykrywania subdomen**

Sprawdź ten wpis na blogu, który napisałem o tym, jak **zautomatyzować wykrywanie subdomen** dla domeny przy użyciu **Trickest workflows**, żeby nie musieć ręcznie uruchamiać na komputerze wielu narzędzi:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny mające witryny na tym adresie IP** przez przeszukanie **źródeł OSINT** w celu znalezienia domen przypisanych do adresu IP lub przez **brute-forcing nazw domen VHost na tym adresie IP**.

#### OSINT

Możesz znaleźć niektóre **VHosts w adresach IP używając** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze WWW, możesz spróbować ją odnaleźć za pomocą Brute Force:
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
> Dzięki tej technice możesz nawet uzyskać dostęp do internal/hidden endpoints.

### **CORS Brute Force**

Czasami znajdziesz strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest poprawna domain/subdomain. W takich scenariuszach możesz nadużyć tego zachowania, aby **odkryć** nowe **subdomains**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Podczas poszukiwania **subdomains** zwracaj uwagę, czy są **pointing** na jakiś rodzaj **bucket**, a w takim przypadku [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponadto, ponieważ na tym etapie będziesz znał wszystkie domeny w zakresie, spróbuj [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Możesz **monitor** czy tworzone są **new subdomains** danej domeny, obserwując logi **Certificate Transparency**, tak jak robi to [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Sprawdź możliwe [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomain** wskazuje na jakiś **S3 bucket**, [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeżeli znajdziesz jakiś **subdomain with an IP different** od tych, które już znalazłeś podczas asset discovery, powinieneś przeprowadzić **basic vulnerability scan** (używając Nessus lub OpenVAS) oraz wykonać [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy pomocy **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **this book some tricks to "attack" them**.\
_Uwaga: czasami subdomain jest hostowany na adresie IP, który nie jest kontrolowany przez klienta, więc nie znajduje się w zakresie — bądź ostrożny._

## IPs

W początkowych krokach mogłeś **found some IP ranges, domains and subdomains**.\
Nadszedł czas, aby **recollect all the IPs from those ranges** oraz dla **domains/subdomains (DNS queries).**

Korzystając z serwisów z poniższych **free apis** możesz także znaleźć **previous IPs used by domains and subdomains**. Te IP mogą nadal należeć do klienta (i mogą pozwolić na znalezienie [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz też sprawdzić domeny wskazujące na konkretny adres IP za pomocą narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs** (ponieważ najprawdopodobniej nie znajdziesz tam nic interesującego). W odnalezionych usługach uruchomionych na tych hostach możesz **able to find vulnerabilities**.

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> Znaleźliśmy wszystkie firmy i ich zasoby i znamy zakresy IP, domeny i subdomains w zakresie. Czas poszukać serwerów WWW.

W poprzednich krokach prawdopodobnie już wykonałeś część **recon of the IPs and domains discovered**, więc możesz już mieć **already found all the possible web servers**. Jeśli jednak nie, teraz zobaczymy kilka **fast tricks to search for web servers** w obrębie zakresu.

Zwróć uwagę, że to będzie **oriented for web apps discovery**, więc powinieneś również **perform the vulnerability** oraz **port scanning** (**jeśli dozwolone** w ramach zakresu).

A **fast method** to discover **ports open** related to **web** servers using [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania serwerów WWW są [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Przekazujesz im listę domen i spróbują połączyć się z portem 80 (http) i 443 (https). Dodatkowo możesz wskazać inne porty:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery WWW** obecne w zakresie (wśród **IPs** firmy oraz wszystkich **domains** i **subdomains**) prawdopodobnie **nie wiesz, od czego zacząć**. Zróbmy to prosto i zacznijmy po prostu robić zrzuty ekranu wszystkich z nich. Już po **rzuceniu okiem** na **stronę główną** możesz znaleźć **dziwne** endpointy, które są bardziej **podatne** na występowanie **podatności**.

Aby zrealizować zaproponowany pomysł możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto możesz użyć [**eyeballer**](https://github.com/BishopFox/eyeballer) do przejrzenia wszystkich **zrzutów ekranu**, aby wskazać **co prawdopodobnie zawiera podatności**, a co nie.

## Publiczne zasoby chmurowe

Aby znaleźć potencjalne cloud assets należące do firmy powinieneś **zacząć od listy słów kluczowych, które identyfikują tę firmę**. Na przykład, dla firmy z branży crypto możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Będziesz też potrzebować wordlistów zawierających **typowe słowa używane w buckets**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie z tych słów powinieneś wygenerować **permutacje** (sprawdź [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) po więcej informacji).

Z powstałymi wordlistami możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając Cloud Assets powinieneś **szukać więcej niż tylko buckets w AWS**.

### **Szukając podatności**

Jeśli znajdziesz rzeczy takie jak **otwarte buckets lub wystawione cloud functions** powinieneś **uzyskać do nich dostęp** i sprawdzić, co Ci oferują i czy możesz je nadużyć.

## E-maile

Mając **domains** i **subdomains** w zakresie masz praktycznie wszystko, czego **potrzebujesz, aby zacząć wyszukiwać e-maile**. Oto **API** i **narzędzia**, które najlepiej sprawdziły się u mnie przy znajdowaniu e-maili firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Szukając podatności**

E-maile przydadzą się później do **brute-force web logins and auth services** (takich jak SSH). Również są potrzebne do **phishings**. Ponadto te API dostarczą Ci dodatkowe **info about the person** stojącej za adresem e-mail, co jest przydatne w kampanii phishingowej.

## Credential Leaks

Mając **domains,** **subdomains**, i **emails** możesz zacząć szukać poświadczeń leaked w przeszłości należących do tych e-maili:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukając podatności**

Jeśli znajdziesz **valid leaked** credentials, to bardzo łatwe zwycięstwo.

## Secrets Leaks

Credential leaks odnoszą się do włamań firm, w których **sensitive information was leaked and sold**. Jednak firmy mogą być dotknięte także **innymi leaks**, których informacje nie znajdują się w tych bazach danych:

### Github Leaks

Credentials i API mogą być leaked w **public repositories** firmy lub użytkowników pracujących dla tej firmy na githubie.\
Możesz użyć **tool** [**Leakos**](https://github.com/carlospolop/Leakos) aby **pobrać** wszystkie **public repos** organizacji i jej **developerów** i automatycznie uruchomić na nich [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** można także wykorzystać do uruchomienia **gitleaks** przeciwko wszystkim przekazanym **text** **URLs**, ponieważ czasami **web pages also contains secrets**.

#### Github Dorks

Sprawdź także tę **page** pod kątem potencjalnych **github dorks**, które możesz wyszukiwać w organizacji, którą atakujesz:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Czasami atakujący lub pracownicy publikują treści firmy na stronach typu paste. To może, ale nie musi zawierać **sensitive information**, jednak warto to przeszukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos) aby przeszukać ponad 80 paste sites jednocześnie.

### Google Dorks

Stare, ale jare google dorks są zawsze przydatne do znalezienia **exposed information that shouldn't be there**. Problem w tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie wykona się ręcznie. Możesz więc wybrać ulubione 10 albo użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks) **aby uruchomić je wszystkie**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Szukając podatności**

Jeśli znajdziesz **valid leaked** credentials lub tokeny API, to bardzo łatwe zwycięstwo.

## Publiczne podatności w kodzie

Jeśli odkryjesz, że firma ma **open-source code** możesz go **przeanalizować** i wyszukać w nim **podatności**.

**W zależności od języka** istnieją różne **narzędzia**, których możesz użyć:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Są też darmowe serwisy, które pozwalają **skanować public repositories**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

The **majority of the vulnerabilities** found by bug hunters resides inside **web applications**, so at this point I would like to talk about a **web application testing methodology**, and you can [**find this information here**](../../network-services-pentesting/pentesting-web/index.html).

Chciałbym też zwrócić uwagę na sekcję [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ, choć nie powinieneś oczekiwać, że znajdą bardzo krytyczne podatności, są przydatne do wdrożenia w workflowach, aby uzyskać podstawowe informacje o webie.

## Podsumowanie

> Gratulacje! Na tym etapie wykonałeś już **wszystkie podstawowe enumeracje**. Tak, to podstawowe, bo można wykonać znacznie więcej (zobaczymy więcej trików później).

Więc masz już:

1. Znalazłeś wszystkie **companies** w zakresie
2. Znalazłeś wszystkie **assets** należące do firm (i przeprowadziłeś jakiś vuln scan jeśli w scope)
3. Znalazłeś wszystkie **domains** należące do firm
4. Znalazłeś wszystkie **subdomains** domen (any subdomain takeover?)
5. Znalazłeś wszystkie **IPs** (zarówno pochodzące z, jak i nie z CDNs) w zakresie.
6. Znalazłeś wszystkie **serwery WWW** i zrobiłeś ich **zrzuty ekranu** (czy coś dziwnego wartego głębszego zbadania?)
7. Znalazłeś wszystkie potencjalne **public cloud assets** należące do firmy.
8. **E-maile**, **credentials leaks**, oraz **secret leaks**, które mogą dać Ci **big win bardzo łatwo**.
9. **Pentesting wszystkich znalezionych webs**

## **Full Recon Automatic Tools**

Istnieje kilka narzędzi, które wykonają część proponowanych działań przeciwko zdefiniowanemu zakresowi.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
