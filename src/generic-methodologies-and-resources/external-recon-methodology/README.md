# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano ci, że wszystko należące do jakiejś firmy jest w zakresie, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. Aby to zrobić, będziemy:

1. Znaleźć przejęcia głównej firmy, co da nam firmy objęte zakresem.
2. Znaleźć ASN (jeśli istnieje) każdej firmy, co da nam zakresy IP należące do każdej firmy
3. Użyć reverse whois lookups do wyszukania innych wpisów (nazwy organizacji, domeny...) powiązanych z pierwszym (można to robić rekurencyjnie)
4. Użyć innych technik, takich jak filtry shodan `org`i `ssl`, aby wyszukać inne zasoby (trik z `ssl` można stosować rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy wiedzieć, które **inne firmy są własnością głównej firmy**.\
Jedna opcja to odwiedzić [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukać** **główną firmę** i **kliknąć** "**acquisitions**". Tam zobaczysz inne firmy przejęte przez główną.\
Inna opcja to odwiedzić stronę **Wikipedia** głównej firmy i wyszukać **acquisitions**.\
W przypadku firm publicznych sprawdź zgłoszenia **SEC/EDGAR**, strony **investor relations** lub lokalne rejestry spółek (np. **Companies House** w UK).\
Dla globalnych struktur korporacyjnych i spółek zależnych wypróbuj **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazę danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Ok, w tym momencie powinieneś znać wszystkie firmy w zakresie. Ustalmy, jak znaleźć ich zasoby.

### **ASNs**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, które mają wyraźnie zdefiniowaną politykę dostępu do sieci zewnętrznych i są administrowane przez jedną organizację, ale mogą składać się z kilku operatorów.

Warto sprawdzić, czy **firma przypisała jakiś ASN**, aby znaleźć jej **zakresy IP.** Przydatne będzie wykonanie **testu podatności** wobec wszystkich **hostów** w **zakresie** oraz **szukanie domen** wewnątrz tych IP.\
Możesz **wyszukiwać** po **nazwie** firmy, po **IP** albo po **domenie** w [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu firmy te linki mogą być przydatne do zebrania większej ilości danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). Tak czy inaczej, prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** pojawiają się już w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Również, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration automatycznie agreguje i podsumowuje ASNy na końcu skanu.
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
Możesz też znaleźć zakresy IP organizacji, korzystając z [http://asnlookup.com/](http://asnlookup.com) (ma darmowe API).\
Możesz znaleźć IP i ASN domeny za pomocą [http://ipv4info.com/](http://ipv4info.com).

### **Szukanie podatności**

Na tym etapie znamy już **wszystkie zasoby w zakresie**, więc jeśli masz na to zgodę, możesz uruchomić jakiś **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Możesz też uruchomić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **albo użyć usług takich jak** Shodan, Censys lub ZoomEye **do znalezienia** otwartych portów, a w zależności od tego, co znajdziesz, powinieneś **zajrzeć do tej książki, aby dowiedzieć się, jak pentestować kilka możliwych usług, które tam działają**.\
**Warto też wspomnieć, że możesz przygotować listy domyślnych nazw użytkowników i haseł oraz spróbować** bruteforce usług z użyciem [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy już wszystkie firmy w zakresie i ich zasoby, czas znaleźć domeny w zakresie.

_Pamiętaj, że w poniższych technikach możesz też znaleźć subdomeny i nie należy tej informacji lekceważyć._

Przede wszystkim powinieneś poszukać **głównej domeny** każdej firmy. Na przykład dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Skoro znalazłeś wszystkie zakresy IP domen, możesz spróbować wykonać **reverse dns lookups** na tych **IP, aby znaleźć więcej domen w zakresie**. Spróbuj użyć jakiegoś serwera dns ofiary albo znanego serwera dns (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Dla tego działania administrator musi ręcznie włączyć PTR.\
Możesz też użyć narzędzia online do tych informacji: [http://ptrarchive.com/](http://ptrarchive.com).\
Dla dużych zakresów narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx) są przydatne do automatyzacji reverse lookups i wzbogacania danych.

### **Reverse Whois (loop)**

W **whois** możesz znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **emaile**, numery telefonów... Ale jeszcze ciekawsze jest to, że możesz znaleźć **więcej assets powiązanych z firmą**, jeśli wykonasz **reverse whois lookups po dowolnym z tych pól** (na przykład inne rejestry whois, gdzie pojawia się ten sam email).\
Możesz użyć narzędzi online takich jak:

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

Możesz zautomatyzować to zadanie, używając [**DomLink** ](https://github.com/vysecurity/DomLink)(wymaga klucza API whoxy).\
Możesz też wykonać pewne automatyczne reverse whois discovery za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz użyć tej techniki do odkrywania większej liczby nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackers**

Jeśli znajdziesz ten sam ID tego samego trackera na 2 różnych stronach, możesz założyć, że obie strony są zarządzane przez ten sam zespół.\
Na przykład, jeśli widzisz ten sam **Google Analytics ID** albo ten sam **Adsense ID** na kilku stronach.

Są strony i narzędzia, które pozwalają szukać po tych trackerach i nie tylko:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, szukając tego samego hasha ikony favicon? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc prosto, favihash pozwoli nam odkryć domeny, które mają taki sam favicon icon hash jak nasz cel.

Co więcej, możesz też wyszukiwać technologie, używając favicon hash, jak wyjaśniono w [**tym wpisie na blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). To oznacza, że jeśli znasz **hash favicon wrażliwej wersji technologii webowej**, możesz sprawdzić to w shodan i **znaleźć więcej podatnych miejsc**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Tak możesz **obliczyć hash favicon** strony internetowej:
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
Możesz też uzyskać hashe faviconów na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) i potem pivotować w Shodan/Censys.

### **Copyright / Uniq string**

Szukaj w stronach WWW **ciągów znaków, które mogą być współdzielone między różnymi witrynami w tej samej organizacji**. **Ciąg copyright** może być dobrym przykładem. Następnie wyszukaj ten ciąg w **google**, w innych **przeglądarkach** albo nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się zadanie cron, takie jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all the certificates domeny na serwerze. Oznacza to, że nawet jeśli CA użyty do tego nie zapisuje czasu jego wygenerowania w polu Validity, możliwe jest **znalezienie domen należących do tej samej firmy w certificate transparency logs**.\
Sprawdź [**ten writeup, aby uzyskać więcej informacji**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Używaj też bezpośrednio logów **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC poczty

Możesz użyć strony web takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) albo narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny współdzielące te same informacje dmarc**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Najwyraźniej często zdarza się, że ludzie przypisują subdomeny do IP, które należą do dostawców chmury, a w pewnym momencie **tracą ten adres IP, ale zapominają usunąć rekord DNS**. Dlatego po prostu **uruchomienie VM** w chmurze (np. Digital Ocean) pozwoli ci faktycznie **przejąć niektóre subdomeny**.

[**Ten post**](https://kmsec.uk/blog/passive-takeover/) wyjaśnia o tym historię i proponuje skrypt, który **uruchamia VM w DigitalOcean**, **pobiera** **IPv4** nowej maszyny i **wyszukuje w Virustotal rekordy subdomen** wskazujące na nią.

### **Inne sposoby**

**Zauważ, że możesz używać tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Jak już wiesz, nazwa organizacji posiadającej przestrzeń IP. Możesz wyszukiwać po tych danych w shodan, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz uzyskać dostęp do **certyfikatu TLS** głównej strony webowej, pobrać nazwę **Organization** i potem wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron web znanych przez **shodan** za pomocą filtra : `ssl:"Tesla Motors"` albo użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie, które szuka **domen powiązanych** z główną domeną oraz ich **subdomen**, naprawdę świetne.

**Passive DNS / Historical DNS**

Dane Passive DNS są świetne do znajdowania **starych i zapomnianych rekordów**, które nadal rozwiązują się albo mogą zostać przejęte. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Wyszukiwanie podatności**

Sprawdź [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Może jakaś firma **używa jakiejś domeny**, ale **straciła jej własność**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz jakąkolwiek **domenę z innym IP** niż te, które już znalazłeś podczas asset discovery, powinieneś przeprowadzić **podstawowy skan podatności** (używając Nessus lub OpenVAS) oraz **skan portów** [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) z użyciem **nmap/masscan/shodan**. W zależności od tego, jakie usługi działają, możesz znaleźć w **tej książce** kilka trików, jak je „zaatakować”.\
_Uwaga: czasami domena jest hostowana na IP, nad którym klient nie ma kontroli, więc nie należy to do scope, bądź ostrożny._

## Subdomains

> Znamy wszystkie firmy w scope, wszystkie zasoby każdej firmy oraz wszystkie domeny powiązane z tymi firmami.

Czas znaleźć wszystkie możliwe subdomeny każdej znalezionej domeny.

> [!TIP]
> Zauważ, że niektóre narzędzia i techniki do znajdowania domen mogą też pomagać w znajdowaniu subdomen

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy też spróbować **Zone Transfer** (jeśli podatne, powinieneś to zgłosić).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najszybszym sposobem na zdobycie wielu subdomen jest wyszukiwanie w zewnętrznych źródłach. Najczęściej używane **tools** są następujące (dla lepszych wyników skonfiguruj klucze API):

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
Istnieją **inne interesujące narzędzia/API**, które nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomen, mogą być przydatne do ich wyszukiwania, takie jak:

- [**IP.THC.ORG**](https://ip.thc.org) free API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do pozyskiwania subdomen
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** pobiera znane URL-e z AlienVault's Open Threat Exchange, Wayback Machine i Common Crawl dla dowolnej podanej domeny.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Przeszukują sieć w poszukiwaniu plików JS i wyciągają z nich subdomeny.
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
- [**securitytrails.com**](https://securitytrails.com/) ma darmowe API do wyszukiwania subdomen i historii IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ten projekt udostępnia za darmo wszystkie subdomeny powiązane z programami bug-bounty. Możesz uzyskać dostęp do tych danych także używając [chaospy](https://github.com/dr-0x0x/chaospy) albo nawet sprawdzić scope używany przez ten projekt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Możesz znaleźć **porównanie** wielu z tych narzędzi tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomains** metodą brute-force na serwerach DNS, używając możliwych nazw subdomen.

Do tego działania będziesz potrzebować kilku **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Oraz IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać resolvery z [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), aby je odfiltrować. Możesz też użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To było pierwsze narzędzie, które wykonało skuteczny DNS brute-force. Jest bardzo szybkie, jednak podatne na false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ten używa tylko 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper wokół `massdns`, napisany w go, który pozwala na enumerację prawidłowych subdomen przy użyciu aktywnego bruteforce, a także rozwiązywanie subdomen z obsługą wildcard i łatwym wsparciem wejście-wyjście.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego brute force nazw domen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS brute-force

Po znalezieniu subdomen przy użyciu otwartych źródeł i brute-forcingu, możesz generować warianty znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Kilka narzędzi jest przydatnych w tym celu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na podstawie domen i subdomen generuje permutacje.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Mając domeny i subdomeny, generuj permutacje.
- Możesz pobrać **wordlist** permutacji goaltdns [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Biorąc domeny i subdomeny, generuje permutacje. Jeśli nie wskazano pliku z permutacjami, gotator użyje własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może też próbować je rozwiązywać (ale lepiej użyć wcześniej skomentowanych narzędzi).
- Możesz pobrać **wordlist** permutacji altdns [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutacji, mutacji i modyfikacji subdomen. To narzędzie wykona brute force wyniku (nie obsługuje dns wild card).
- Możesz pobrać listę słów permutacji dmut [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy subdomen** według wskazanych wzorców, aby spróbować odkryć więcej subdomen.

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): Po więcej informacji przeczytaj ten [**post**](https://cramppet.github.io/regulator/index.html), ale ogólnie pobiera **główne części** z **odkrytych subdomen** i miesza je, aby znaleźć więcej subdomen.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to subdomenowy brute-force fuzzer połączony z niezwykle prostym, ale skutecznym algorytmem sterowanym odpowiedziami DNS. Wykorzystuje dostarczony zestaw danych wejściowych, taki jak dopasowana wordlist lub historyczne rekordy DNS/TLS, aby dokładnie syntetyzować więcej odpowiadających nazw domen i dalej je rozszerzać w pętli na podstawie informacji zebranych podczas skanowania DNS.
```
echo www | subzuf facebook.com
```
### **Workflow odkrywania subdomen**

Sprawdź ten wpis na blogu, który napisałem o tym, jak **zautomatyzować odkrywanie subdomen** z domeny używając **Trickest workflows**, dzięki czemu nie muszę ręcznie uruchamiać wielu narzędzi na swoim komputerze:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z webami na tym IP**, przeszukując **źródła OSINT** w poszukiwaniu domen na danym IP albo **brute-forcując nazwy domen VHost na tym IP**.

#### OSINT

Możesz znaleźć niektóre **VHosts w IPs używając** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na web serverze, możesz spróbować ją brute force’ować:

Gdy **IP przekierowuje na hostname** (name-based vhosts), fuzzuj bezpośrednio nagłówek `Host` i pozwól ffuf **auto-calibrate**, aby wyróżnić odpowiedzi różniące się od domyślnego vhosta:
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
> Dzięki tej technice możesz nawet uzyskać dostęp do wewnętrznych/ukrytych endpointów.

### **CORS Brute Force**

Czasami znajdziesz strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest poprawna domena/subdomena. W takich scenariuszach możesz nadużyć tego zachowania, aby **odkryć** nowe **subdomeny**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute force Bucketów**

Podczas szukania **subdomains** zwracaj uwagę, czy któryś z nich **wskazuje** na jakiś typ **bucket**, a w takim przypadku [**sprawdź permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponadto, ponieważ na tym etapie będziesz już znać wszystkie domeny w zakresie, spróbuj [**brute force możliwych nazw bucketów i sprawdź permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorization**

Możesz **monitor**ować, czy tworzone są **new subdomains** domeny, obserwując logi **Certificate Transparency**; robi to [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Looking for vulnerabilities**

Sprawdź, czy nie ma możliwych [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomain** wskazuje na jakiś **S3 bucket**, [**sprawdź permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz jakikolwiek **subdomain z innym IP** niż te, które już znalazłeś podczas assets discovery, powinieneś przeprowadzić **podstawowy vulnerability scan** (używając Nessus lub OpenVAS) oraz **port scan** [**nmap/masscan/shodan**](../pentesting-network/index.html#discovering-hosts-from-the-outside). W zależności od tego, jakie usługi działają, możesz znaleźć w **tej książce kilka trików, jak je "atakować"**.\
_Uwaga: czasami subdomain jest hostowany na IP, nad którym klient nie ma kontroli, więc nie jest ono w scope — uważaj._

## IPs

Na początkowych etapach mogłeś **znaleźć jakieś zakresy IP, domeny i subdomains**.\
Czas zebrać wszystkie IP z tych zakresów oraz z **domen/subdomains (zapytania DNS).**

Korzystając z usług z poniższych **free apis**, możesz też znaleźć **previous IPs używane przez domeny i subdomains**. Te IP mogą nadal należeć do klienta (i mogą pozwolić ci znaleźć [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz też sprawdzić domeny wskazujące na określony adres IP za pomocą narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Looking for vulnerabilities**

**Przeskanuj porty wszystkich IP, które nie należą do CDNów** (ponieważ z dużym prawdopodobieństwem nie znajdziesz tam nic interesującego). W wykrytych działających usługach możesz **znaleźć vulnerabilities**.

**Znajdź** [**guide**](../pentesting-network/index.html) **o tym, jak skanować hosty.**

## Web servers hunting

> Znaleźliśmy wszystkie firmy i ich zasoby oraz znamy zakresy IP, domeny i subdomains w scope. Czas szukać web servers.

W poprzednich krokach prawdopodobnie wykonałeś już część **recon IP i domen, które wykryłeś**, więc mogłeś już **znaleźć wszystkie możliwe web servers**. Jeśli jednak tak się nie stało, to teraz zobaczymy kilka **szybkich trików do wyszukiwania web servers** w zakresie.

Pamiętaj, że będzie to **nastawione na discovery web apps**, więc powinieneś także **wykonać vulnerability** oraz **port scanning** (**jeśli pozwala na to** scope).

**Szybką metodę** wykrywania **otwartych portów** związanych z **web** serverami za pomocą [**masscan** można znaleźć tutaj](../pentesting-network/index.html#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania web servers są [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy podać listę domen, a narzędzie spróbuje połączyć się z portem 80 (http) i 443 (https). Dodatkowo możesz wskazać inne porty, które ma sprawdzić:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

Teraz, gdy odkryłeś **wszystkie serwery webowe** obecne w zakresie (wśród **IP** firmy oraz wszystkich **domen** i **subdomen**) prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy więc to i zacznijmy po prostu robić ich zrzuty ekranu. Już sam **rzut oka** na **stronę główną** może ujawnić **dziwne** endpointy, które są **bardziej podatne** na **vulnerability**.

Aby zrealizować ten pomysł, możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto możesz potem użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przeanalizować wszystkie **zrzuty ekranu** i powiedzieć ci, **co prawdopodobnie zawiera vulnerability**, a co nie.

## Public Cloud Assets

Aby znaleźć potencjalne cloud assets należące do firmy, powinieneś **zacząć od listy słów kluczowych identyfikujących tę firmę**. Na przykład, dla firmy crypto możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Będziesz też potrzebować wordlists z **popularnymi słowami używanymi w bucketach**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie, używając tych słów, powinieneś wygenerować **permutations** (sprawdź [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round), aby uzyskać więcej informacji).

Z wynikowymi wordlists możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając Cloud Assets, powinieneś szu**kać czegoś więcej niż tylko bucketów w AWS**.

### **Looking for vulnerabilities**

Jeśli znajdziesz takie rzeczy jak **otwarte buckety lub wystawione cloud functions**, powinieneś **uzyskać do nich dostęp** i spróbować sprawdzić, co oferują i czy możesz to nadużyć.

## Emails

Mając **domeny** i **subdomeny** w zakresie, zasadniczo masz wszystko, czego **potrzebujesz, aby zacząć szukać emaili**. Oto **APIs** i **narzędzia**, które najlepiej sprawdzały się u mnie do znajdowania emaili firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emaile przydadzą się później do **brute-force web logins and auth services** (takich jak SSH). Są też potrzebne do **phishings**. Ponadto te APIs dadzą ci jeszcze więcej **info about the person** stojącym za emailem, co jest przydatne w kampanii phishingowej.

## Credential Leaks

Mając **domeny,** **subdomeny** i **emaile**, możesz zacząć szukać credentiali wyciekłych w przeszłości, należących do tych emaili:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

Jeśli znajdziesz **valid leaked** credentiale, to bardzo łatwy win.

## Secrets Leaks

Credential leaks są powiązane z hackami firm, w których **wrażliwe informacje wyciekły i zostały sprzedane**. Jednak firmy mogą być dotknięte także przez **inne leak**i, których info nie ma w tych bazach:

### Github Leaks

Credentiale i APIs mogą wyciec do **public repositories** **company** lub użytkowników pracujących w tej firmie github.\
Możesz użyć **tool** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **public repos** organizacji i jej **developers** oraz automatycznie uruchomić na nich [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** może być też używany do uruchamiania **gitleaks** przeciwko wszystkim **text** podanym przez **URLs passed** do niego, ponieważ czasem **web pages also contains secrets**.

#### Github Dorks

Sprawdź także tę **page** pod kątem potencjalnych **github dorks**, których możesz również szukać w organizacji, którą atakujesz:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Czasami atakujący albo po prostu pracownicy będą **publikować firmową treść na paste site**. Może to zawierać albo nie zawierać **wrażliwych informacji**, ale warto tego szukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby przeszukiwać jednocześnie ponad 80 paste sites.

### Google Dorks

Stare, ale dobre google dorks są zawsze przydatne do znajdowania **exposed information that shouldn't be there**. Jedyny problem polega na tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie da się uruchomić ręcznie. Możesz więc wybrać swoje ulubione 10 albo użyć **tool such as** [**Gorks**](https://github.com/carlospolop/Gorks) **to run them all**.

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

Jeśli znajdziesz **valid leaked** credentiale lub tokeny API, to bardzo łatwy win.

## Public Code Vulnerabilities

Jeśli odkryłeś, że firma ma **open-source code**, możesz go **analysować** i szukać w nim **vulnerabilities**.

**Depending on the language** istnieją różne **tools**, których możesz użyć:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Są też darmowe usługi, które pozwalają **scan public repositories**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Większość vulnerabilities** znajdowanych przez bug hunterów znajduje się w **web applications**, więc w tym miejscu chciałbym porozmawiać o **metodologii testowania web application**, a **tutaj znajdziesz te informacje**([**../../network-services-pentesting/pentesting-web/index.html**](../../network-services-pentesting/pentesting-web/index.html)).

Chcę też wyróżnić sekcję [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ choć nie powinieneś oczekiwać, że znajdą ci bardzo wrażliwe vulnerabilities, to są przydatne do wdrożenia ich w **workflows**, aby uzyskać początkowe informacje o web.

## Recapitulation

> Gratulacje! Na tym etapie wykonałeś już **całą podstawową enumerację**. Tak, jest podstawowa, ponieważ można zrobić znacznie więcej enumeracji (więcej trików zobaczymy później).

Więc masz już:

1. Znalezione wszystkie **companies** w zakresie
2. Znalezione wszystkie **assets** należące do firm (i wykonany ewentualny scan vuln, jeśli jest w zakresie)
3. Znalezione wszystkie **domains** należące do firm
4. Znalezione wszystkie **subdomains** domen (czy jest jakieś subdomain takeover?)
5. Znalezione wszystkie **IP** (z **CDNs** i spoza nich) w zakresie.
6. Znalezione wszystkie **web servers** i zrobiony **screenshot** każdego z nich (czy coś dziwnego wartego głębszego spojrzenia?)
7. Znalezione wszystkie **potential public cloud assets** należące do firmy.
8. **Emails**, **credential leaks** i **secret leaks**, które mogą dać ci **duży win bardzo łatwo**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

Istnieje kilka narzędzi, które wykonają część proponowanych działań dla danego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Trochę stare i nieaktualizowane

## **References**

- Wszystkie darmowe kursy [**@Jhaddix**](https://twitter.com/Jhaddix), takie jak [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
