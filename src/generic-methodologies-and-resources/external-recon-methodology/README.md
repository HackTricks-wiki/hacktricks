# Metodyka zewnętrznego rozpoznania

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano Ci, że wszystko należące do pewnej firmy znajduje się w zakresie, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie informacji o wszystkich **firmach należących do głównej firmy**, a następnie o wszystkich **zasobach** tych firm. Aby to zrobić, będziemy:<sup>[[1]](#references)</sup>

1. Znajdziemy przejęcia głównej firmy, co pozwoli nam ustalić firmy znajdujące się w zakresie.
2. Znajdziemy ASN (jeśli istnieje) każdej firmy, co pozwoli nam ustalić zakresy IP należące do każdej z nich
3. Użyjemy reverse whois lookups do wyszukania innych wpisów (nazw organizacji, domen...) powiązanych z pierwszym wpisem (można to wykonywać rekurencyjnie)
4. Użyjemy innych technik, takich jak filtry `org` i `ssl` w shodan, aby wyszukać inne zasoby (trik z `ssl` można wykonywać rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy wiedzieć, które **inne firmy należą do głównej firmy**.\
Jedną z opcji jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** **głównej firmy** i **kliknięcie** opcji "**acquisitions**". Zobaczysz tam inne firmy przejęte przez główną firmę.\
Inną opcją jest odwiedzenie strony **Wikipedia** głównej firmy i wyszukanie informacji o **acquisitions**.\
W przypadku spółek publicznych sprawdź **SEC/EDGAR filings**, strony **investor relations** lub lokalne rejestry korporacyjne (np. **Companies House** w Wielkiej Brytanii).\
W przypadku globalnych struktur korporacyjnych i spółek zależnych spróbuj użyć **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazy danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> W porządku, na tym etapie powinieneś znać wszystkie firmy znajdujące się w zakresie. Ustalmy teraz, jak znaleźć ich zasoby.

### **ASN-y**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, które mają jasno określoną politykę dostępu do sieci zewnętrznych i są zarządzane przez jedną organizację, ale mogą składać się z kilku operatorów.

Warto sprawdzić, czy **firmie przypisano jakikolwiek ASN**, aby znaleźć jej **zakresy IP.** Warto przeprowadzić **test podatności** wszystkich **hostów** znajdujących się w **zakresie** oraz **poszukać domen** w obrębie tych adresów IP.\
Możesz **wyszukiwać** po **nazwie** firmy, **IP** lub **domenie** w serwisach [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu, w którym znajduje się firma, te linki mogą być przydatne do zebrania większej ilości danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** znajdują się już w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ponadto enumeracja [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** automatycznie agreguje i podsumowuje ASN-y na końcu skanowania.
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
Zakresy IP organizacji można również znaleźć za pomocą [http://asnlookup.com/](http://asnlookup.com) (dostępne jest bezpłatne API).\
Adres IP i ASN domeny można znaleźć za pomocą [http://ipv4info.com/](http://ipv4info.com).

### **Wyszukiwanie podatności**

Na tym etapie znamy **wszystkie zasoby znajdujące się w zakresie**, więc jeśli masz na to zgodę, możesz uruchomić **skaner podatności** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) dla wszystkich hostów.\
Możesz również uruchomić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub użyć usług takich jak** Shodan, Censys albo ZoomEye, **aby znaleźć** otwarte porty, **a następnie, w zależności od tego, co znajdziesz, powinieneś** zajrzeć do tej książki, aby dowiedzieć się, jak przeprowadzać pentesting różnych potencjalnych uruchomionych usług.\
**Warto również wspomnieć, że możesz przygotować** listy domyślnych nazw użytkowników **i** haseł **oraz spróbować przeprowadzić** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy wszystkie firmy znajdujące się w zakresie oraz ich zasoby; czas znaleźć domeny znajdujące się w zakresie.

_Należy pamiętać, że za pomocą poniższych proponowanych technik można również znaleźć subdomeny, a tych informacji nie należy lekceważyć._

Przede wszystkim należy znaleźć **główną domenę**(y) każdej firmy. Na przykład w przypadku _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Ponieważ znaleziono wszystkie zakresy IP domen, można spróbować wykonać **reverse dns lookups** dla tych **IP, aby znaleźć więcej domen znajdujących się w zakresie**. Spróbuj użyć serwera dns ofiary lub któregoś ze znanych serwerów dns (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Aby to zadziałało, administrator musi ręcznie włączyć PTR.\
Możesz również użyć narzędzia online, aby uzyskać te informacje: [http://ptrarchive.com/](http://ptrarchive.com).\
W przypadku dużych zakresów przydatne są narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), które automatyzują reverse lookups i wzbogacanie danych.

### **Reverse Whois (loop)**

W ramach **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **adresy e-mail**, numery telefonów... Jeszcze ciekawsze jest to, że można znaleźć **więcej assetów powiązanych z firmą**, wykonując **reverse whois lookups na podstawie dowolnego z tych pól** (na przykład inne rejestry whois, w których pojawia się ten sam adres e-mail).\
Możesz użyć narzędzi online, takich jak:

- [https://ip.thc.org/](https://ip.thc.org/) - **Darmowe** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Darmowe**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Darmowe**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Darmowe**
- [https://www.whoxy.com/](https://www.whoxy.com) - Darmowy dostęp przez Web, API jest płatne.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Płatne
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Płatne (tylko **100 darmowych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Płatne
- [https://securitytrails.com/](https://securitytrails.com/) - Płatne (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Płatne (API)

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink)(wymaga klucza API whoxy).\
Możesz również przeprowadzić częściowo automatyczne reverse whois discovery za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz używać tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackery**

Jeśli znajdziesz **ten sam ID tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli zobaczysz ten sam **Google Analytics ID** lub ten sam **Adsense ID** na kilku stronach.

Istnieją strony i narzędzia, które pozwalają wyszukiwać na podstawie tych trackerów i innych danych:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (znajduje powiązane strony na podstawie współdzielonych analytics/trackerów)

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, wyszukując ten sam hash ikony favicon? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
Mówiąc prosto, favihash pozwoli nam znaleźć domeny, które mają taki sam hash ikony favicon jak nasz cel.

![Wynik favihash użyty do znalezienia domen z takim samym hashem favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Użyj znanego hasha favicon jako pivotu w Shodan lub FOFA, aby znaleźć inne ujawnione instancje tej samej technologii.<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Oto jak można **obliczyć hash faviconu** strony internetowej (MMH3 na **zakodowanych w base64** bajtach faviconu):
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
Możesz również uzyskiwać hashe faviconów na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a następnie wykonywać pivoting w Shodan/Censys.

Traktuj fingerprinty faviconów jako wskazówki i weryfikuj je za pomocą sygnałów kontekstowych.<sup>[[3]](#references)[[4]](#references)</sup>

- **Traktuj hash jako wskaźnik, a nie dowód**: MMH3 jest kompaktowy; możliwe są kolizje, ponowne użycie ikon i celowe spoofing.
- **Sprawdzaj więcej niż** `/favicon.ico`: analizuj ścieżki frameworków/buildów, pliki manifestów, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, wbudowane data URL oraz tagi HTML `<link rel="icon">`.
- **Statyczne assety mogą pozostać dostępne za kontrolami WAF/SSO/IdP**: żądaj ikony bezpośrednio i analizuj nagłówki `ETag`, `Last-Modified`, przekierowania oraz nagłówki cache.
- **Weryfikuj dopasowania za pomocą sygnałów kontekstowych**: porównuj tytuł, hash HTML/body, nagłówki, subject/SAN certyfikatu TLS, komponenty produktu oraz exposed ports.
- **Grupuj według hasha HTML/body**: spójny template wzmacnia fingerprint; różne template'y sugerują generyczną lub współdzieloną ikonę.
- **Traktuj hash pojawiający się wśród niepowiązanych sygnatur, portów i produktów jako potencjalny honeypot lub placeholder.**
- **W przypadku niejednoznacznych celów porównaj prawdziwą stronę z nieistniejącą ścieżką**, taką jak `/_favicon_probe_<8-hex>`; identyczne odpowiedzi hostingu lub parkingu mogą wyjaśniać współdzieloną ikonę.
- **Rozpocznij triage na podstawie reguł detekcji Nuclei lub publicznych datasetów**, które mapują hashe faviconów na produkty i CPE.
- **Pamiętaj o luce w pokryciu skoncentrowanym na IP**: powierzchnie frontowane przez CDN, routowane za pomocą SNI, anycast oraz powierzchnie dostępne wyłącznie przez domenę mogą nie występować w datasetach podobnych do Shodan.

### **Copyright / Uniq string**

Wyszukuj wewnątrz stron internetowych **stringi, które mogą być współdzielone przez różne witryny w tej samej organizacji**. Dobrym przykładem może być **string copyrightu**. Następnie wyszukaj ten string w **Google**, w innych **przeglądarkach** lub nawet w **Shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się cron job taki jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
aby odnowić wszystkie certyfikaty na serwerze jednocześnie. Korelowanie znaczników czasu certyfikatów lub pozycji w logach certificate transparency może ujawnić powiązane domeny.<sup>[[6]](#references)</sup>

Możesz również bezpośrednio korzystać z logów **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje Mail DMARC

Możesz użyć strony takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny współdzielące te same informacje DMARC**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Porzucony rekord A może stać się osiągalny, gdy dostawca cloud ponownie przydzieli adres IP. Opisane badania przedstawiają oportunistyczny workflow, który tworzy instancję i koreluje jej adres z danymi passive DNS; scenariusze takeover testuj wyłącznie w ramach autoryzowanego zakresu.<sup>[[7]](#references)</sup>

### **Inne sposoby**

Powtarzaj odpowiednie pivots związane z discovery za każdym razem, gdy znajdziesz nową domenę: każdy wynik może ujawnić dodatkowe nazwy certyfikatów, zależności passive-DNS, dopasowania favicon oraz identyfikatory organizacji, które nie były widoczne na podstawie pierwotnego seeda.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Jak już wiesz, znasz nazwę organizacji będącej właścicielem przestrzeni adresowej IP. Możesz wyszukać te dane w shodan, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz uzyskać dostęp do **certyfikatu TLS** głównej strony internetowej, pobrać **nazwę organizacji**, a następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych **shodan** za pomocą filtra: `ssl:"Tesla Motors"` lub użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie, które wyszukuje **domeny powiązane** z główną domeną oraz ich **subdomeny** — jest naprawdę świetne.

**Passive DNS / Historical DNS**

Dane Passive DNS świetnie pomagają znajdować **stare i zapomniane rekordy**, które nadal rozwiązują się do adresu lub które można przejąć. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Poszukiwanie podatności**

Sprawdź, czy występuje [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa domeny**, ale **utraciła do niej prawa własności**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz dowolną **domenę z adresem IP innym** niż te, które już znalazłeś podczas asset discovery, powinieneś wykonać **basic vulnerability scan** (za pomocą Nessus lub OpenVAS) oraz [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) z użyciem **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **tej książce pewne triki umożliwiające ich „atakowanie”**.\
_Należy pamiętać, że czasami domena jest hostowana na adresie IP, który nie jest kontrolowany przez klienta, więc nie należy do zakresu; zachowaj ostrożność._

## Subdomeny

> Znamy wszystkie firmy objęte zakresem, wszystkie zasoby każdej firmy oraz wszystkie domeny powiązane z tymi firmami.

Czas znaleźć wszystkie możliwe subdomeny każdej znalezionej domeny.

> [!TIP]
> Pamiętaj, że niektóre narzędzia i techniki służące do znajdowania domen mogą również pomóc w znajdowaniu subdomen

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy również spróbować wykonać **Zone Transfer** (jeśli jest podatny, należy to zgłosić).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Najszybszym sposobem na uzyskanie dużej liczby subdomen jest przeszukiwanie zewnętrznych źródeł. Najczęściej używane **narzędzia** to:

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
Istnieją **inne interesujące narzędzia/API**, które, nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomen, mogą być przydatne do znajdowania subdomen, takie jak:

- [**IP.THC.ORG**](https://ip.thc.org) darmowe API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskiwania subdomen
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
- [**Wyszukiwarka subdomen Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) oferuje darmowe API do wyszukiwania subdomen i historii adresów IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ten projekt oferuje **bezpłatnie wszystkie subdomeny powiązane z programami bug-bounty**. Możesz uzyskać dostęp do tych danych również za pomocą [chaospy](https://github.com/dr-0x0x/chaospy) lub uzyskać dostęp do zakresu używanego przez ten projekt: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

[**Porównanie**](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off) wielu z tych narzędzi znajdziesz tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny**, wykonując brute-force serwerów DNS przy użyciu możliwych nazw subdomen.

Do tego działania potrzebujesz **list słów zawierających popularne subdomeny, takich jak**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebujesz również adresów IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać resolvery z [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich przefiltrowania. Możesz też użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej zalecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): Było to pierwsze narzędzie, które skutecznie wykonywało DNS brute-force. Jest bardzo szybkie, jednak podatne na false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ten, jak sądzę, korzysta tylko z 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper na `massdns`, napisany w Go, który umożliwia enumerację poprawnych subdomen za pomocą active bruteforce, a także rozwiązywanie subdomen z obsługą wildcardów i łatwym wsparciem wejścia-wyjścia.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego przeprowadzania brute force nazw domen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS brute-force

Po znalezieniu subdomen za pomocą open sources i brute-forcingu możesz wygenerować warianty znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Do tego celu przydatnych jest kilka narzędzi:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na podstawie domen i subdomen generuje permutacje.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na podstawie domen i subdomen generuje permutacje.
- Listę słów **wordlist** dla permutacji goaltdns można znaleźć [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na podstawie domen i subdomen generuje permutacje. Jeśli nie wskażesz pliku permutacji, gotator użyje własnego pliku.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może również próbować je rozwiązywać (ale lepiej użyć wcześniej wymienionych narzędzi).
- Listę słów (**wordlist**) z permutacjami altdns można znaleźć [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutations, mutations i alteration subdomen. To narzędzie przeprowadzi brute force wyniku (nie obsługuje DNS wildcard).
- Listę słów dmut permutations można znaleźć [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy subdomen** zgodnie ze wskazanymi wzorcami, aby spróbować odkryć więcej subdomen.

#### Inteligentne generowanie permutacji

- [**regulator**](https://github.com/cramppet/regulator): Uczy się wzorców podobnych do regexów na podstawie odkrytych subdomen i generuje nazwy kandydatów do rozwiązania DNS.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to fuzzer do brute-force subdomen, wykorzystujący niezwykle prosty, ale skuteczny algorytm sterowany odpowiedziami DNS. Korzysta z dostarczonego zestawu danych wejściowych, takiego jak dostosowana wordlista lub historyczne rekordy DNS/TLS, aby dokładnie generować kolejne odpowiadające nazwy domen i iteracyjnie rozszerzać je na podstawie informacji zebranych podczas skanowania DNS.
```
echo www | subzuf facebook.com
```
### **Workflow wykrywania subdomen**

Przykłady workflowów Trickest łączą OSINT, brute force DNS i etapy permutacji, umożliwiając powtarzalną enumerację subdomen.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami na tym IP**, wyszukując w **źródłach OSINT** domeny przypisane do adresu IP lub wykonując **brute force nazw domen VHost na tym IP**.

#### OSINT

Możesz znaleźć niektóre **VHosty na adresach IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze webowym, możesz spróbować wykonać na niej brute force:

W przypadku vhostów opartych na nazwach wykonaj fuzzing nagłówka `Host` i użyj auto-kalibracji ffuf, aby odfiltrować domyślną odpowiedź.<sup>[[2]](#references)</sup>
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

Czasami znajdziesz strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/subdomena. W takich scenariuszach możesz wykorzystać to zachowanie do **odkrywania** nowych **subdomen**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Podczas wyszukiwania **subdomains** zwróć uwagę, czy któryś z nich **wskazuje** na dowolnego rodzaju **bucket**, a jeśli tak, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponadto, ponieważ na tym etapie znasz już wszystkie domeny znajdujące się w zakresie, spróbuj [**brute force możliwych nazw bucketów i sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorowanie**

Możesz **monitorować**, czy tworzone są **nowe subdomains** danej domeny, monitorując logi **Certificate Transparency**, co robi [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Wyszukiwanie podatności**

Sprawdź możliwe przypadki [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomain** wskazuje na jakiś **S3 bucket**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz **subdomain z adresem IP innym** niż te, które znalazłeś podczas odkrywania assetów, powinieneś przeprowadzić **podstawowy skan podatności** (za pomocą Nessus lub OpenVAS) oraz wykonać [**skan portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **tej książce pewne triki pozwalające je „zaatakować”**.\
_Należy pamiętać, że czasami subdomain jest hostowany wewnątrz adresu IP, który nie jest kontrolowany przez klienta, więc nie znajduje się w zakresie — zachowaj ostrożność._

## IPs

Na początkowych etapach mogłeś **znaleźć pewne zakresy IP, domeny i subdomains**.\
Nadszedł czas, aby **zebrać wszystkie adresy IP z tych zakresów** oraz dla **domen/subdomains (zapytania DNS).**

Korzystając z usług udostępnianych przez poniższe **free APIs**, możesz również znaleźć **wcześniejsze adresy IP używane przez domeny i subdomains**. Te adresy IP mogą nadal należeć do klienta (i mogą pozwolić ci znaleźć [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz również sprawdzić domeny wskazujące na konkretny adres IP za pomocą narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Wyszukiwanie podatności**

**Przeskanuj wszystkie adresy IP, które nie należą do CDN-ów** (ponieważ najprawdopodobniej nie znajdziesz tam nic interesującego). W wykrytych uruchomionych usługach możesz **znaleźć podatności**.

**Znajdź** [**guide**](../pentesting-network/index.html) **na temat skanowania hostów.**

## Poszukiwanie web serverów

> Znaleźliśmy wszystkie firmy i ich assety oraz znamy zakresy IP, domeny i subdomains znajdujące się w zakresie. Nadszedł czas, aby wyszukać web servery.

W poprzednich krokach prawdopodobnie wykonałeś już pewien **recon adresów IP i znalezionych domen**, więc być może **znalazłeś już wszystkie możliwe web servery**. Jeśli jednak tego nie zrobiłeś, teraz przedstawimy kilka **szybkich trików do wyszukiwania web serverów** w zakresie.

Pamiętaj, że będzie to **ukierunkowane na odkrywanie web apps**, dlatego powinieneś również **wykonać skanowanie podatności** oraz **skanowanie portów** (**jeśli zakres na to pozwala**).

**Szybka metoda** wykrywania **otwartych portów** powiązanych z web serverami za pomocą [**masscan** znajduje się tutaj](../pentesting-network/index.html#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania web serverów jest [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy przekazać listę domen, a narzędzie spróbuje połączyć się z portem 80 (http) i 443 (https). Dodatkowo możesz wskazać inne porty do sprawdzenia:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery webowe** znajdujące się w zakresie (wśród **IP** firmy oraz wszystkich **domen** i **subdomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy to więc i zacznijmy od wykonania zrzutów ekranu wszystkich z nich. Już samo **spojrzenie** na **stronę główną** może ujawnić **dziwne** endpointy, które są bardziej **podatne** na występowanie **podatności**.

Do wykonania tego zadania możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto możesz użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przeanalizować wszystkie **zrzuty ekranu** i określić, **co prawdopodobnie zawiera podatności**, a co nie.

## Public Cloud Assets

Aby znaleźć potencjalne zasoby cloud należące do firmy, powinieneś **zacząć od listy słów kluczowych identyfikujących tę firmę**. Na przykład w przypadku firmy crypto możesz użyć takich słów jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Potrzebujesz również wordlist zawierających **często używane słowa występujące w bucketach**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie, używając tych słów, powinieneś wygenerować **permutacje** (więcej informacji znajdziesz w sekcji [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Z otrzymanymi wordlistami możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że podczas wyszukiwania Cloud Assets powinieneś **szukać nie tylko bucketów w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz takie elementy jak **otwarte buckety lub ujawnione cloud functions**, powinieneś **uzyskać do nich dostęp** i sprawdzić, co oferują oraz czy możesz je wykorzystać.

## Emaile

Mając w zakresie **domeny** i **subdomeny**, zasadniczo masz wszystko, czego **potrzebujesz, aby rozpocząć wyszukiwanie emaili**. Poniżej znajdują się **API** i **narzędzia**, które najlepiej sprawdzały się u mnie podczas wyszukiwania emaili firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (wersja darmowa)
- API [**https://app.snov.io/**](https://app.snov.io/) (wersja darmowa)
- API [**https://minelead.io/**](https://minelead.io/) (wersja darmowa)

### **Szukanie podatności**

Emaile przydadzą się później do **brute-force'owania logowań webowych i usług auth** (takich jak SSH). Są również potrzebne do **phishingu**. Ponadto te API dostarczą ci jeszcze więcej **informacji o osobie** stojącej za adresem email, co jest przydatne podczas kampanii phishingowej.

## Credential Leaks

Mając **domeny,** **subdomeny** oraz **emaile**, możesz rozpocząć wyszukiwanie credentials, które w przeszłości wyciekły i należały do tych adresów email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe credentials pochodzące z leak**, będzie to bardzo łatwy sukces.

## Secrets Leaks

Credential leaks są związane z hackami firm, podczas których **wrażliwe informacje wyciekły i zostały sprzedane**. Firmy mogą jednak paść ofiarą **innych leak**, których informacje nie znajdują się w tych bazach:

### Github Leaks

Credentials i API mogą wyciec do **publicznych repozytoriów** **firmy** lub **użytkowników** pracujących dla tej firmy na githubie.\
Możesz użyć **tool** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** **organizacji** i jej **developerów**, a następnie automatycznie uruchomić na nich [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** może być również używany do uruchamiania **gitleaks** przeciwko całemu **tekstowi** dostarczonemu przez **przekazane URL-e**, ponieważ czasami **strony webowe również zawierają sekrety**.

#### Github Dorks

Sprawdź [stronę GitHub dorks and leaks](github-leaked-secrets.md), aby znaleźć potencjalne **GitHub dorks** do wyszukania w organizacji.

### Pastes Leaks

Czasami atakujący lub po prostu pracownicy **publikują treści firmy na stronie paste**. Mogą, ale nie muszą, zawierać **wrażliwe informacje**, jednak bardzo interesujące jest ich wyszukanie.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie wyszukiwać w ponad 80 serwisach paste.

### Google Dorks

Stare, ale nadal skuteczne google dorks są zawsze przydatne do znajdowania **ujawnionych informacji, które nie powinny być dostępne**. Jedyny problem polega na tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie możesz uruchomić ręcznie. Możesz więc wybrać 10 swoich ulubionych albo użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks), **aby uruchomić je wszystkie**.

_Należy pamiętać, że narzędzia próbujące przeszukać całą bazę za pomocą zwykłej przeglądarki Google nigdy nie zakończą działania, ponieważ Google bardzo szybko cię zablokuje._

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe credentials pochodzące z leak** lub tokeny API, będzie to bardzo łatwy sukces.

## Podatności publicznego kodu

Jeśli odkryłeś, że firma posiada **kod open source**, możesz go **przeanalizować** i wyszukać w nim **podatności**.

**W zależności od języka** możesz użyć różnych **narzędzi**; zobacz listę [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Dostępne są również bezpłatne usługi umożliwiające **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Metodyka Pentestingu Web**](../../network-services-pentesting/pentesting-web/index.html)

**Większość podatności** znajdowanych przez bug hunterów znajduje się w **aplikacjach webowych**, dlatego w tym miejscu chciałbym omówić **metodykę testowania aplikacji webowych**. [**Informacje te znajdziesz tutaj**](../../network-services-pentesting/pentesting-web/index.html).

Chciałbym również szczególnie wspomnieć o sekcji [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ chociaż nie należy oczekiwać, że znajdą bardzo wrażliwe podatności, są przydatne do wdrażania ich w **workflowach w celu uzyskania wstępnych informacji o webie.**

## Podsumowanie

> Gratulacje! Na tym etapie wykonałeś już **całą podstawową enumerację**. Tak, jest podstawowa, ponieważ można przeprowadzić znacznie więcej enumeracji (więcej trików omówimy później).

Masz już:

1. Znalezione wszystkie **firmy** znajdujące się w zakresie
2. Znalezione wszystkie **zasoby** należące do firm (oraz wykonane skanowanie podatności, jeśli było w zakresie)
3. Znalezione wszystkie **domeny** należące do firm
4. Znalezione wszystkie **subdomeny** domen (czy możliwy jest subdomain takeover?)
5. Znalezione wszystkie **IP** (z **CDN** i **spoza CDN**) znajdujące się w zakresie.
6. Znalezione wszystkie **serwery webowe** i wykonane ich **zrzuty ekranu** (czy jest coś dziwnego, co warto dokładniej zbadać?)
7. Znalezione wszystkie **potencjalne publiczne zasoby cloud** należące do firmy.
8. Znalezione **emaile**, **credential leaks** i **secret leaks**, które mogą bardzo łatwo zapewnić ci **duży sukces**.
9. Wykonany **pentesting wszystkich znalezionych webów**

## **Automatyczne narzędzia do pełnego recon**

Istnieje wiele narzędzi, które wykonują część proponowanych działań dla określonego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Trochę stare i nieaktualizowane

## References

- [1] [Jason Haddix – Metodyka Bug Huntera w wersji v4.0: edycja Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O faviconach: od ikon przeglądarki do analizy attack surface](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Wykorzystanie favicon.ico w BugBounties, OSINT i nie tylko](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Odkrywanie domen za pomocą ataku korelacji czasowej na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: ujawnienie (i emulacja) kosztownej kampanii subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: unikalna metoda enumeracji subdomen](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Pełny workflow odkrywania subdomen, część 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Pełne odkrywanie subdomen metodą brute force z użyciem zautomatyzowanego workflow Trickest, część 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – zrzut ekranu wyniku favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
