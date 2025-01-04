# Metodologia Zewnętrznego Rekonesansu

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano ci, że wszystko, co należy do jakiejś firmy, jest w zakresie, a ty chcesz dowiedzieć się, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie wszystkich **firm należących do głównej firmy** oraz wszystkich **zasobów** tych firm. Aby to zrobić, zamierzamy:

1. Znaleźć przejęcia głównej firmy, co da nam firmy w zakresie.
2. Znaleźć ASN (jeśli istnieje) każdej firmy, co da nam zakresy IP należące do każdej firmy.
3. Użyć odwrotnych wyszukiwań whois, aby poszukać innych wpisów (nazwy organizacji, domeny...) związanych z pierwszym (można to zrobić rekurencyjnie).
4. Użyć innych technik, takich jak filtry shodan `org` i `ssl`, aby poszukać innych zasobów (sztuczka `ssl` może być wykonana rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy wiedzieć, które **inne firmy są własnością głównej firmy**.\
Jedną z opcji jest odwiedzenie [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukiwanie** **głównej firmy** i **kliknięcie** na "**przejęcia**". Tam zobaczysz inne firmy nabyte przez główną.\
Inną opcją jest odwiedzenie strony **Wikipedia** głównej firmy i wyszukiwanie **przejęć**.

> Ok, w tym momencie powinieneś znać wszystkie firmy w zakresie. Dowiedzmy się, jak znaleźć ich zasoby.

### **ASN-y**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, które mają wyraźnie zdefiniowaną politykę dostępu do zewnętrznych sieci i są zarządzane przez jedną organizację, ale mogą składać się z kilku operatorów.

Interesujące jest sprawdzenie, czy **firma przypisała jakikolwiek ASN**, aby znaleźć jej **zakresy IP.** Warto przeprowadzić **test podatności** na wszystkie **hosty** w **zakresie** i **szukać domen** w tych IP.\
Możesz **wyszukiwać** według **nazwa firmy**, według **IP** lub według **domeny** w [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**W zależności od regionu firmy, te linki mogą być przydatne do zbierania dodatkowych danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie, prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** pojawiają się już w pierwszym linku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Również, [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeracja subdomen automatycznie agreguje i podsumowuje ASN na końcu skanowania.
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

### **Szukając luk w zabezpieczeniach**

Na tym etapie znamy **wszystkie zasoby w zakresie**, więc jeśli masz na to pozwolenie, możesz uruchomić jakiś **skaner luk** (Nessus, OpenVAS) na wszystkich hostach.\
Możesz również przeprowadzić [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub użyć usług takich jak** shodan **aby znaleźć** otwarte porty **i w zależności od tego, co znajdziesz, powinieneś** zajrzeć do tej książki, aby dowiedzieć się, jak przeprowadzić pentesting różnych możliwych usług.\
**Warto również wspomnieć, że możesz przygotować kilka** domyślnych nazw użytkowników **i** haseł **i spróbować** bruteforce'ować usługi za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy wszystkie firmy w zakresie i ich zasoby, czas znaleźć domeny w zakresie.

_Proszę zauważyć, że w poniższych proponowanych technikach możesz również znaleźć subdomeny i ta informacja nie powinna być niedoceniana._

Przede wszystkim powinieneś poszukać **głównej domeny**(s) każdej firmy. Na przykład, dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Ponieważ znalazłeś wszystkie zakresy IP domen, możesz spróbować wykonać **odwrotne zapytania DNS** na tych **IP, aby znaleźć więcej domen w zakresie**. Spróbuj użyć jakiegoś serwera DNS ofiary lub jakiegoś znanego serwera DNS (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Aby to zadziałało, administrator musi ręcznie włączyć PTR.\
Możesz również użyć narzędzia online do uzyskania tych informacji: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

W **whois** możesz znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **emaile**, numery telefonów... Ale co jest jeszcze bardziej interesujące, to to, że możesz znaleźć **więcej zasobów związanych z firmą**, jeśli wykonasz **odwrócone zapytania whois według dowolnego z tych pól** (na przykład inne rejestry whois, w których pojawia się ten sam email).\
Możesz użyć narzędzi online, takich jak:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Darmowe**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Darmowe**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Darmowe**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Darmowe** web, nie darmowe API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Nie darmowe
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie darmowe (tylko **100 darmowych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie darmowe

Możesz zautomatyzować to zadanie, używając [**DomLink** ](https://github.com/vysecurity/DomLink) (wymaga klucza API whoxy).\
Możesz również przeprowadzić automatyczne odkrywanie reverse whois za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Zauważ, że możesz użyć tej techniki, aby odkryć więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackers**

Jeśli znajdziesz **ten sam ID tego samego trackera** na 2 różnych stronach, możesz przypuszczać, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli widzisz ten sam **ID Google Analytics** lub ten sam **ID Adsense** na kilku stronach.

Istnieją strony i narzędzia, które pozwalają na wyszukiwanie według tych trackerów i więcej:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, szukając tego samego hasha ikony favicon? Dokładnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - odkryj domeny z tym samym hashem ikony favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc prosto, favihash pozwoli nam odkryć domeny, które mają ten sam hash ikony favicon co nasz cel.

Co więcej, możesz również wyszukiwać technologie, używając hasha favicon, jak wyjaśniono w [**tym wpisie na blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Oznacza to, że jeśli znasz **hash ikony favicon wrażliwej wersji technologii webowej**, możesz wyszukiwać w shodan i **znaleźć więcej wrażliwych miejsc**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
W ten sposób możesz **obliczyć hash favicony** strony internetowej:
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
### **Copyright / Uniq string**

Szukaj na stronach internetowych **ciągów, które mogą być udostępniane w różnych witrynach w tej samej organizacji**. **Ciąg praw autorskich** może być dobrym przykładem. Następnie wyszukaj ten ciąg w **google**, w innych **przeglądarkach** lub nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często występuje zadanie cron, takie jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
aby odnowić wszystkie certyfikaty domen na serwerze. Oznacza to, że nawet jeśli CA użyta do tego nie ustawia czasu, w którym został wygenerowany w czasie ważności, możliwe jest **znalezienie domen należących do tej samej firmy w logach przejrzystości certyfikatów**.\
Sprawdź ten [**artykuł, aby uzyskać więcej informacji**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### Informacje o DMARC w mailach

Możesz użyć strony internetowej takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny dzielące te same informacje DMARC**.

### **Pasywne przejęcie**

Wygląda na to, że powszechne jest przypisywanie subdomen do adresów IP należących do dostawców chmury i w pewnym momencie **utrata tego adresu IP, ale zapomnienie o usunięciu rekordu DNS**. Dlatego wystarczy **uruchomić VM** w chmurze (takiej jak Digital Ocean), aby faktycznie **przejąć niektóre subdomeny**.

[**Ten post**](https://kmsec.uk/blog/passive-takeover/) wyjaśnia historię na ten temat i proponuje skrypt, który **uruchamia VM w DigitalOcean**, **uzyskuje** **IPv4** nowej maszyny i **wyszukuje w Virustotal rekordy subdomen** wskazujące na nią.

### **Inne sposoby**

**Zauważ, że możesz użyć tej techniki, aby odkrywać więcej nazw domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Jak już wiesz, nazwa organizacji posiadającej przestrzeń IP. Możesz wyszukiwać te dane w shodan używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz uzyskać dostęp do **certyfikatu TLS** głównej strony internetowej, uzyskać **nazwę organizacji** i następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych przez **shodan** z filtrem: `ssl:"Tesla Motors"` lub użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) to narzędzie, które wyszukuje **domeny związane** z główną domeną oraz **subdomeny** z nimi, całkiem niesamowite.

### **Szukając luk w zabezpieczeniach**

Sprawdź niektóre [przejęcia domen](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Może jakaś firma **używa jakiejś domeny**, ale **straciła jej własność**. Po prostu zarejestruj ją (jeśli jest wystarczająco tania) i daj znać firmie.

Jeśli znajdziesz jakąkolwiek **domenę z adresem IP różnym** od tych, które już znalazłeś w odkrywaniu zasobów, powinieneś przeprowadzić **podstawowe skanowanie luk** (używając Nessus lub OpenVAS) oraz jakieś [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **tej książce kilka sztuczek, aby je "zaatakować"**.\
&#xNAN;_&#x4E;ote, że czasami domena jest hostowana w IP, które nie jest kontrolowane przez klienta, więc nie jest w zakresie, bądź ostrożny._

## Subdomeny

> Znamy wszystkie firmy w zakresie, wszystkie zasoby każdej firmy i wszystkie domeny związane z tymi firmami.

Czas znaleźć wszystkie możliwe subdomeny każdej znalezionej domeny.

> [!TIP]
> Zauważ, że niektóre narzędzia i techniki do znajdowania domen mogą również pomóc w znajdowaniu subdomen.

### **DNS**

Spróbujmy uzyskać **subdomeny** z rekordów **DNS**. Powinniśmy również spróbować **Transferu Strefy** (jeśli jest podatny, powinieneś to zgłosić).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

Naj szybszym sposobem na uzyskanie wielu subdomen jest przeszukiwanie zewnętrznych źródeł. Najczęściej używane **narzędzia** to następujące (dla lepszych wyników skonfiguruj klucze API):

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
Są **inne interesujące narzędzia/API**, które, nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomen, mogą być przydatne do ich znajdowania, takie jak:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskiwania subdomen
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
- [**gau**](https://github.com/lc/gau)**:** pobiera znane URL-e z Open Threat Exchange AlienVault, Wayback Machine i Common Crawl dla dowolnej domeny.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Zbierają dane z sieci w poszukiwaniu plików JS i wyodrębniają subdomeny stamtąd.
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

Ten projekt oferuje **darmowo wszystkie subdomeny związane z programami bug-bounty**. Możesz uzyskać dostęp do tych danych również za pomocą [chaospy](https://github.com/dr-0x0x/chaospy) lub nawet uzyskać dostęp do zakresu używanego przez ten projekt [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Możesz znaleźć **porównanie** wielu z tych narzędzi tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny** poprzez brute-forcing serwerów DNS, używając możliwych nazw subdomen.

Do tej akcji będziesz potrzebować kilku **popularnych list słów subdomen**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

A także IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać resolvery z [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich filtrowania. Lub możesz użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do brute-force DNS to:

- [**massdns**](https://github.com/blechschmidt/massdns): To było pierwsze narzędzie, które skutecznie przeprowadzało brute-force DNS. Jest bardzo szybkie, jednak jest podatne na fałszywe pozytywy.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Myślę, że ten używa tylko 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper wokół `massdns`, napisany w go, który pozwala na enumerację ważnych subdomen za pomocą aktywnego bruteforce, a także rozwiązywanie subdomen z obsługą wildcard i łatwym wsparciem dla wejścia-wyjścia.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego łamania nazw domen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda brute-force DNS

Po znalezieniu subdomen za pomocą otwartych źródeł i brute-forcingu, możesz wygenerować modyfikacje znalezionych subdomen, aby spróbować znaleźć jeszcze więcej. Kilka narzędzi jest przydatnych w tym celu:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Daje możliwość generowania permutacji na podstawie domen i subdomen.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Dla podanych domen i subdomen generuje permutacje.
- Możesz uzyskać permutacje goaltdns **wordlist** [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Podając domeny i subdomeny, generuje permutacje. Jeśli nie wskazano pliku z permutacjami, gotator użyje swojego własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen, może również próbować je rozwiązać (ale lepiej użyć wcześniej wspomnianych narzędzi).
- Możesz uzyskać permutacje altdns **wordlist** w [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Inne narzędzie do wykonywania permutacji, mutacji i modyfikacji subdomen. To narzędzie będzie przeprowadzać brute force na wyniku (nie obsługuje dzikich kart dns).
- Możesz pobrać listę słów permutacji dmut [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy subdomen** na podstawie wskazanych wzorców, aby spróbować odkryć więcej subdomen.

#### Generowanie inteligentnych permutacji

- [**regulator**](https://github.com/cramppet/regulator): Aby uzyskać więcej informacji, przeczytaj ten [**post**](https://cramppet.github.io/regulator/index.html), ale zasadniczo wyciągnie on **główne części** z **odkrytych subdomen** i wymiesza je, aby znaleźć więcej subdomen.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to narzędzie do brutalnego ataku na subdomeny, połączone z niezwykle prostym, ale skutecznym algorytmem opartym na odpowiedziach DNS. Wykorzystuje dostarczony zestaw danych wejściowych, takich jak dostosowana lista słów lub historyczne rekordy DNS/TLS, aby dokładnie syntetyzować więcej odpowiadających nazw domen i rozszerzać je jeszcze bardziej w pętli na podstawie informacji zebranych podczas skanowania DNS.
```
echo www | subzuf facebook.com
```
### **Workflow Odkrywania Subdomen**

Sprawdź ten post na blogu, który napisałem o tym, jak **zautomatyzować odkrywanie subdomen** z domeny za pomocą **workflow Trickest**, aby nie musieć ręcznie uruchamiać wielu narzędzi na moim komputerze:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Wirtualne Hosty**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami w tym IP**, przeszukując **źródła OSINT** w poszukiwaniu domen w danym IP lub **brute-forcując nazwy domen VHost w tym IP**.

#### OSINT

Możesz znaleźć kilka **VHosts w IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że niektóre subdomeny mogą być ukryte na serwerze WWW, możesz spróbować je brute force:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> Dzięki tej technice możesz nawet uzyskać dostęp do wewnętrznych/ukrytych punktów końcowych.

### **CORS Brute Force**

Czasami znajdziesz strony, które zwracają tylko nagłówek _**Access-Control-Allow-Origin**_, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/poddomena. W tych scenariuszach możesz wykorzystać to zachowanie, aby **odkryć** nowe **poddomeny**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Brute Force Buckets**

Podczas poszukiwania **subdomen** zwróć uwagę, czy wskazują one na jakikolwiek typ **bucket**, a w takim przypadku [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Również, w tym momencie, gdy znasz już wszystkie domeny w zakresie, spróbuj [**brute force'ować możliwe nazwy bucketów i sprawdzić uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitorowanie**

Możesz **monitorować**, czy **nowe subdomeny** danej domeny są tworzone, monitorując **logi przejrzystości certyfikatów** [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Poszukiwanie luk**

Sprawdź możliwe [**przejęcia subdomen**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomena** wskazuje na jakiś **bucket S3**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/).

Jeśli znajdziesz jakąkolwiek **subdomenę z adresem IP różnym** od tych, które już znalazłeś w odkrywaniu zasobów, powinieneś przeprowadzić **podstawowe skanowanie luk** (używając Nessus lub OpenVAS) oraz jakieś [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć w **tej książce kilka sztuczek, aby je "zaatakować"**.\
&#xNAN;_&#x4E;ote, że czasami subdomena jest hostowana w IP, które nie jest kontrolowane przez klienta, więc nie jest w zakresie, bądź ostrożny._

## IPs

W początkowych krokach mogłeś **znaleźć pewne zakresy IP, domeny i subdomeny**.\
Czas na **zebranie wszystkich IP z tych zakresów** oraz dla **domen/subdomen (zapytania DNS).**

Korzystając z usług z poniższych **darmowych API**, możesz również znaleźć **wcześniejsze IP używane przez domeny i subdomeny**. Te IP mogą nadal być własnością klienta (i mogą pozwolić Ci znaleźć [**obejścia CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz również sprawdzić, które domeny wskazują na konkretny adres IP, używając narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Poszukiwanie luk**

**Skanuj porty wszystkich IP, które nie należą do CDN** (ponieważ prawdopodobnie nie znajdziesz tam nic interesującego). W odkrytych usługach możesz **znaleźć luki**.

**Znajdź** [**przewodnik**](../pentesting-network/) **na temat skanowania hostów.**

## Polowanie na serwery WWW

> Znaleźliśmy wszystkie firmy i ich zasoby oraz znamy zakresy IP, domeny i subdomeny w zakresie. Czas na poszukiwanie serwerów WWW.

W poprzednich krokach prawdopodobnie już przeprowadziłeś jakieś **recon IP i odkrytych domen**, więc mogłeś **już znaleźć wszystkie możliwe serwery WWW**. Jednak jeśli tego nie zrobiłeś, teraz zobaczymy kilka **szybkich sztuczek do wyszukiwania serwerów WWW** w zakresie.

Proszę zauważyć, że to będzie **ukierunkowane na odkrywanie aplikacji webowych**, więc powinieneś **przeprowadzić skanowanie luk** i **skanowanie portów** również (**jeśli dozwolone** przez zakres).

**Szybka metoda** na odkrycie **otwartych portów** związanych z **serwerami** WWW za pomocą [**masscan** można znaleźć tutaj](../pentesting-network/index.html#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania serwerów WWW jest [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy, że przekażesz listę domen, a narzędzie spróbuje połączyć się z portem 80 (http) i 443 (https). Dodatkowo możesz wskazać, aby spróbować innych portów:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery internetowe** znajdujące się w zakresie (wśród **adresów IP** firmy oraz wszystkich **domen** i **subdomen**) prawdopodobnie **nie wiesz, od czego zacząć**. Zróbmy to prosto i zacznijmy od robienia zrzutów ekranu wszystkich z nich. Już po **rzuceniu okiem** na **stronę główną** możesz znaleźć **dziwne** punkty końcowe, które są bardziej **podatne** na bycie **wrażliwymi**.

Aby zrealizować zaproponowany pomysł, możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto, możesz następnie użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przejrzeć wszystkie **zrzuty ekranu** i powiedzieć ci, **co prawdopodobnie zawiera luki**, a co nie.

## Publiczne zasoby chmurowe

Aby znaleźć potencjalne zasoby chmurowe należące do firmy, powinieneś **zacząć od listy słów kluczowych, które identyfikują tę firmę**. Na przykład, dla firmy kryptograficznej możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Będziesz również potrzebować list słów **powszechnie używanych w bucketach**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie, z tymi słowami powinieneś wygenerować **permutacje** (sprawdź [**Drugą rundę DNS Brute-Force**](#second-dns-bruteforce-round) po więcej informacji).

Z uzyskanymi listami słów możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając zasobów chmurowych, powinieneś **szukać więcej niż tylko bucketów w AWS**.

### **Szukając luk**

Jeśli znajdziesz takie rzeczy jak **otwarte buckety lub wystawione funkcje chmurowe**, powinieneś **uzyskać do nich dostęp** i spróbować zobaczyć, co oferują i czy możesz je wykorzystać.

## E-maile

Mając **domeny** i **subdomeny** w zakresie, zasadniczo masz wszystko, co **potrzebujesz, aby zacząć szukać e-maili**. Oto **API** i **narzędzia**, które najlepiej działały dla mnie w znajdowaniu e-maili firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (wersja darmowa)
- API [**https://app.snov.io/**](https://app.snov.io/) (wersja darmowa)
- API [**https://minelead.io/**](https://minelead.io/) (wersja darmowa)

### **Szukając luk**

E-maile będą przydatne później do **brute-force'owania logowania do stron internetowych i usług autoryzacyjnych** (takich jak SSH). Ponadto są potrzebne do **phishingu**. Co więcej, te API dadzą ci jeszcze więcej **informacji o osobie** stojącej za e-mailem, co jest przydatne w kampanii phishingowej.

## Wycieki danych uwierzytelniających

Mając **domeny**, **subdomeny** i **e-maile**, możesz zacząć szukać danych uwierzytelniających, które wyciekły w przeszłości i należą do tych e-maili:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukając luk**

Jeśli znajdziesz **ważne wyciekłe** dane uwierzytelniające, to bardzo łatwe zwycięstwo.

## Wycieki sekretów

Wyciek danych uwierzytelniających jest związany z hackami firm, w których **wrażliwe informacje zostały wycieknięte i sprzedane**. Jednak firmy mogą być dotknięte **innymi wyciekami**, których informacje nie znajdują się w tych bazach danych:

### Wyciek z GitHub

Dane uwierzytelniające i API mogą być wycieknięte w **publicznych repozytoriach** firmy lub użytkowników pracujących dla tej firmy na GitHubie.\
Możesz użyć **narzędzia** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** organizacji i jej **deweloperów** oraz automatycznie uruchomić [**gitleaks**](https://github.com/zricethezav/gitleaks) na nich.

**Leakos** może być również używane do uruchamiania **gitleaks** przeciwko całemu **tekstowi** dostarczonemu **URL-om przekazanym** do niego, ponieważ czasami **strony internetowe również zawierają sekrety**.

#### Dorki GitHub

Sprawdź również tę **stronę** w poszukiwaniu potencjalnych **dorków GitHub**, które możesz również wyszukiwać w organizacji, którą atakujesz:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Wyciek Paste

Czasami napastnicy lub po prostu pracownicy **publikują treści firmy na stronie paste**. Może to zawierać lub nie zawierać **wrażliwych informacji**, ale bardzo interesujące jest ich wyszukiwanie.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby przeszukać więcej niż 80 stron paste jednocześnie.

### Dorki Google

Stare, ale złote dorki Google są zawsze przydatne do znajdowania **ujawnionych informacji, które nie powinny tam być**. Jedynym problemem jest to, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie możesz uruchomić ręcznie. Możesz więc wziąć swoje ulubione 10 lub możesz użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks) **do ich uruchomienia**.

_Uwaga, że narzędzia, które oczekują uruchomienia całej bazy danych za pomocą standardowej przeglądarki Google, nigdy się nie skończą, ponieważ Google zablokuje cię bardzo, bardzo szybko._

### **Szukając luk**

Jeśli znajdziesz **ważne wyciekłe** dane uwierzytelniające lub tokeny API, to bardzo łatwe zwycięstwo.

## Publiczne luki w kodzie

Jeśli odkryjesz, że firma ma **otwarty kod źródłowy**, możesz go **analizować** i szukać **luk** w nim.

**W zależności od języka** istnieją różne **narzędzia**, które możesz użyć:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Istnieją również darmowe usługi, które pozwalają na **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia Pentestingu Web**](../../network-services-pentesting/pentesting-web/)

**Większość luk** znalezionych przez łowców błędów znajduje się w **aplikacjach internetowych**, więc w tym momencie chciałbym porozmawiać o **metodologii testowania aplikacji internetowych**, a możesz [**znaleźć te informacje tutaj**](../../network-services-pentesting/pentesting-web/).

Chcę również szczególnie wspomnieć o sekcji [**Narzędzia do automatycznego skanowania aplikacji webowych open source**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ, jeśli nie powinieneś oczekiwać, że znajdą ci bardzo wrażliwe luki, są przydatne do wdrażania ich w **workflow, aby uzyskać pewne początkowe informacje o sieci.**

## Reasumpcja

> Gratulacje! Na tym etapie już wykonałeś **wszystkie podstawowe enumeracje**. Tak, to podstawowe, ponieważ można wykonać znacznie więcej enumeracji (zobaczymy więcej sztuczek później).

Więc już:

1. Znalazłeś wszystkie **firmy** w zakresie
2. Znalazłeś wszystkie **zasoby** należące do firm (i przeprowadziłeś skanowanie luk, jeśli było w zakresie)
3. Znalazłeś wszystkie **domeny** należące do firm
4. Znalazłeś wszystkie **subdomeny** domen (czy jakieś przejęcie subdomeny?)
5. Znalazłeś wszystkie **adresy IP** (z i **nie z CDN**) w zakresie.
6. Znalazłeś wszystkie **serwery internetowe** i zrobiłeś **zrzut ekranu** z nich (czy coś dziwnego wartego głębszego spojrzenia?)
7. Znalazłeś wszystkie **potencjalne publiczne zasoby chmurowe** należące do firmy.
8. **E-maile**, **wycieki danych uwierzytelniających** i **wycieki sekretów**, które mogą dać ci **duże zwycięstwo bardzo łatwo**.
9. **Pentesting wszystkich stron, które znalazłeś**

## **Pełne automatyczne narzędzia rekonesansowe**

Istnieje kilka narzędzi, które wykonają część zaproponowanych działań przeciwko danemu zakresowi.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Trochę stare i nieaktualizowane

## **Referencje**

- Wszystkie darmowe kursy [**@Jhaddix**](https://twitter.com/Jhaddix) takie jak [**Metodologia Łowcy Błędów v4.0 - Wydanie Rekonesansu**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
