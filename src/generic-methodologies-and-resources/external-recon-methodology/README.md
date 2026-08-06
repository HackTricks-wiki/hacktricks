# Metodyka zewnętrznego rozpoznania

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie assetów

> Powiedziano Ci więc, że wszystko należące do jakiejś firmy znajduje się w zakresie, a Ty chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie informacji o wszystkich **firmach należących do głównej firmy**, a następnie o wszystkich **assetach** tych firm. W tym celu będziemy:

1. Znajdować przejęcia głównej firmy, co da nam firmy znajdujące się w zakresie.
2. Znajdować ASN (jeśli istnieje) każdej firmy, co da nam zakresy IP należące do każdej firmy.
3. Używać reverse whois lookups do wyszukiwania innych wpisów (nazw organizacji, domen...) powiązanych z pierwszą firmą (można to wykonywać rekurencyjnie).
4. Używać innych technik, takich jak filtry `org` i `ssl` w Shodan, do wyszukiwania kolejnych assetów (trik z `ssl` można wykonywać rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy dowiedzieć się, **jakie inne firmy należą do głównej firmy**.\
Jedną z możliwości jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** **głównej firmy** i **kliknięcie** opcji "**acquisitions**". Zobaczysz tam inne firmy przejęte przez główną firmę.\
Inną możliwością jest odwiedzenie strony **Wikipedia** głównej firmy i wyszukanie informacji o **przejęciach**.\
W przypadku spółek publicznych sprawdź **dokumenty SEC/EDGAR**, strony **relacji inwestorskich** lub lokalne rejestry spółek (np. **Companies House** w Wielkiej Brytanii).\
W przypadku globalnych struktur korporacyjnych i spółek zależnych wypróbuj **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazę danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> W tym momencie powinieneś już znać wszystkie firmy znajdujące się w zakresie. Ustalmy teraz, jak znaleźć ich assety.

### **ASN-y**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, które mają jasno określoną politykę dostępu do sieci zewnętrznych i są zarządzane przez jedną organizację, ale mogą składać się z kilku operatorów.

Warto sprawdzić, czy **firmie przypisano jakikolwiek ASN**, aby znaleźć jej **zakresy IP.** Warto przeprowadzić **test podatności** wszystkich **hostów** znajdujących się w **zakresie** oraz **wyszukać domeny** w obrębie tych adresów IP.\
Możesz **wyszukiwać** według **nazwy firmy**, **adresu IP** lub **domeny** w serwisach [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu, w którym znajduje się firma, te odnośniki mogą być przydatne do zebrania większej ilości danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** znajdują się już w pierwszym odnośniku.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Ponadto, [**BBOT**](https://github.com/blacklanternsecurity/bbot) w ramach enumeracji automatycznie agreguje i podsumowuje ASN-y na końcu skanowania.
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
Możesz znaleźć zakresy IP organizacji również za pomocą [http://asnlookup.com/](http://asnlookup.com) (udostępnia darmowe API).\
Możesz znaleźć IP i ASN domeny za pomocą [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

W tym momencie znamy **wszystkie assety znajdujące się w scope**, więc jeśli masz na to pozwolenie, możesz uruchomić **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Możesz również uruchomić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub użyć usług takich jak** Shodan, Censys lub ZoomEye, **aby znaleźć** otwarte porty, **a w zależności od tego, co znajdziesz, powinieneś** zajrzeć do tej książki, aby dowiedzieć się, jak przeprowadzać pentesting różnych możliwych uruchomionych usług.\
**Warto również wspomnieć, że możesz przygotować** listy domyślnych nazw użytkowników **i** haseł **oraz spróbować** bruteforce'ować usługi za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Znamy wszystkie firmy znajdujące się w scope oraz ich assety, więc czas znaleźć domeny znajdujące się w scope.

_Pamiętaj, że za pomocą poniższych proponowanych technik możesz również znaleźć subdomeny, a tych informacji nie należy lekceważyć._

Przede wszystkim powinieneś poszukać **głównej domeny** (lub **domen**) każdej firmy. Na przykład dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Skoro znalazłeś wszystkie zakresy IP domen, możesz spróbować wykonać **reverse dns lookups** dla tych **IP, aby znaleźć więcej domen znajdujących się w scope**. Spróbuj użyć serwera DNS ofiary lub któregoś ze znanych serwerów DNS (1.1.1.1, 8.8.8.8)
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

W ramach **whois** możesz znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **adresy e-mail**, numery telefonów... Jeszcze bardziej interesująca jest możliwość znalezienia **większej liczby zasobów powiązanych z firmą**, jeśli wykonasz **reverse whois lookups na podstawie dowolnego z tych pól** (na przykład innych rejestrów whois, w których pojawia się ten sam adres e-mail).\
Możesz użyć narzędzi online, takich jak:

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

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
Możesz również przeprowadzić częściowo automatyczne reverse whois discovery za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz używać tej techniki do wykrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackers**

Jeśli znajdziesz **ten sam identyfikator tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli na kilku stronach zobaczysz ten sam **Google Analytics ID** lub ten sam **Adsense ID**.

Istnieją strony i narzędzia, które pozwalają wyszukiwać na podstawie tych trackerów i innych danych:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Czy wiesz, że możemy znaleźć domeny i subdomeny powiązane z naszym celem, wyszukując ten sam hash ikony favicon? Właśnie do tego służy narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py), stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc krótko, favihash pozwala nam odkrywać domeny, które mają ten sam hash ikony favicon co nasz cel.

Ponadto możesz również wyszukiwać technologie za pomocą hasha favicon, jak wyjaśniono w [**tym wpisie na blogu**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Oznacza to, że jeśli znasz **hash favicon podatnej wersji technologii webowej**, możesz wyszukać go w shodan i **znaleźć więcej podatnych miejsc**:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Tak możesz **obliczyć hash favicon** strony internetowej (MMH3 dla **zakodowanych w base64** bajtów favicon):
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

Ważne rzeczy, o których należy pamiętać podczas korzystania z fingerprintów faviconów:<sup>[[3]](#references)[[4]](#references)</sup>

- **Traktuj hash jako wskaźnik, a nie dowód**: MMH3 jest kompaktowy i możliwe są kolizje; operatorzy mogą również zastąpić favicony lub celowo użyć wprowadzającej w błąd ikony.
- **Sprawdzaj więcej niż** `/favicon.ico`: wiele produktów udostępnia ikony w ścieżkach frameworków/buildów lub za pośrednictwem `manifest.json`, `site.webmanifest`, `browserconfig.xml`, `apple-touch-icon*`, wbudowanych adresów `data:` albo tagów HTML `<link rel="icon">`. Sama ścieżka może fingerprintować rodzinę produktów.
- **Pliki statyczne są często dostępne, gdy aplikacja nie jest**: mechanizmy WAF/SSO/IdP mogą chronić dynamiczne trasy, ale nadal udostępniać statyczne ikony. Zawsze żądaj faviconu bezpośrednio i analizuj `ETag`, `Last-Modified`, przekierowania oraz nagłówki cache pod kątem słabych wskazówek dotyczących wersji/builda.
- **Weryfikuj dopasowania za pomocą dodatkowych sygnałów**: porównuj tytuł, hash HTML/body, nagłówki, subject/SAN certyfikatu TLS, komponenty Shodan/Censys oraz dostępne porty, zanim stwierdzisz, że favicon identyfikuje produkt.
- **Podczas pivotingu na dużą skalę grupuj według hasha HTML/body**: jeśli większość hostów współdzielących favicon łączy się w jeden szablon strony, fingerprint jest silniejszy; jeśli ten sam hash dzieli się na wiele niezwiązanych szablonów, preferuj określenie „generic/shared/honeypot” zamiast etykiety produktu.
- **Heurystyka honeypota**: jeśli ten sam hash faviconu występuje w wielu niezwiązanych sygnaturach HTML, na losowych portach i przy sprzecznych produktach, traktuj go jako prawdopodobny honeypot lub generyczny placeholder, a nie rzeczywisty fingerprint produktu.
- **Użyj probe 404 dla niejednoznacznych celów**: w przeglądarce pobierz prawdziwą stronę oraz nieistniejącą ścieżkę, taką jak `/_favicon_probe_<8-hex>`. Identyczne odpowiedzi hosting-provider/parking często lepiej wyjaśniają współdzielone favicony niż rzeczywiste nakładanie się produktów.
- **Twórz początkowe mapowania na podstawie reguł detekcji**: templates Nuclei i publiczne datasety faviconów mogą dostarczyć znanych mapowań `favicon` ↔ `product` ↔ `CPE`, przydatnych do szybkiego triage po ujawnieniu CVE.
- **Zastrzeżenie dotyczące pokrycia**: datasety w stylu Shodan są zorientowane na IP. Powierzchnie dostępne przez CDN, routowane za pomocą SNI, anycast oraz wyłącznie domenowe mogą być zaniżone, więc mała liczba trafień **nie** oznacza małej rzeczywistej skali wdrożenia.

### **Copyright / Uniq string**

Szukaj wewnątrz stron internetowych **stringów, które mogą być współdzielone przez różne witryny w tej samej organizacji**. Dobrym przykładem może być **string copyright**. Następnie wyszukaj ten string w **google**, w innych **przeglądarkach** lub nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się cron job, taki jak
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
aby odnowić wszystkie certyfikaty domen na serwerze. Oznacza to, że nawet jeśli CA używane do tego nie ustawia czasu wygenerowania w czasie Validity, możliwe jest **znalezienie domen należących do tej samej firmy w logach certificate transparency**.\
Sprawdź ten [**writeup, aby uzyskać więcej informacji**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).<sup>[[6]](#references)</sup>

Używaj również bezpośrednio logów **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC dotyczące poczty

Możesz użyć strony takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny współdzielące te same informacje DMARC**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Najwyraźniej często zdarza się, że ludzie przypisują subdomeny do adresów IP należących do cloud providerów, a w pewnym momencie **tracą ten adres IP, ale zapominają usunąć rekord DNS**. W rezultacie samo **uruchomienie VM** w cloudzie (np. Digital Ocean) może faktycznie oznaczać **przejęcie niektórych subdomen**.

[**Ten post**](https://kmsec.uk/blog/passive-takeover/) opisuje przypadek tego typu i proponuje skrypt, który **uruchamia VM w DigitalOcean**, **pobiera** **IPv4** nowej maszyny oraz **wyszukuje w Virustotal rekordy subdomen** wskazujące na ten adres.<sup>[[7]](#references)</sup>

### **Inne sposoby**

**Pamiętaj, że możesz używać tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

**Shodan**

Jak już wiesz, jaka organizacja posiada daną przestrzeń IP, możesz wyszukać te dane w Shodan, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz uzyskać dostęp do **certyfikatu TLS** głównej strony internetowej, odczytać **nazwę organizacji**, a następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych przez **Shodan**, używając filtra: `ssl:"Tesla Motors"` lub narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie, które wyszukuje **domeny powiązane** z główną domeną oraz ich **subdomeny** — jest niesamowite.

**Passive DNS / Historical DNS**

Dane Passive DNS świetnie nadają się do znajdowania **starych i zapomnianych rekordów**, które nadal się rozwiązują lub mogą zostać przejęte. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Poszukiwanie podatności**

Sprawdź, czy występuje [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa domeny**, ale **utraciła do niej prawa własności**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz **domenę z adresem IP różnym** od tych, które już znaleziono podczas asset discovery, powinieneś przeprowadzić **podstawowy skan podatności** (używając Nessus lub OpenVAS) oraz [**skan portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług w **tej książce znajdziesz pewne triki pozwalające je „zaatakować”**.\
_Należy pamiętać, że czasami domena jest hostowana w adresie IP, który nie jest kontrolowany przez klienta, więc nie znajduje się w zakresie — zachowaj ostrożność._

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

Najszybszym sposobem na uzyskanie dużej liczby subdomen jest wyszukiwanie w zewnętrznych źródłach. Najczęściej używane **narzędzia** to:

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
Istnieją **inne interesujące narzędzia/API**, które, nawet jeśli nie są bezpośrednio wyspecjalizowane w znajdowaniu subdomen, mogą być przydatne do ich znajdowania, takie jak:

- [**IP.THC.ORG**](https://ip.thc.org) darmowe API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Wykorzystuje API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskiwania subdomen
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**darmowe API JLDC**](https://jldc.me/anubis/subdomains/google.com)
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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Przeszukują web w poszukiwaniu plików JS i wyodrębniają z nich subdomeny.
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
- [**securitytrails.com**](https://securitytrails.com/) ma darmowe API do wyszukiwania subdomen i historii adresów IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Ten projekt oferuje **bezpłatnie wszystkie subdomeny powiązane z programami bug-bounty**. Dostęp do tych danych można uzyskać również za pomocą [chaospy](https://github.com/dr-0x0x/chaospy), a nawet uzyskać zakres używany przez ten projekt: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off) zawiera **porównanie** wielu z tych narzędzi.

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny**, wykonując brute-force serwerów DNS przy użyciu potencjalnych nazw subdomen.

Do tego działania potrzebne będą pewne **listy słów zawierające typowe subdomeny, takie jak**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebne będą również adresy IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, można pobrać resolvery z [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) do ich odfiltrowania. Można też użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): Było to pierwsze narzędzie, które skutecznie wykonywało DNS brute-force. Jest bardzo szybkie, jednak często generuje false positives.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): Ten moim zdaniem używa tylko 1 resolvera
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper wokół `massdns`, napisany w Go, który pozwala enumerować prawidłowe subdomeny za pomocą aktywnego bruteforce, a także rozwiązywać subdomeny z obsługą wildcardów oraz łatwą obsługą danych wejściowych i wyjściowych.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) wykorzystuje asyncio do asynchronicznego brute force nazw domen.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Druga runda DNS Brute-Force

Po znalezieniu poddomen za pomocą otwartych źródeł i brute-forcingu możesz wygenerować modyfikacje znalezionych poddomen, aby spróbować znaleźć jeszcze więcej. Do tego celu przydatnych jest kilka narzędzi:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na podstawie domen i poddomen generuje permutacje.
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): Na podstawie domen i subdomen generuje permutacje.
- Listę słów **wordlist** dla permutacji goaltdns można znaleźć [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** Na podstawie domen i subdomen generuje permutacje. Jeśli nie wskazano pliku permutacji, gotator użyje własnego.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może również próbować je rozwiązywać (ale lepiej użyć wcześniej wspomnianych narzędzi).
- Listę **wordlist** z permutacjami altdns można znaleźć [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutacji, mutacji i modyfikacji subdomen. To narzędzie przeprowadza brute force wyniku (nie obsługuje dns wild card).
- Listę słów do permutacji dmut można znaleźć [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy subdomen** zgodnie ze wskazanymi wzorcami, aby spróbować odkryć więcej subdomen.

#### Generowanie inteligentnych permutacji

- [**regulator**](https://github.com/cramppet/regulator): Więcej informacji znajdziesz w tym [**wpisie**](https://cramppet.github.io/regulator/index.html), ale zasadniczo narzędzie pobiera **główne części** z **wykrytych subdomen** i łączy je, aby znaleźć więcej subdomen.<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to fuzzer brute-force subdomen, wyposażony w niezwykle prosty, ale skuteczny algorytm kierowany odpowiedziami DNS. Wykorzystuje dostarczony zestaw danych wejściowych, taki jak dostosowany wordlist lub historyczne rekordy DNS/TLS, aby dokładnie generować kolejne odpowiadające nazwy domen i jeszcze bardziej rozszerzać je w pętli na podstawie informacji zebranych podczas skanowania DNS.
```
echo www | subzuf facebook.com
```
### **Workflow wykrywania subdomen**

Sprawdź ten wpis na blogu, który napisałem o tym, jak **automatyzować wykrywanie subdomen** domeny za pomocą **workflowów Trickest**, dzięki czemu nie muszę ręcznie uruchamiać wielu narzędzi na swoim komputerze:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

Jeśli znalazłeś adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami na tym IP**, przeszukując **źródła OSINT** w poszukiwaniu domen przypisanych do adresu IP lub wykonując **brute-force nazw domen VHostów na tym IP**.

#### OSINT

Możesz znaleźć niektóre **VHosty na adresach IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze webowym, możesz spróbować ją odnaleźć za pomocą brute force:

Gdy **IP przekierowuje do hostname** (vhosty oparte na nazwie), fuzzuj bezpośrednio nagłówek `Host` i pozwól ffuf **automatycznie skalibrować wyniki**, aby wyróżnić odpowiedzi różniące się od domyślnego vhosta:<sup>[[2]](#references)</sup>
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

Czasami znajdziesz strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/subdomena. W takich scenariuszach możesz wykorzystać to zachowanie do **wykrywania** nowych **subdomen**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

Podczas wyszukiwania **subdomains** zwracaj uwagę, czy któryś z nich **wskazuje** na dowolnego rodzaju **bucket**, a jeśli tak, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponadto, ponieważ na tym etapie znasz już wszystkie domeny znajdujące się w scope, spróbuj [**wykonać brute force możliwych nazw bucketów i sprawdzić uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorowanie**

Możesz **monitorować**, czy tworzone są **nowe subdomains** domeny, monitorując logi **Certificate Transparency**, tak jak robi to [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Wyszukiwanie vulnerabilities**

Sprawdź możliwe przypadki [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomain** wskazuje na jakiś **S3 bucket**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz **subdomain z adresem IP różnym** od tych, które zostały już znalezione podczas assets discovery, powinieneś wykonać **basic vulnerability scan** (używając Nessus lub OpenVAS) oraz [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług w **tej książce znajdziesz triki pozwalające je „zaatakować”**.\
_Należy pamiętać, że czasami subdomain jest hostowany wewnątrz adresu IP, który nie jest kontrolowany przez klienta, więc nie znajduje się w scope — zachowaj ostrożność._

## IPs

We wstępnych krokach mogłeś **znaleźć zakresy IP, domeny i subdomains**.\
Czas **zebrać wszystkie adresy IP z tych zakresów** oraz dla **domen/subdomains wykonać zapytania DNS**.

Korzystając z usług oferowanych przez poniższe **free APIs**, możesz także znaleźć **wcześniejsze adresy IP używane przez domeny i subdomains**. Te adresy IP nadal mogą należeć do klienta (i mogą pozwolić ci znaleźć [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz także sprawdzać domeny wskazujące na konkretny adres IP za pomocą narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Wyszukiwanie vulnerabilities**

**Wykonaj port scan wszystkich adresów IP, które nie należą do CDN-ów** (ponieważ z dużym prawdopodobieństwem nie znajdziesz tam nic interesującego). W wykrytych uruchomionych usługach możesz **znaleźć vulnerabilities**.

**Znajdź** [**guide**](../pentesting-network/index.html) **opisujący, jak skanować hosty.**

## Poszukiwanie serwerów webowych

> Znaleźliśmy wszystkie firmy i ich assets oraz znamy zakresy IP, domeny i subdomains znajdujące się w scope. Czas rozpocząć wyszukiwanie serwerów webowych.

We wcześniejszych krokach prawdopodobnie przeprowadziłeś już pewien **recon adresów IP i znalezionych domen**, więc być może **znalazłeś już wszystkie możliwe serwery webowe**. Jeśli jednak jeszcze tego nie zrobiłeś, teraz przedstawimy kilka **szybkich trików do wyszukiwania serwerów webowych** w scope.

Pamiętaj, że będzie to **ukierunkowane na discovery aplikacji webowych**, dlatego powinieneś również **wykonać vulnerability** oraz **port scanning** (**jeśli jest to dozwolone** w scope).

[Szybką metodę](../pentesting-network/index.html#http-port-discovery) wykrywania **otwartych portów** związanych z serwerami **webowymi** przy użyciu [**masscan** można znaleźć tutaj](../pentesting-network/index.html#http-port-discovery).\
Innym przyjaznym narzędziem do wyszukiwania serwerów webowych jest [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) oraz [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy przekazać listę domen, a narzędzie spróbuje połączyć się z portem 80 (http) i 443 (https). Dodatkowo możesz wskazać inne porty do sprawdzenia:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Zrzuty ekranu**

Teraz, gdy odkryłeś **wszystkie serwery webowe** obecne w zakresie (wśród **IP** firmy oraz wszystkich **domen** i **subdomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy to więc i zacznijmy od wykonania zrzutów ekranu wszystkich z nich. Już samo **spojrzenie** na **stronę główną** może ujawnić **dziwne** endpointy, które są bardziej **podatne** na występowanie **vulnerability**.

Aby zrealizować ten pomysł, możesz użyć [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ponadto możesz następnie użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przeanalizować wszystkie **zrzuty ekranu** i wskazać, **co prawdopodobnie zawiera vulnerability**, a co nie.

## Public Cloud Assets

Aby znaleźć potencjalne cloud assets należące do firmy, powinieneś **zacząć od listy słów kluczowych identyfikujących tę firmę**. Na przykład w przypadku firmy kryptowalutowej możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Potrzebne będą również wordlisty zawierające **często używane słowa występujące w bucketach**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie, używając tych słów, powinieneś wygenerować **permutacje** (więcej informacji znajdziesz w sekcji [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)).

Z użyciem wynikowych wordlist możesz wykorzystać narzędzia takie jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że podczas szukania Cloud Assets powinieneś **szukać nie tylko bucketów w AWS**.

### **Szukanie vulnerability**

Jeśli znajdziesz takie rzeczy jak **otwarte buckety lub exposed cloud functions**, powinieneś **uzyskać do nich dostęp** i sprawdzić, co oferują oraz czy możesz je wykorzystać.

## Emaile

Mając w zakresie **domeny** i **subdomeny**, masz zasadniczo wszystko, czego **potrzebujesz, aby rozpocząć wyszukiwanie emaili**. Oto **API** i **narzędzia**, które najlepiej sprawdzały się u mnie podczas wyszukiwania emaili należących do firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (wersja darmowa)
- API [**https://app.snov.io/**](https://app.snov.io/) (wersja darmowa)
- API [**https://minelead.io/**](https://minelead.io/) (wersja darmowa)

### **Szukanie vulnerability**

Emaile przydadzą się później do **brute-force web loginów i usług auth** (takich jak SSH). Są również potrzebne do **phishingu**. Ponadto te API dostarczą jeszcze więcej **informacji o osobie** stojącej za emailem, co jest przydatne podczas kampanii phishingowej.

## Credential Leaks

Mając **domeny,** **subdomeny** i **emaile**, możesz rozpocząć wyszukiwanie credentials, które w przeszłości wyciekły i należały do tych adresów email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie vulnerability**

Jeśli znajdziesz **prawidłowe leaked** credentials, będzie to bardzo łatwy sukces.

## Secrets Leaks

Credential leaks są związane z hackami firm, podczas których **wrażliwe informacje wyciekły i zostały sprzedane**. Firmy mogą jednak być dotknięte **innymi leakami**, których informacje nie znajdują się w tych bazach danych:

### Github Leaks

Credentials i API mogą wyciec do **publicznych repozytoriów** **firmy** lub **użytkowników** pracujących w tej firmie korzystającej z github.\
Możesz użyć **tool** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** **organizacji** i jej **developerów**, a następnie automatycznie uruchomić [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** może być również użyty do uruchomienia **gitleaks** przeciwko całemu **tekstowi** dostarczonemu przez **URL-e przekazane** do narzędzia, ponieważ czasami **strony webowe również zawierają sekrety**.

#### Github Dorks

Sprawdź również tę **stronę** pod kątem potencjalnych **github dorks**, których możesz także szukać w organizacji, którą atakujesz:

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

Czasami atakujący lub po prostu pracownicy będą **publikować treści firmy w serwisie paste**. Mogą one zawierać **wrażliwe informacje**, ale nie muszą; mimo to warto ich poszukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie wyszukiwać w ponad 80 serwisach paste.

### Google Dorks

Stare, ale skuteczne google dorks są zawsze przydatne do znajdowania **ujawnionych informacji, które nie powinny być dostępne**. Jedyny problem polega na tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie można uruchomić ręcznie. Możesz więc wybrać swoje ulubione 10 zapytań albo użyć **tool takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks), **aby uruchomić je wszystkie**.

_Note that tools, które próbują uruchomić całą bazę za pomocą zwykłej przeglądarki Google, nigdy nie zakończą działania, ponieważ Google bardzo szybko je zablokuje._

### **Szukanie vulnerability**

Jeśli znajdziesz **prawidłowe leaked** credentials lub tokeny API, będzie to bardzo łatwy sukces.

## Public Code Vulnerabilities

Jeśli odkryłeś, że firma posiada **open-source code**, możesz go **przeanalizować** i poszukać w nim **vulnerability**.

**W zależności od języka** możesz użyć różnych **tools**:

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

Dostępne są również darmowe usługi umożliwiające **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**Większość vulnerability** znajdowanych przez bug hunterów znajduje się w **aplikacjach webowych**, dlatego w tym momencie chciałbym omówić **metodologię testowania aplikacji webowych**; informacje na ten temat [**znajdziesz tutaj**](../../network-services-pentesting/pentesting-web/index.html).

Chciałbym również wspomnieć o sekcji [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ, mimo że nie należy oczekiwać, iż znajdą bardzo wrażliwe vulnerability, są przydatne do wdrażania ich w **workflowach w celu uzyskania wstępnych informacji o webie.**

## Podsumowanie

> Gratulacje! Na tym etapie wykonałeś już **całą podstawową enumerację**. Tak, jest podstawowa, ponieważ można wykonać znacznie więcej enumeracji (więcej trików poznamy później).

Masz już:

1. Znalezione wszystkie **firmy** znajdujące się w zakresie
2. Znalezione wszystkie **asset** należące do firm (oraz wykonany skan vulnerability, jeśli był w zakresie)
3. Znalezione wszystkie **domeny** należące do firm
4. Znalezione wszystkie **subdomeny** domen (czy jest możliwy subdomain takeover?)
5. Znalezione wszystkie **IP** (z **CDN-ów** i **spoza CDN-ów**) znajdujące się w zakresie.
6. Znalezione wszystkie **serwery webowe** i wykonane ich **zrzuty ekranu** (czy jest coś dziwnego, co warto dokładniej zbadać?)
7. Znalezione wszystkie potencjalne public cloud assets należące do firmy.
8. Znalezione **emaile**, **credential leaks** i **secret leaks**, które mogą zapewnić Ci **duży sukces bardzo łatwo**.
9. Wykonany **pentesting wszystkich znalezionych webów**

## **Full Recon Automatic Tools**

Dostępnych jest wiele narzędzi, które wykonują część opisanych działań dla danego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Nieco stare i nieaktualizowane

## Referencje

- [1] Wszystkie darmowe kursy [**@Jhaddix**](https://twitter.com/Jhaddix), takie jak [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
