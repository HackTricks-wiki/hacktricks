# Metodologia zewnętrznego rozpoznania

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano Ci, że wszystko, co należy do jakiejś firmy, jest objęte zakresem, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest ustalenie wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. W tym celu:<sup>[[1]](#references)</sup>

1. Znajdź przejęcia dokonane przez główną firmę, aby ustalić, które firmy należą do zakresu.
2. Znajdź ASN (jeśli istnieje) każdej firmy, aby ustalić należące do niej zakresy IP.
3. Użyj wyszukiwania reverse whois, aby znaleźć inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszym wpisem (można to robić rekurencyjnie).
4. Użyj innych technik, takich jak filtry `org` i `ssl` w shodan, aby wyszukać inne zasoby (sztuczkę z `ssl` można stosować rekurencyjnie).

### **Przejęcia**

Najpierw musimy ustalić, **jakie inne firmy należą do głównej firmy**.\
Jedną z możliwości jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** **głównej firmy** i **kliknięcie** pozycji "**acquisitions**". Zobaczysz tam inne firmy przejęte przez tę główną.\
Inną możliwością jest odwiedzenie strony głównej firmy w **Wikipedii** i wyszukanie informacji o **przejęciach**.\
W przypadku spółek publicznych sprawdź **zgłoszenia SEC/EDGAR**, strony **relacji inwestorskich** lub lokalne rejestry przedsiębiorstw (np. **Companies House** w Wielkiej Brytanii).\
Aby sprawdzić globalne struktury korporacyjne i spółki zależne, skorzystaj z **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazy danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Dobrze, na tym etapie powinieneś znać wszystkie firmy objęte zakresem. Ustalmy, jak znaleźć ich zasoby.

### **ASN-y**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, dla których określono odrębne zasady dostępu do sieci zewnętrznych. Są one zarządzane przez jedną organizację, ale mogą obejmować kilku operatorów.

Warto sprawdzić, czy **firmie przypisano ASN**, aby znaleźć jej **zakresy IP**. Warto przeprowadzić **test podatności** wszystkich **hostów** objętych **zakresem** oraz **poszukać domen** w tych zakresach IP.\
Możesz **wyszukiwać** według **nazwy** firmy, **IP** lub **domeny** w serwisach [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu, w którym działa firma, te odnośniki mogą pomóc w zebraniu dodatkowych danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** znajdują się już w pierwszym odnośniku.

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

Możesz znaleźć zakresy IP organizacji również za pomocą [http://asnlookup.com/](http://asnlookup.com) (dostępne jest bezpłatne API).\
Adres IP i ASN domeny możesz znaleźć za pomocą [http://ipv4info.com/](http://ipv4info.com).

### **Szukanie podatności**

Na tym etapie znamy **wszystkie zasoby objęte zakresem**, więc jeśli masz na to zgodę, możesz uruchomić **skaner podatności** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) dla wszystkich hostów.\
Możesz też przeprowadzić [**skany portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub skorzystać z usług takich jak** Shodan, Censys czy ZoomEye, **aby znaleźć** otwarte porty. **W zależności od wyników zajrzyj do tej książki, by sprawdzić, jak przeprowadzić pentesting różnych potencjalnych usług.**\
**Warto też wspomnieć, że możesz przygotować listy** domyślnych nazw użytkowników **i** haseł **oraz spróbować przeprowadzić** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy już wszystkie firmy objęte zakresem i ich zasoby. Czas znaleźć domeny objęte zakresem.

_Pamiętaj, że poniższe proponowane techniki mogą również pomóc znaleźć subdomeny, a tych informacji nie należy lekceważyć._

Przede wszystkim należy znaleźć **główną domenę** każdej firmy. Na przykład w przypadku _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Skoro znasz już wszystkie zakresy IP domen, możesz spróbować wykonać **reverse dns lookups** dla tych **adresów IP, aby znaleźć więcej domen objętych zakresem**. Spróbuj użyć serwera DNS ofiary lub jednego z powszechnie znanych serwerów DNS (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Aby to zadziałało, administrator musi ręcznie włączyć PTR.\
Możesz też skorzystać z narzędzia online, aby uzyskać te informacje: [http://ptrarchive.com/](http://ptrarchive.com).\
W przypadku dużych zakresów przydatne są narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), które automatyzują reverse lookups i wzbogacanie danych.

### **Reverse Whois (loop)**

W rekordzie **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **e-maile**, numery telefonów... Jeszcze ciekawsze jest to, że możesz znaleźć **więcej zasobów powiązanych z firmą**, wykonując **reverse whois lookups na podstawie dowolnego z tych pól** (na przykład wyszukując inne rejestry whois, w których pojawia się ten sam adres e-mail).\
Możesz skorzystać z narzędzi online, takich jak:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bezpłatne** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bezpłatne**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Bezpłatne**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bezpłatne**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Bezpłatna** wersja webowa, API jest płatne.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Płatne
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Płatne (tylko **100 bezpłatnych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Płatne
- [https://securitytrails.com/](https://securitytrails.com/) - Płatne (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Płatne (API)

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink)(wymaga klucza API whoxy).\
Możesz też automatycznie wyszukiwać powiązania reverse whois za pomocą [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz używać tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackery**

Jeśli znajdziesz **ten sam identyfikator tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli na kilku stronach widzisz ten sam **Google Analytics ID** lub ten sam **Adsense ID**.

Istnieją strony i narzędzia umożliwiające wyszukiwanie na podstawie tych i innych trackerów:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (wyszukuje powiązane witryny na podstawie wspólnych analytics/trackerów)
- [**StackScan**](https://www.stackscan.com) - **Bezpłatny plan** (Web i API). Pozwala wyszukiwać na podstawie dowolnego udostępnianego zasobu, nie tylko identyfikatorów trackerów: ścieżki skryptu, nazwy własnego bundla lub hosta, z którego ładowany jest zasób, i zwraca wszystkie witryny, które go używają

API zwraca stack dla pojedynczej domeny, co przydaje się do potwierdzenia, że dany zasób należy do tej samej infrastruktury:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Zwraca każdą wykrytą technologię wraz z jej kategorią. Asset pivoting jest obecnie dostępne tylko dla stron internetowych; API umożliwia wyszukiwanie dla poszczególnych domen.

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, szukając takiego samego hasha ikony favicon? Właśnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc najprościej, favihash pozwala nam odkrywać domeny, które mają ten sam hash ikony favicon co nasz cel.

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Użyj znanego hasha favicony jako punktu pivot w Shodan lub FOFA, aby znaleźć inne ujawnione instancje tej samej technologii.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Oto jak możesz **obliczyć hash faviconu strony WWW** (MMH3 dla bajtów faviconu zakodowanych w **base64**):

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

Możesz też zbierać hashe faviconów na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a następnie pivotować w Shodan/Censys.

Traktuj fingerprinty faviconów jako wskazówki i weryfikuj je, korzystając z dodatkowych sygnałów.<sup>[[3]](#references)[[4]](#references)</sup>

- **Traktuj hash jako wskaźnik, a nie dowód**: MMH3 jest kompaktowy; możliwe są kolizje, ponowne użycie ikon i celowe podszywanie się.
- **Sprawdzaj więcej niż** `/favicon.ico`: sprawdź ścieżki frameworków i buildów, pliki manifestu, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, osadzone data URL-e i tagi HTML `<link rel="icon">`.
- **Zasoby statyczne mogą pozostać dostępne za kontrolami WAF/SSO/IdP**: pobierz ikonę bezpośrednio i sprawdź `ETag`, `Last-Modified`, przekierowania oraz nagłówki cache.
- **Weryfikuj dopasowania za pomocą dodatkowych sygnałów**: porównaj tytuł, hash HTML/body, nagłówki, podmioty/SAN-y certyfikatu TLS, komponenty produktu i otwarte porty.
- **Grupuj według hasha HTML/body**: spójny szablon wzmacnia fingerprint; różne szablony sugerują ogólną lub współdzieloną ikonę.
- **Hash występujący w niezwiązanych sygnaturach, portach i produktach traktuj jako potencjalną honeypot lub placeholder.**
- **W przypadku niejednoznacznych celów porównaj rzeczywistą stronę z nieistniejącą ścieżką**, taką jak `/_favicon_probe_<8-hex>`; pasujące odpowiedzi hostingu lub parkingu mogą wyjaśniać współdzieloną ikonę.
- **Rozpocznij triage od reguł wykrywania Nuclei lub publicznych zbiorów danych**, które mapują hashe faviconów na produkty i CPE.
- **Pamiętaj o luce w pokryciu opartym na IP**: powierzchnie korzystające z CDN, routingu SNI, anycastu i dostępne wyłącznie przez domenę mogą nie występować w zbiorach danych podobnych do Shodan.

### **Copyright / Uniq string**

Wyszukuj na stronach internetowych **ciągi znaków, które mogą być wspólne dla różnych witryn w tej samej organizacji**. Dobrym przykładem może być **ciąg copyright**. Następnie wyszukaj ten ciąg w **google**, w innych **przeglądarkach** lub nawet w **shodan**: `shodan search http.html:"Copyright string"`

### **CRT Time**

Często spotyka się zadanie cron, takie jak

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

aby odnowić wszystkie certyfikaty na serwerze jednocześnie. Korelowanie znaczników czasu certyfikatów lub pozycji w logach certificate transparency może ujawnić powiązane domeny.<sup>[[6]](#references)</sup>

Możesz też korzystać bezpośrednio z logów **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC dotyczące poczty

Możesz skorzystać ze strony takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny korzystające z tych samych informacji DMARC**.\
Inne przydatne narzędzia to [**spoofcheck**](https://github.com/BishopFox/spoofcheck) i [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Porzucony rekord A może stać się osiągalny, gdy dostawca chmury ponownie przydzieli adres IP. W przywołanym badaniu przedstawiono oportunistyczny workflow polegający na utworzeniu instancji i skorelowaniu jej adresu z danymi passive DNS; testuj scenariusze takeover wyłącznie w ramach autoryzowanego zakresu.<sup>[[7]](#references)</sup>

### **Inne metody**

Powtarzaj odpowiednie metody wyszukiwania za każdym razem, gdy znajdziesz nową domenę: każdy wynik może ujawnić dodatkowe nazwy z certyfikatów, powiązania passive DNS, dopasowania favicon i identyfikatory organizacji, które nie były widoczne na podstawie pierwotnej domeny początkowej.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Znasz już nazwę organizacji będącej właścicielem tej przestrzeni adresów IP. Możesz wyszukać ją w Shodan za pomocą: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz pobrać **certyfikat TLS** głównej strony internetowej, uzyskać **nazwę organizacji**, a następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych **Shodanowi**, używając filtra: `ssl:"Tesla Motors"` lub narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie wyszukujące **domeny powiązane** z domeną główną oraz ich **subdomeny** — jest naprawdę świetne.

**Passive DNS / Historical DNS**

Dane passive DNS świetnie nadają się do znajdowania **starych i zapomnianych rekordów**, które nadal rozwiązują się do adresów IP lub mogą zostać przejęte. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Wyszukiwanie podatności**

Sprawdź, czy możliwe jest jakieś [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **korzysta z domeny**, ale **utraciła do niej prawa własności**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz **domenę z adresem IP innym** niż te, które zostały już wykryte podczas identyfikacji zasobów, wykonaj **podstawowe skanowanie podatności** (za pomocą Nessus lub OpenVAS) oraz [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. W zależności od uruchomionych usług w **tej książce znajdziesz kilka sposobów na ich „zaatakowanie”**.\
_Pamiętaj, że czasami domena jest hostowana pod adresem IP, którego klient nie kontroluje, a więc znajduje się poza zakresem testów. Zachowaj ostrożność._

## Subdomeny

> Znamy wszystkie firmy objęte zakresem, wszystkie zasoby każdej z nich oraz wszystkie powiązane z nimi domeny.

Czas znaleźć wszystkie możliwe subdomeny każdej ze znalezionych domen.

> [!TIP]
> Pamiętaj, że niektóre narzędzia i techniki wyszukiwania domen mogą również pomóc w znajdowaniu subdomen

### **DNS**

Spróbujmy znaleźć **subdomeny** w rekordach **DNS**. Powinniśmy również spróbować wykonać **Zone Transfer** (jeśli jest możliwy, należy to zgłosić).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Najszybszym sposobem na uzyskanie wielu subdomen jest wyszukiwanie w zewnętrznych źródłach. Najczęściej używane **narzędzia** to:


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

Istnieją **inne interesujące narzędzia/API**, które — mimo że nie są bezpośrednio wyspecjalizowane w wyszukiwaniu subdomen — mogą być przydatne do ich znajdowania, takie jak:

- [**IP.THC.ORG**](https://ip.thc.org) — darmowe API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Używa API [https://sonar.omnisint.io](https://sonar.omnisint.io) do uzyskiwania subdomenીઓ

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**Darmowe API JLDC**](https://jldc.me/anubis/subdomains/google.com)

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

- [**securitytrails.com**](https://securitytrails.com/) ma darmowe API do wyszukiwania subdomen i historii adresów IP
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ten projekt udostępnia **za darmo wszystkie subdomeny powiązane z programami bug bounty**. Możesz uzyskać dostęp do tych danych także za pomocą [chaospy](https://github.com/dr-0x0x/chaospy) lub sprawdzić zakres używany przez ten projekt: [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

**Porównanie** wielu z tych narzędzi znajdziesz tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny**, przeprowadzając brute-force na serwerach DNS przy użyciu potencjalnych nazw subdomen.

Do tego działania będą potrzebne **listy słów z popularnymi subdomenami**, takie jak:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebne będą również adresy IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać listę resolverów z [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), aby je odfiltrować. Możesz też użyć: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To pierwsze narzędzie, które umożliwiło skuteczny DNS brute-force. Jest bardzo szybkie, ale podatne na wyniki fałszywie pozytywne.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Ten, jak sądzę, używa tylko jednego resolvera.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper dla `massdns`, napisany w Go, który umożliwia enumerowanie poprawnych subdomen za pomocą aktywnego brute force, a także rozwiązywanie subdomen z obsługą wildcardów i łatwą obsługą wejścia-wyjścia.

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

### Druga runda brute-force DNS

Po znalezieniu subdomen za pomocą otwartych źródeł i brute-force możesz wygenerować warianty znalezionych subdomen, aby spróbować znaleźć ich jeszcze więcej. Przydatnych jest do tego kilka narzędzi:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Na podstawie domen i subdomen generuje permutacje.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na podstawie domen i subdomen generuje permutacje.
  - Listę **wordlist** dla permutacji goaltdns znajdziesz [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na podstawie domen i subdomen generuje permutacje. Jeśli nie wskazano pliku z permutacjami, gotator użyje własnego.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może również próbować je rozwiązywać (ale lepiej użyć wcześniej omówionych narzędzi).
  - **wordlist** z permutacjami altdns znajdziesz [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutacji, mutacji i modyfikacji subdomen. Narzędzie będzie brute force'ować wynik (nie obsługuje wildcardów DNS).
  - Listę słów z permutacjami dmut znajdziesz [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nowe potencjalne nazwy subdomen** zgodnie ze wskazanymi wzorcami, aby spróbować odkryć więcej subdomen.

#### Generowanie inteligentnych permutacji

- [**regulator**](https://github.com/cramppet/regulator): Uczy się wzorców podobnych do regexów na podstawie odkrytych subdomen i generuje kandydackie nazwy do rozwiązania.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to fuzzer brute-force subdomen wykorzystujący niezwykle prosty, ale skuteczny algorytm kierowany odpowiedziami DNS. Korzysta z dostarczonego zestawu danych wejściowych, takiego jak dostosowana wordlista lub historyczne rekordy DNS/TLS, aby precyzyjnie generować kolejne pasujące nazwy domen i rozszerzać ich zbiór w pętli na podstawie informacji zebranych podczas skanowania DNS.

```
echo www | subzuf facebook.com
```

### **Workflow wykrywania subdomen**

Przykładowe workflowy Trickest łączą OSINT, brute force DNS i etapy permutacji, umożliwiając powtarzalną enumerację subdomen.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Jeśli znajdziesz adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami na tym IP**, przeszukując **źródła OSINT** w poszukiwaniu domen przypisanych do tego IP albo wykonując **brute force nazw domen VHost na tym IP**.

#### OSINT

Możesz znaleźć **VHosts na adresach IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze WWW, możesz spróbować wykonać jej brute force:

W przypadku vhostów opartych na nazwie testuj różne wartości nagłówka `Host` i użyj automatycznej kalibracji ffuf, aby odfiltrować domyślną odpowiedź.<sup>[[2]](#references)</sup>

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

Czasami można znaleźć strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/poddomena. W takich sytuacjach możesz wykorzystać to zachowanie, aby **odkryć** nowe **poddomeny**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Podczas wyszukiwania **subdomen** zwracaj uwagę, czy **wskazują** one na jakiś **bucket**. Jeśli tak, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponieważ na tym etapie znasz już wszystkie domeny objęte zakresem, spróbuj [**wykonać brute force możliwych nazw bucketów i sprawdzić uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorowanie**

Możesz **monitorować**, czy powstają **nowe subdomeny** danej domeny, śledząc logi **Certificate Transparency** — tak jak robi to [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Wyszukiwanie podatności**

Sprawdź, czy możliwe są [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomena** wskazuje na jakiś **S3 bucket**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz **subdomenę z adresem IP innym** niż te, które znaleziono już podczas wykrywania zasobów, wykonaj **podstawowy skan podatności** (za pomocą Nessus lub OpenVAS) oraz [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. W zależności od działających usług w **tej książce znajdziesz kilka sposobów na ich „zaatakowanie”**.\
_Pamiętaj, że czasami subdomena jest hostowana pod adresem IP, którego klient nie kontroluje, a więc nieobjętym zakresem. Zachowaj ostrożność._

## IP

Na początkowych etapach mogłeś **znaleźć zakresy IP, domeny i subdomeny**.\
Czas **zebrać wszystkie adresy IP z tych zakresów**, a także adresy IP powiązane z **domenami/subdomenami (zapytania DNS).**

Korzystając z usług udostępniających poniższe **darmowe API**, możesz też znaleźć **adresy IP, których domeny i subdomeny używały wcześniej**. Te adresy IP mogą nadal należeć do klienta (i mogą pozwolić ci znaleźć [**obejścia CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**https://securitytrails.com/**](https://securitytrails.com/)

Możesz też sprawdzić, jakie domeny wskazują na konkretny adres IP, używając narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Wyszukiwanie podatności**

Wykonaj **port scan wszystkich adresów IP, które nie należą do CDN-ów** (bo najprawdopodobniej nie znajdziesz tam nic interesującego). Wykryte działające usługi mogą **ujawnić podatności**.

**Znajdź** [**przewodnik**](../pentesting-network/index.html) **o tym, jak skanować hosty.**

## Wyszukiwanie serwerów WWW

> Znaleźliśmy wszystkie firmy i ich zasoby, a także znamy zakresy IP, domeny i subdomeny objęte zakresem. Czas poszukać serwerów WWW.

Na poprzednich etapach prawdopodobnie wykonano już **rekonesans znalezionych adresów IP i domen**, więc być może **udało się już znaleźć wszystkie możliwe serwery WWW**. Jeśli jednak tak się nie stało, pokażemy teraz kilka **szybkich sposobów wyszukiwania serwerów WWW** w obrębie zakresu.

Pamiętaj, że opisane metody są **ukierunkowane na wykrywanie aplikacji webowych**, dlatego należy również **wykonać skanowanie podatności** i **portów** (**jeśli pozwala na to zakres**).

**Szybki sposób** na wykrywanie **otwartych portów** powiązanych z serwerami **WWW** za pomocą [**masscan** można znaleźć tutaj](../pentesting-network/index.html#http-port-discovery).\
Inne przydatne narzędzia do wyszukiwania serwerów WWW to [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy przekazać im listę domen, a spróbują połączyć się z portami 80 (http) i 443 (https). Możesz też wskazać, by sprawdziły inne porty:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Zrzuty ekranu**

Teraz, gdy udało Ci się znaleźć **wszystkie serwery WWW** w zakresie (wśród **adresów IP** firmy oraz wszystkich jej **domen** i **subdomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy to i zacznijmy od zrobienia zrzutów ekranu każdej z nich. Już samo **spojrzenie** na **stronę główną** może ujawnić **nietypowe** endpointy, które są bardziej **podatne** na **podatności**.

Do realizacji tego pomysłu możesz użyć narzędzi [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Możesz też użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przeanalizować wszystkie **zrzuty ekranu** i wskazać, **które prawdopodobnie zawierają podatności**, a które nie.

## Zasoby chmury publicznej

Aby znaleźć potencjalne zasoby chmurowe należące do firmy, zacznij od **listy słów kluczowych identyfikujących tę firmę**. Na przykład w przypadku firmy kryptowalutowej możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Potrzebne będą też listy słów zawierające **często używane nazwy bucketów**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie wygeneruj z tych słów **permutacje** (więcej informacji znajdziesz w sekcji [**Druga runda brute-force DNS**](#second-dns-bruteforce-round)).

Do pracy z uzyskanymi listami słów możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając zasobów chmurowych, należy sprawdzać **nie tylko buckety w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz **otwarte buckety lub udostępnione funkcje chmurowe**, uzyskaj do nich **dostęp**, sprawdź, co oferują i czy możesz je wykorzystać.

## E-maile

Mając w zakresie **domeny** i **subdomeny**, masz w zasadzie wszystko, czego **potrzebujesz, by zacząć szukać adresów e-mail**. Oto **API** i **narzędzia**, które najlepiej sprawdziły się u mnie w wyszukiwaniu adresów e-mail pracowników firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (wersja bezpłatna)
- API [**https://app.snov.io/**](https://app.snov.io/) (wersja bezpłatna)
- API [**https://minelead.io/**](https://minelead.io/) (wersja bezpłatna)

### **Szukanie podatności**

Adresy e-mail przydadzą się później do **brute-force logowania do stron i usług uwierzytelniających** (takich jak SSH). Są też potrzebne do **phishingu**. Ponadto te API dostarczą więcej **informacji o osobie** kryjącej się za adresem e-mail, co może się przydać w kampanii phishingowej.

## Credential Leaks

Mając **domeny**, **subdomeny** i **adresy e-mail**, możesz zacząć szukać danych uwierzytelniających ujawnionych w przeszłości, powiązanych z tymi adresami e-mail:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe ujawnione** dane uwierzytelniające, to bardzo łatwy sukces.

## Secrets Leaks

Credential leaks dotyczą włamań do firm, w wyniku których **ujawniono i sprzedano poufne informacje**. Firmy mogą jednak ucierpieć wskutek **innych leaków**, których danych nie ma w tych bazach:

### Leaki na Githubie

Dane uwierzytelniające i API mogą zostać ujawnione w **publicznych repozytoriach** **firmy** lub **użytkowników** pracujących w firmie korzystającej z GitHuba.\
Możesz użyć **narzędzia** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** **organizacji** i jej **programistów**, a następnie automatycznie uruchomić na nich [**gitleaks**](https://github.com/zricethezav/gitleaks).

**Leakos** można też wykorzystać do uruchomienia **gitleaks** na wszystkich przekazanych mu **adresach URL** z tekstem, ponieważ **strony internetowe również mogą zawierać sekrety**.

#### Github Dorks

Sprawdź stronę [GitHub dorks and leaks](github-leaked-secrets.md), aby znaleźć potencjalne **GitHub dorks** do przeszukania organizacji.

### Leaki na Pastebinach

Czasami atakujący lub po prostu pracownicy **publikują treści firmowe w serwisach typu paste**. Mogą one zawierać **poufne informacje**, ale nie muszą — mimo to warto ich poszukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie przeszukiwać ponad 80 serwisów typu paste.

### Google Dorks

Stare, ale jare google dorks zawsze pomagają znaleźć **ujawnione informacje, które nie powinny być publicznie dostępne**. Jedyny problem polega na tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera **tysiące** możliwych zapytań, których nie da się uruchomić ręcznie. Możesz więc wybrać 10 ulubionych albo użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks), **aby uruchomić je wszystkie**.

_Zwróć uwagę, że narzędzia próbujące przeszukać całą bazę za pomocą zwykłej przeglądarki Google nigdy nie skończą, ponieważ Google bardzo szybko je zablokuje._

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe ujawnione** dane uwierzytelniające lub tokeny API, to bardzo łatwy sukces.

## Podatności w publicznym kodzie

Jeśli okaże się, że firma udostępnia **kod open source**, możesz go **przeanalizować** i poszukać w nim **podatności**.

**W zależności od języka** możesz użyć różnych **narzędzi**; zobacz listę [narzędzi do przeglądu kodu źródłowego](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Istnieją też bezpłatne usługi umożliwiające **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia pentestów aplikacji Web**](../../network-services-pentesting/pentesting-web/index.html)

**Większość podatności** znajdowanych przez bug hunterów znajduje się w **aplikacjach webowych**, dlatego na tym etapie chciałbym omówić **metodologię testowania aplikacji webowych**. [**Więcej informacji znajdziesz tutaj**](../../network-services-pentesting/pentesting-web/index.html).

Chciałbym też szczególnie wyróżnić sekcję [**Narzędzia open source do automatycznego skanowania aplikacji Web**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners). Nie należy oczekiwać, że znajdą bardzo poważne podatności, ale przydają się do wdrożenia w **workflow, aby zebrać podstawowe informacje o aplikacji Web.**

## Podsumowanie

> Gratulacje! Na tym etapie masz już za sobą **podstawowe rozpoznanie**. Tak, podstawowe, bo można przeprowadzić znacznie więcej działań rozpoznawczych (później poznamy kolejne sztuczki).

Masz już za sobą:

1. Znalezienie wszystkich **firm** w zakresie
2. Znalezienie wszystkich **zasobów** należących do tych firm (i przeprowadzenie skanowania pod kątem podatności, jeśli mieściło się ono w zakresie)
3. Znalezienie wszystkich **domen** należących do tych firm
4. Znalezienie wszystkich **subdomen** tych domen (czy jest możliwe przejęcie subdomeny?)
5. Znalezienie wszystkich **adresów IP** (zarówno z **CDN**, jak i spoza CDN) w zakresie.
6. Znalezienie wszystkich **serwerów WWW** i zrobienie ich **zrzutów ekranu** (czy jest coś nietypowego, co warto dokładniej sprawdzić?)
7. Znalezienie wszystkich **potencjalnych zasobów chmury publicznej** należących do firmy.
8. Znalezienie **adresów e-mail**, **credential leaks** i **secret leaks**, które mogą zapewnić **łatwy i duży sukces**.
9. **Przeprowadzenie pentestów wszystkich znalezionych stron**

## **Automatyczne narzędzia do pełnego recon**

Dostępnych jest wiele narzędzi, które wykonują część opisanych działań w ramach danego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Dość stare i nieaktualizowane

## References

- [1] [Jason Haddix – Metodologia bug huntera v4.0: edycja Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O faviconach: od ikon przeglądarki po analizę powierzchni ataku](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Wykorzystanie favicon.ico w bug bounty, OSINT i nie tylko](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Odkrywanie domen za pomocą ataku korelacji czasowej na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasywne przejęcie: analiza (i emulacja) kosztownej kampanii przejmowania subdomen](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: wyjątkowa metoda enumeracji subdomen](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Pełny workflow wykrywania subdomen, część 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Pełne wykrywanie subdomen metodą brute-force z użyciem automatycznego workflow Trickest, część 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Zrzut ekranu z wynikiem favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
