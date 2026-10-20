# Metodologia zewnętrznego rekonesansu

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

> Powiedziano Ci, że wszystko, co należy do jakiejś firmy, jest w zakresie testów, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest uzyskanie listy wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. W tym celu zamierzamy:<sup>[[1]](#references)</sup>

1. Znaleźć przejęcia dokonane przez główną firmę — dzięki temu poznamy firmy objęte zakresem.
2. Znaleźć ASN każdej firmy (jeśli go ma) — dzięki temu poznamy zakresy adresów IP należące do poszczególnych firm.
3. Użyć wyszukiwania reverse whois, aby znaleźć inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszą firmą (można to robić rekurencyjnie).
4. Użyć innych technik, takich jak filtry `org` i `ssl` w shodan, aby znaleźć kolejne zasoby (sztuczkę z `ssl` można stosować rekurencyjnie).

### **Przejęcia**

Przede wszystkim musimy ustalić, **jakie inne firmy należą do głównej firmy**.\
Jedną z możliwości jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** **głównej firmy** i **kliknięcie** opcji „**acquisitions**”. Zobaczysz tam inne firmy przejęte przez główną firmę.\
Inną możliwością jest odwiedzenie strony **Wikipedia** głównej firmy i wyszukanie informacji o **przejęciach**.\
W przypadku spółek publicznych sprawdź **dokumenty SEC/EDGAR**, strony **relacji inwestorskich** lub lokalne rejestry przedsiębiorstw (np. **Companies House** w Wielkiej Brytanii).\
Aby znaleźć globalne struktury korporacyjne i podmioty zależne, sprawdź **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazę danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Dobrze, na tym etapie znasz już wszystkie firmy objęte zakresem. Ustalmy, jak znaleźć ich zasoby.

### **ASN-y**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisany do **systemu autonomicznego** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, dla których określono odrębną politykę dostępu do sieci zewnętrznych. Jest administrowany przez jedną organizację, ale może obejmować kilku operatorów.

Warto sprawdzić, czy **firmie przypisano jakiś ASN**, aby znaleźć jej **zakresy adresów IP**. Warto przeprowadzić **test podatności** na wszystkich **hostach** objętych **zakresem** oraz **wyszukać domeny** w tych adresach IP.\
Możesz **wyszukiwać** według **nazwy** firmy, **adresu IP** lub **domeny** na stronach [**https://bgp.he.net/**](https://bgp.he.net) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu, w którym działa firma, te linki mogą być przydatne do zebrania większej ilości danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie prawdopodobnie wszystkie** przydatne informacje **(zakresy adresów IP i Whois)** znajdują się już w pierwszym linku.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ponadto, enumeracja [**BBOT**](https://github.com/blacklanternsecurity/bbot)**-a** automatycznie agreguje i podsumowuje ASN-y na końcu skanowania.

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

Możesz też znaleźć zakresy adresów IP organizacji za pomocą [ASNLookup](https://asnlookup.com/), który oferuje ograniczony bezpłatny dostęp do API.

### **Wyszukiwanie podatności**

Na tym etapie znamy **wszystkie zasoby objęte zakresem**, więc jeśli masz na to pozwolenie, możesz uruchomić **skaner podatności** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Możesz też przeprowadzić [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub skorzystać z usług takich jak** Shodan, Censys czy ZoomEye, **aby znaleźć** otwarte porty. **W zależności od wyników warto** zajrzeć do tej książki, by dowiedzieć się, jak przeprowadzić pentest różnych usług, które mogą być uruchomione.\
**Warto też wspomnieć, że możesz przygotować listy domyślnych nazw użytkowników i** haseł **oraz spróbować przeprowadzić** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy już wszystkie firmy objęte zakresem i ich zasoby. Czas znaleźć domeny objęte zakresem.

_Pamiętaj, że opisane poniżej techniki mogą również pomóc znaleźć subdomeny, a tych informacji nie należy lekceważyć._

Najpierw należy znaleźć **główną domenę** (lub domeny) każdej firmy. Na przykład w przypadku _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Skoro znasz już wszystkie zakresy adresów IP domen, możesz spróbować wykonać **zapytania reverse DNS** dla tych **adresów IP, aby znaleźć więcej domen objętych zakresem**. Spróbuj użyć serwera DNS ofiary lub jednego ze znanych serwerów DNS (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Aby to zadziałało, administrator musi ręcznie włączyć PTR.\
Możesz też użyć [SecurityTrails](https://securitytrails.com/) do uzyskania tych informacji, choć dostęp do historycznych danych DNS wymaga płatnego planu.\
W przypadku dużych zakresów przydatne są narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), które automatyzują reverse lookup i wzbogacanie danych.

### **Reverse Whois (pętla)**

W rekordzie **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **adresy e-mail**, numery telefonów... Jeszcze ciekawsze jest to, że można znaleźć **więcej zasobów powiązanych z firmą**, wykonując **reverse whois lookup na podstawie dowolnego z tych pól** (na przykład innych rejestrów whois, w których występuje ten sam adres e-mail).\
Możesz skorzystać z narzędzi online, takich jak:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bezpłatne** (Web i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bezpłatne**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bezpłatne**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Bezpłatny** interfejs webowy; płatne API.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Płatne
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Płatne (tylko **100 bezpłatnych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Płatne
- [https://securitytrails.com/](https://securitytrails.com/) - Ograniczony bezpłatny dostęp do API dla bieżących rekordów DNS/subdomen; dane historyczne i reverse lookup wymagają płatnego planu.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 bezpłatnych kredytów API po rejestracji; później usługa jest płatna.

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink) (wymaga klucza API whoxy).\
Możesz też przeprowadzić automatyczne wyszukiwanie reverse whois za pomocą [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz użyć tej techniki, aby za każdym razem, gdy znajdziesz nową domenę, odkrywać kolejne nazwy domen.**

### **Trackery**

Jeśli znajdziesz **ten sam identyfikator tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli na kilku stronach widzisz ten sam **identyfikator Google Analytics** lub ten sam **identyfikator Adsense**.

Istnieją strony i narzędzia, które pozwalają wyszukiwać te i inne trackery:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Płatna** usługa webowa i API ([cennik](https://www.stackscan.com/pricing)); obecnie nie jest reklamowany bezpłatny plan. Wykonaj pivot na dowolnym udostępnianym zasobie, nie tylko na identyfikatorach trackerów: ścieżce skryptu, nazwie samodzielnie hostowanego pakietu lub hoście, z którego ładowany jest zasób. Narzędzie zwraca wszystkie strony, na których go znaleziono.

API zwraca stack dla pojedynczej domeny, co ułatwia potwierdzenie, że potencjalny zasób należy do tego samego środowiska:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Zwraca każdą wykrytą technologię wraz z jej kategorią. Pivotowanie po zasobach jest obecnie dostępne tylko dla stron WWW, a API umożliwia wyszukiwanie dla poszczególnych domen.

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, wyszukując ten sam hash ikony favicon? Właśnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Wyniki Favihash użyte do wykrycia domen współdzielących hash favicony](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc najprościej, favihash pozwala wykrywać domeny, które mają taki sam hash ikony favicon jak nasz cel.

![Wynik favihash użyty do wykrycia domen z tym samym hashem favicony](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Użyj znanego hasha favicony jako pivota w Shodan lub FOFA, aby znaleźć inne wystąpienia tej samej technologii dostępne z zewnątrz.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Oto jak możesz **obliczyć hash faviconu** strony internetowej (MMH3 z bajtów faviconu zakodowanych w **base64**):

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

Traktuj odciski faviconów jako wskazówki i weryfikuj je za pomocą dodatkowych sygnałów.<sup>[[3]](#references)[[4]](#references)</sup>

- **Traktuj hash jako wskaźnik, a nie dowód**: MMH3 jest kompaktowy; możliwe są kolizje, ponowne użycie ikon i celowe podszywanie się.
- **Sprawdzaj więcej niż** `/favicon.ico`: kontroluj ścieżki frameworków/buildów, pliki manifestów, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, wbudowane adresy URL danych oraz tagi HTML `<link rel="icon">`.
- **Zasoby statyczne mogą być nadal dostępne za kontrolami WAF/SSO/IdP**: pobierz ikonę bezpośrednio i sprawdź nagłówki `ETag`, `Last-Modified`, przekierowania oraz cache.
- **Weryfikuj dopasowania za pomocą dodatkowych sygnałów**: porównaj tytuł, hash HTML/treści, nagłówki, podmioty/SAN-y certyfikatu TLS, komponenty produktu i otwarte porty.
- **Grupuj według hasha HTML/treści**: spójny szablon wzmacnia wiarygodność odcisku; różne szablony sugerują ikonę ogólną lub współdzieloną.
- **Hash występujący w różnych, niezwiązanych ze sobą sygnaturach, portach i produktach traktuj jako potencjalny honeypot lub placeholder.**
- **W przypadku niejednoznacznych celów porównaj prawdziwą stronę ze ścieżką, która nie istnieje**, taką jak `/_favicon_probe_<8-hex>`; identyczne odpowiedzi hostingu lub strony parkingowej mogą wyjaśniać współdzieloną ikonę.
- **Rozpocznij triage od reguł detekcji Nuclei lub publicznych zbiorów danych**, które mapują hashe faviconów na produkty i CPE.
- **Pamiętaj o ograniczeniach zasięgu opartego na IP**: powierzchnie za CDN, routowane przez SNI, anycastowe i dostępne tylko przez domenę mogą być nieobecne w zbiorach danych podobnych do Shodan.

### **Copyright / Uniq string**

Wyszukuj na stronach internetowych **ciągi znaków, które mogą być wspólne dla różnych witryn tej samej organizacji**. Dobrym przykładem może być **ciąg copyrightu**. Następnie wyszukaj ten ciąg w **Google**, innych **przeglądarkach**, a nawet w **Shodan**: `shodan search http.html:"Copyright string"`

### **Czas CRT**

Często spotyka się zadanie cron, takie jak

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

aby odnowić wszystkie certyfikaty na serwerze w tym samym czasie. Korelowanie znaczników czasu certyfikatów lub ich pozycji w logach Certificate Transparency może ujawnić powiązane domeny.<sup>[[6]](#references)</sup>

Korzystaj też bezpośrednio z logów **Certificate Transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC poczty

Możesz skorzystać ze strony takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) lub narzędzia takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny współdzielące te same informacje DMARC**.\
Inną przydatną usługą jest [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Porzucony rekord A może stać się osiągalny, gdy dostawca chmury ponownie przypisze adres IP. Opisane badania przedstawiają oportunistyczny workflow, który polega na uruchomieniu instancji i skorelowaniu jej adresu z danymi passive DNS; scenariusze takeover testuj wyłącznie w ramach autoryzowanego zakresu.<sup>[[7]](#references)</sup>

### **Inne sposoby**

Powtarzaj odpowiednie metody odkrywania za każdym razem, gdy znajdziesz nową domenę: każdy wynik może ujawnić dodatkowe nazwy certyfikatów, powiązania passive DNS, dopasowania favicon i identyfikatory organizacji, które nie były widoczne na podstawie początkowej domeny.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Jak już wiesz, kto jest właścicielem przestrzeni adresów IP, możesz wyszukiwać te dane w Shodan, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz pobrać **certyfikat TLS** głównej strony, uzyskać **nazwę organizacji**, a następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron znanych **Shodanowi** za pomocą filtra: `ssl:"Tesla Motors"` albo użyć narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie wyszukujące **domeny powiązane** z domeną główną oraz ich **subdomeny** — jest niesamowite.

**Passive DNS / Historyczny DNS**

Dane passive DNS świetnie nadają się do znajdowania **starych i zapomnianych rekordów**, które nadal rozwiązują się do adresów IP lub które można przejąć. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Poszukiwanie podatności**

Sprawdź, czy możliwy jest jakiś [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **korzysta z domeny**, ale **utraciła do niej prawa własności**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i powiadom firmę.

Jeśli znajdziesz jakąś **domenę z adresem IP innym** niż te, które już znalazłeś podczas wykrywania zasobów, wykonaj **podstawowe skanowanie podatności** (za pomocą Nessus lub OpenVAS) i [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) za pomocą **nmap/masscan/shodan**. W zależności od uruchomionych usług w **tej książce znajdziesz kilka sposobów na ich „zaatakowanie”**.\
_Pamiętaj, że czasami domena jest hostowana pod adresem IP, który nie jest kontrolowany przez klienta, więc nie należy do zakresu — zachowaj ostrożność._

## Subdomeny

> Znamy wszystkie firmy objęte zakresem, wszystkie zasoby każdej z nich oraz wszystkie powiązane z nimi domeny.

Czas znaleźć wszystkie możliwe subdomeny każdej znalezionej domeny.

> [!TIP]
> Pamiętaj, że niektóre narzędzia i techniki wyszukiwania domen mogą również pomóc w znajdowaniu subdomen.

### **DNS**

Spróbujmy znaleźć **subdomeny** na podstawie rekordów **DNS**. Powinniśmy też spróbować wykonać **Zone Transfer** (jeśli jest możliwy, należy to zgłosić).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Informacje o API i platformach dotyczących infrastruktury, reputacji, rejestrów naruszeń i wzbogacania danych wykraczającego poza wykrywanie subdomen znajdziesz w [katalogu API do rozpoznania i analizy zagrożeń](reconnaissance-and-threat-intelligence-apis.md).

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

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

Istnieją **inne interesujące narzędzia/API**, które, nawet jeśli nie są bezpośrednio przeznaczone do znajdowania subdomen, mogą być przydatne do ich wyszukiwania, na przykład:

- [**IP.THC.ORG**](https://ip.thc.org) — darmowe API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Darmowe API AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**SecurityTrails**](https://securitytrails.com/) oferuje ograniczony, bezpłatny dostęp do API z bieżącymi danymi DNS i dotyczącymi poddomen; historyczne dane DNS/IP wymagają płatnego planu.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ten projekt udostępnia **bezpłatnie wszystkie poddomeny powiązane z programami bug-bounty**. Dostęp do tych danych możesz uzyskać również za pomocą [chaospy](https://github.com/Moaaz-0x/chaospy) albo sprawdzić scope używany przez ten projekt: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Porównanie** wielu z tych narzędzi znajdziesz tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **poddomeny**, wykonując brute-force na serwerach DNS z użyciem potencjalnych nazw poddomen.

Do tego działania potrzebne będą **popularne wordlisty poddomen, takie jak**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebne będą również adresy IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać resolvery z [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i przefiltrować je za pomocą [**dnsvalidator**](https://github.com/vortexau/dnsvalidator). Możesz też skorzystać z: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To pierwsze narzędzie, które skutecznie wykonywało DNS brute-force. Jest bardzo szybkie, ale podatne na wyniki fałszywie pozytywne.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Myślę, że używa tylko 1 resolvera

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper dla `massdns`, napisany w go, który umożliwia enumerację prawidłowych subdomen za pomocą aktywnego bruteforce, a także rozwiązywanie subdomen z obsługą wildcardów i łatwą obsługą wejścia-wyjścia.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Również używa `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) używa asyncio do asynchronicznego brute force’owania nazw domen.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Druga runda brute-force DNS

Po znalezieniu subdomen za pomocą otwartych źródeł i brute-force możesz wygenerować warianty znalezionych subdomen, aby spróbować znaleźć ich jeszcze więcej. Przydatnych jest do tego kilka narzędzi:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Na podstawie domen i subdomen generuje permutacje.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Na podstawie podanych domen i subdomen generuje permutacje.
  - Listę **wordlist** z permutacjami goaltdns znajdziesz [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na podstawie domen i subdomen generuje permutacje. Jeśli nie wskazano pliku z permutacjami, gotator użyje własnego.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może też próbować je rozwiązywać (ale lepiej użyć wcześniej wspomnianych narzędzi).
  - Permutacje altdns można pobrać jako **wordlistę** [**tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do tworzenia permutacji, mutacji i modyfikacji subdomen. Narzędzie używa brute force do uzyskania wyników (nie obsługuje wildcard DNS).
  - Listę słów z permutacjami dla dmut znajdziesz [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Na podstawie domeny **generuje nazwy potencjalnych nowych subdomen** zgodnie ze wskazanymi wzorcami, aby spróbować odkryć więcej subdomen.

#### Generowanie inteligentnych permutacji

- [**regulator**](https://github.com/cramppet/regulator): Uczy się wzorców przypominających regex na podstawie odkrytych subdomen i generuje nazwy kandydatów do rozpoznania.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to fuzzer do brute-force subdomen, wykorzystujący niezwykle prosty, ale skuteczny algorytm sterowany odpowiedziami DNS. Korzysta z dostarczonego zestawu danych wejściowych, takiego jak specjalnie przygotowana wordlista lub historyczne rekordy DNS/TLS, aby precyzyjnie generować kolejne pasujące nazwy domen i dalej je rozszerzać w pętli na podstawie informacji zebranych podczas skanowania DNS.

```
echo www | subzuf facebook.com
```

### **Workflow odkrywania subdomen**

Przykładowe workflowy Trickest łączą OSINT, DNS brute force i etapy permutacji, umożliwiając powtarzalną enumerację subdomen.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Jeśli znajdziesz adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami pod tym adresem IP**, wyszukując domeny powiązane z adresem IP w **źródłach OSINT** albo **przeprowadzając brute force nazw domen VHost pod tym adresem IP**.

#### OSINT

Możesz znaleźć **VHosts pod adresami IP za pomocą** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute Force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze WWW, możesz spróbować przeprowadzić brute force:

W przypadku vhostów opartych na nazwie przetestuj różne wartości nagłówka `Host` i użyj automatycznej kalibracji ffuf, aby odfiltrować domyślną odpowiedź.<sup>[[2]](#references)</sup>

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
> Dzięki tej technice możesz uzyskać dostęp nawet do wewnętrznych/ukrytych endpointów.

### **CORS Brute Force**

Czasami można znaleźć strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ podano prawidłową domenę/subdomenę. W takich sytuacjach można wykorzystać to zachowanie, aby **odkryć** nowe **subdomeny**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

Szukając **subdomen**, zwracaj uwagę na to, czy **wskazują** na jakiegoś rodzaju **bucket**, a jeśli tak, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ponadto, ponieważ na tym etapie znasz już wszystkie domeny w zakresie, spróbuj [**przeprowadzić brute force możliwych nazw bucketów i sprawdzić uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Monitorowanie**

Możesz **monitorować**, czy tworzone są **nowe subdomeny** domeny, obserwując logi **Certificate Transparency**, tak jak robi to [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Wyszukiwanie podatności**

Sprawdź, czy możliwe jest [**przejęcie subdomeny**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomena** wskazuje na jakiś **bucket S3**, [**sprawdź uprawnienia**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Jeśli znajdziesz **subdomenę z adresem IP innym** niż te, które zostały już wykryte podczas rozpoznania zasobów, wykonaj **podstawowe skanowanie podatności** (za pomocą Nessus lub OpenVAS) oraz [**skanowanie portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. W zależności od uruchomionych usług w **tej książce znajdziesz kilka sposobów na ich „zaatakowanie”**.\
_Pamiętaj, że subdomena bywa hostowana pod adresem IP, który nie jest kontrolowany przez klienta, a więc nie należy do zakresu. Zachowaj ostrożność._

## Adresy IP

Na początkowych etapach mogłeś **znaleźć pewne zakresy adresów IP, domeny i subdomeny**.\
Czas **zebrać wszystkie adresy IP z tych zakresów** oraz te przypisane do **domen/subdomen (zapytania DNS).**

Korzystając z usług takich jak poniższe, możesz też znaleźć **wcześniejsze adresy IP używane przez domeny i subdomeny**. Klient może nadal być ich właścicielem (a one mogą pomóc w znalezieniu [**sposobów na ominięcie CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (dostęp do historycznych danych DNS/IP wymaga płatnego planu)

Możesz też sprawdzić, które domeny wskazują na konkretny adres IP, korzystając z narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Wyszukiwanie podatności**

**Skanuj porty wszystkich adresów IP, które nie należą do CDN** (ponieważ najprawdopodobniej nie znajdziesz tam nic interesującego). Wykryte uruchomione usługi mogą **być podatne na ataki**.

**Znajdź** [**poradnik**](../pentesting-network/index.html) **opisujący skanowanie hostów.**

## Poszukiwanie serwerów WWW

> Znaleźliśmy wszystkie firmy i ich zasoby, a także znamy zakresy adresów IP, domeny i subdomeny należące do zakresu. Czas poszukać serwerów WWW.

Na poprzednich etapach prawdopodobnie przeprowadziłeś już **rozpoznanie wykrytych adresów IP i domen**, więc być może **znalazłeś już wszystkie możliwe serwery WWW**. Jeśli jednak tak się nie stało, pokażemy teraz kilka **szybkich sposobów na wyszukanie serwerów WWW** w zakresie.

Pamiętaj, że działania te będą **ukierunkowane na wykrywanie aplikacji webowych**, dlatego należy też przeprowadzić **skanowanie podatności** i **portów** (**jeśli zezwala na to zakres**).

**Szybki sposób** wykrywania **otwartych portów** związanych z serwerami **WWW** za pomocą [**masscan znajdziesz tutaj**](../pentesting-network/index.html#http-port-discovery).\
Innymi przydatnymi narzędziami do wyszukiwania serwerów WWW są [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy przekazać im listę domen, a spróbują połączyć się z portami 80 (http) i 443 (https). Możesz też wskazać inne porty do sprawdzenia:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Zrzuty ekranu**

Po odkryciu **wszystkich serwerów WWW** w zakresie (wśród **adresów IP** firmy oraz wszystkich jej **domen** i **subdomen**) prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy to więc i zacznijmy od zrobienia zrzutów ekranu wszystkich tych serwerów. Już samo **spojrzenie** na **stronę główną** może ujawnić **nietypowe** endpointy, które są bardziej **podatne** na **podatności**.

Aby zrealizować ten pomysł, możesz użyć [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Możesz też użyć [**eyeballer**](https://github.com/BishopFox/eyeballer), aby przeanalizować wszystkie **zrzuty ekranu** i wskazać, **które prawdopodobnie zawierają podatności**, a które nie.

## Zasoby w chmurze publicznej

Aby znaleźć potencjalne zasoby w chmurze należące do firmy, **zacznij od listy słów kluczowych identyfikujących tę firmę**. Na przykład w przypadku firmy z branży kryptowalut możesz użyć takich słów jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Potrzebne będą też listy **często używanych nazw bucketów**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie wygeneruj z tych słów **permutacje** (więcej informacji znajdziesz w sekcji [**Druga runda DNS brute-force**](#second-dns-bruteforce-round)).

Do pracy z wygenerowanymi listami słów możesz użyć takich narzędzi jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając zasobów w chmurze, należy **szukać nie tylko bucketów w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz takie zasoby jak **otwarte buckety lub ujawnione funkcje chmurowe**, **uzyskaj do nich dostęp** i sprawdź, co oferują oraz czy można je wykorzystać.

## E-maile

Mając **domeny** i **subdomeny** objęte zakresem, masz właściwie wszystko, **czego potrzebujesz, aby rozpocząć wyszukiwanie adresów e-mail**. Oto **API** i **narzędzia**, które najlepiej sprawdziły się u mnie przy wyszukiwaniu adresów e-mail firmy:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (wersja bezpłatna)
- API [**https://app.snov.io/**](https://app.snov.io/) (wersja bezpłatna)
- API [**https://minelead.io/**](https://minelead.io/) (wersja bezpłatna)

### **Szukanie podatności**

Adresy e-mail przydadzą się później do **brute-force’owania logowań do serwisów WWW i usług uwierzytelniania** (takich jak SSH). Są też potrzebne do **phishingu**. Co więcej, te API dostarczą jeszcze więcej **informacji o osobie** stojącej za adresem e-mail, co może być przydatne w kampanii phishingowej.

## Wycieki danych uwierzytelniających

Mając **domeny**, **subdomeny** i **adresy e-mail**, możesz zacząć szukać danych uwierzytelniających, które wyciekły w przeszłości i są powiązane z tymi adresami e-mail:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe dane uwierzytelniające z wycieku**, to bardzo łatwe zwycięstwo.

## Wycieki sekretów

Wycieki danych uwierzytelniających są związane z włamaniami do firm, podczas których **wrażliwe informacje wyciekły i zostały sprzedane**. Firmy mogą jednak paść ofiarą **innych wycieków**, których dane nie znajdują się w tych bazach:

### Wycieki z Githuba

Dane uwierzytelniające i API mogą wyciekać do **publicznych repozytoriów** **firmy** lub **użytkowników** pracujących w tej firmie.\
Możesz użyć **narzędzia** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** **organizacji** i jej **programistów**, a następnie automatycznie uruchomić na nich [**gitleaks**](https://github.com/gitleaks/gitleaks).

**Leakos** można też użyć do uruchomienia **gitleaks** na wszystkich adresach **URL** przekazanych do niego jako **tekst**, ponieważ czasami **strony WWW również zawierają sekrety**.

#### Github Dorks

Sprawdź stronę [GitHub dorks and leaks](github-leaked-secrets.md), aby znaleźć potencjalne **GitHub dorks** do wyszukiwania w organizacji.

### Wycieki z serwisów paste

Czasami atakujący lub po prostu pracownicy **publikują treści firmowe w serwisach paste**. Mogą one zawierać **wrażliwe informacje**, ale nie muszą — mimo to warto ich poszukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie przeszukiwać ponad 80 serwisów paste.

### Google Dorks

Stare, ale wciąż skuteczne Google dorks są przydatne do znajdowania **ujawnionych informacji, które nie powinny być publicznie dostępne**. Problem w tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** potencjalnych zapytań, których nie da się uruchomić ręcznie. Możesz więc wybrać 10 ulubionych zapytań albo użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks), **aby uruchomić je wszystkie**.

_Należy pamiętać, że narzędzia próbujące przeszukać całą bazę za pomocą zwykłej przeglądarki Google nigdy nie skończą, ponieważ Google bardzo szybko zablokuje dostęp._

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe dane uwierzytelniające lub tokeny API z wycieku**, to bardzo łatwe zwycięstwo.

## Podatności w publicznym kodzie

Jeśli odkryjesz, że firma udostępnia **kod open source**, możesz go **przeanalizować** i poszukać w nim **podatności**.

**W zależności od języka** możesz użyć różnych **narzędzi**; zobacz listę [narzędzi do przeglądu kodu źródłowego](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Dostępne są też bezpłatne usługi umożliwiające **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia pentestów aplikacji WWW**](../../network-services-pentesting/pentesting-web/index.html)

**Większość podatności** wykrywanych przez bug hunterów znajduje się w **aplikacjach WWW**, dlatego w tym miejscu chcę omówić **metodologię testowania aplikacji WWW**. [**Więcej informacji znajdziesz tutaj**](../../network-services-pentesting/pentesting-web/index.html).

Chcę też szczególnie wspomnieć o sekcji [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners). Nie należy oczekiwać, że skanery znajdą bardzo poważne podatności, ale przydają się do wdrożenia w **workflow, aby zebrać wstępne informacje o aplikacji WWW.**

## Podsumowanie

> Gratulacje! Na tym etapie masz już za sobą **cały podstawowy rekonesans**. Tak, podstawowy, bo można przeprowadzić znacznie więcej rekonesansu (pokażę później więcej trików).

Masz już:

1. Znalezione wszystkie **firmy** objęte zakresem
2. Znalezione wszystkie **zasoby** należące do tych firm (i przeprowadzone skanowanie podatności, jeśli mieściło się w zakresie)
3. Znalezione wszystkie **domeny** należące do tych firm
4. Znalezione wszystkie **subdomeny** tych domen (czy któraś jest podatna na subdomain takeover?)
5. Znalezione wszystkie **adresy IP** objęte zakresem (zarówno te **za CDN**, jak i **poza CDN**).
6. Znalezione wszystkie **serwery WWW** i zrobione ich **zrzuty ekranu** (czy coś wygląda nietypowo i zasługuje na dokładniejsze sprawdzenie?)
7. Znalezione wszystkie **potencjalne zasoby w chmurze publicznej** należące do firmy.
8. Znalezione **adresy e-mail**, **wycieki danych uwierzytelniających** i **wycieki sekretów**, które mogą zapewnić **łatwe zwycięstwo**.
9. **Przeprowadzone pentesty wszystkich znalezionych witryn**

## **Automatyczne narzędzia do pełnego rekonesansu**

Dostępnych jest kilka narzędzi, które wykonują część opisanych działań w ramach określonego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Dość stare i nieaktualizowane

## References

- [1] [Jason Haddix – Metodologia bug huntera v4.0: edycja dotycząca rekonesansu](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O faviconach: od ikon przeglądarki do analizy powierzchni ataku](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Wykorzystanie favicon.ico w bug bounty, OSINT i nie tylko](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Odkrywanie domen za pomocą ataku korelacji czasowej na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasywne przejęcie: odkrywanie (i naśladowanie) kosztownej kampanii subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: wyjątkowa metoda enumeracji subdomen](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Pełny workflow wykrywania subdomen, część 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Pełne wykrywanie subdomen metodą brute-force z użyciem zautomatyzowanego workflow Trickest, część 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Zrzut ekranu z wynikiem favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
