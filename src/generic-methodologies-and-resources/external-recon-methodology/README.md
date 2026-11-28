# Metodologia zewnętrznego rozpoznania

{{#include ../../banners/hacktricks-training.md}}

## Odkrywanie zasobów

Skategoryzowaną listę dodatkowych projektów OSINT i narzędzi do wykrywania zasobów internetowych znajdziesz w [narzędziach i zasobach innych firm](../third-party-tools-and-resources.md#osint).

> Powiedziano Ci, że wszystko, co należy do jakiejś firmy, jest objęte zakresem, i chcesz ustalić, co ta firma faktycznie posiada.

Celem tej fazy jest ustalenie wszystkich **firm należących do głównej firmy**, a następnie wszystkich **zasobów** tych firm. W tym celu:<sup>[[1]](#references)</sup>

1. Ustal przejęcia głównej firmy — dzięki temu poznasz firmy objęte zakresem.
2. Znajdź ASN każdej firmy (jeśli go ma) — dzięki temu poznasz należące do niej zakresy IP.
3. Użyj wyszukiwania reverse whois, aby znaleźć inne wpisy (nazwy organizacji, domeny...) powiązane z pierwszym wpisem (można to robić rekurencyjnie).
4. Użyj innych technik, takich jak filtry `org`i `ssl` w shodan, aby znaleźć kolejne zasoby (sztuczkę z `ssl` można stosować rekurencyjnie).

Aby poznać kolejne etapy procesu — od rozwiązanych subdomen po crawling HTTP i wykrywanie portów — zobacz [metodologię pentestów](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Przejęcia**

Najpierw musimy ustalić, **jakie inne firmy należą do głównej firmy**.\
Jednym ze sposobów jest odwiedzenie strony [https://www.crunchbase.com/](https://www.crunchbase.com), **wyszukanie** **głównej firmy** i kliknięcie **„acquisitions”**. Znajdziesz tam inne firmy przejęte przez główną firmę.\
Innym sposobem jest odwiedzenie strony głównej firmy w **Wikipedii** i wyszukanie hasła **acquisitions**.\
W przypadku spółek publicznych sprawdź **dokumenty SEC/EDGAR**, strony **relacji inwestorskich** lub lokalne rejestry przedsiębiorstw (np. **Companies House** w Wielkiej Brytanii).\
Aby znaleźć globalne struktury korporacyjne i spółki zależne, skorzystaj z **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) oraz bazy danych **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Dobrze, na tym etapie powinieneś znać wszystkie firmy objęte zakresem. Ustalmy, jak znaleźć ich zasoby.

### **ASN**

Numer systemu autonomicznego (**ASN**) to **unikalny numer** przypisywany **systemowi autonomicznemu** (AS) przez **Internet Assigned Numbers Authority (IANA)**.\
**AS** składa się z **bloków** **adresów IP**, które mają jasno określoną politykę dostępu do sieci zewnętrznych. Są zarządzane przez jedną organizację, ale mogą obejmować kilku operatorów.

Warto sprawdzić, czy **firmie przypisano ASN**, aby znaleźć jej **zakresy IP**. Warto przeprowadzić **test podatności** wszystkich **hostów** objętych **zakresem** oraz **poszukać domen** w tych adresach IP.\
Możesz **wyszukiwać** według **nazwy** firmy, **adresu IP** lub **domeny** w serwisie [**https://bgp.he.net/**](https://bgp.he.net) **lub** [**https://ipinfo.io/**](https://ipinfo.io/).\
**W zależności od regionu, w którym działa firma, przydatne mogą być te zasoby do zebrania dodatkowych danych:** [**AFRINIC**](https://www.afrinic.net) **(Afryka),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Ameryka Północna),** [**APNIC**](https://www.apnic.net) **(Azja),** [**LACNIC**](https://www.lacnic.net) **(Ameryka Łacińska),** [**RIPE NCC**](https://www.ripe.net) **(Europa). W każdym razie prawdopodobnie wszystkie** przydatne informacje **(zakresy IP i Whois)** znajdują się już w pierwszym serwisie.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ponadto narzędzie [**BBOT**](https://github.com/blacklanternsecurity/bbot) automatycznie agreguje i podsumowuje ASN-y na końcu skanowania.

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

Możesz również znaleźć zakresy adresów IP organizacji za pomocą [ASNLookup](https://asnlookup.com/), który oferuje ograniczony bezpłatny dostęp do API.

### **Poszukiwanie podatności**

Na tym etapie znamy **wszystkie zasoby objęte zakresem**, więc jeśli masz na to pozwolenie, możesz uruchomić **skaner podatności** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) na wszystkich hostach.\
Możesz również przeprowadzić [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **lub skorzystać z usług takich jak** Shodan, Censys czy ZoomEye, **aby znaleźć** otwarte porty. **W zależności od wyników warto** zajrzeć do tej książki, by dowiedzieć się, jak przeprowadzić pentest różnych usług, które mogą działać na znalezionych hostach.\
**Warto również przygotować listy domyślnych** nazw użytkowników **i** haseł **oraz spróbować przeprowadzić** bruteforce usług za pomocą [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domeny

> Znamy już wszystkie firmy objęte zakresem i ich zasoby. Czas znaleźć domeny objęte zakresem.

_Pamiętaj, że opisane poniżej techniki mogą również pomóc w znalezieniu subdomen i nie należy lekceważyć tych informacji._

Najpierw należy znaleźć **główną domenę** każdej firmy. Na przykład dla _Tesla Inc._ będzie to _tesla.com_.

### **Reverse DNS**

Skoro znasz już wszystkie zakresy adresów IP domen, możesz spróbować wykonać **reverse DNS lookups** dla tych **adresów IP, aby znaleźć więcej domen objętych zakresem**. Spróbuj użyć serwera DNS ofiary lub jednego ze znanych serwerów DNS (1.1.1.1, 8.8.8.8).

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Aby to zadziałało, administrator musi ręcznie włączyć PTR.\
Możesz też skorzystać z [SecurityTrails](https://securitytrails.com/), aby uzyskać te informacje, jednak dostęp do historycznych danych DNS wymaga płatnego planu.\
W przypadku dużych zakresów przydatne są narzędzia takie jak [**massdns**](https://github.com/blechschmidt/massdns) i [**dnsx**](https://github.com/projectdiscovery/dnsx), które automatyzują wyszukiwanie odwrotne i wzbogacanie danych.

### **Reverse Whois (pętla)**

W rekordzie **whois** można znaleźć wiele interesujących **informacji**, takich jak **nazwa organizacji**, **adres**, **adresy e-mail**, numery telefonów... Jeszcze ciekawsze jest to, że można odkryć **więcej zasobów powiązanych z firmą**, wykonując **wyszukiwanie odwrotne whois na podstawie dowolnego z tych pól** (na przykład znajdując inne rejestry whois, w których pojawia się ten sam adres e-mail).\
Możesz skorzystać z narzędzi online, takich jak:

- [https://ip.thc.org/](https://ip.thc.org/) - **Bezpłatne** (strona internetowa i API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Bezpłatne**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Bezpłatne**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Bezpłatny** interfejs WWW; API jest płatne.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Płatne
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Nie jest bezpłatne (tylko **100 bezpłatnych** wyszukiwań)
- [https://www.domainiq.com/](https://www.domainiq.com) - Nie jest bezpłatne
- [https://securitytrails.com/](https://securitytrails.com/) - Ograniczony bezpłatny dostęp do API dla bieżących rekordów DNS i subdomen; dostęp do danych historycznych i wyszukiwania odwrotnego wymaga płatnego planu.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 bezpłatnych kredytów API po rejestracji; później usługa jest płatna.

Możesz zautomatyzować to zadanie za pomocą [**DomLink** ](https://github.com/vysecurity/DomLink)(wymaga klucza API whoxy).\
Możesz też automatycznie wyszukiwać powiązania w reverse whois za pomocą [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Pamiętaj, że możesz używać tej techniki do odkrywania kolejnych nazw domen za każdym razem, gdy znajdziesz nową domenę.**

### **Trackery**

Jeśli znajdziesz **ten sam identyfikator tego samego trackera** na 2 różnych stronach, możesz założyć, że **obie strony** są **zarządzane przez ten sam zespół**.\
Na przykład, jeśli na kilku stronach widzisz ten sam **identyfikator Google Analytics** lub **identyfikator Adsense**.

Istnieją strony i narzędzia, które umożliwiają wyszukiwanie na podstawie tych i innych trackerów:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **Płatna** usługa WWW i API ([cennik](https://www.stackscan.com/pricing)); obecnie nie jest oferowany bezpłatny plan. Wyszukuj zasoby, z których korzysta dana strona, a nie tylko identyfikatory trackerów: ścieżkę skryptu, nazwę własnego pakietu lub hosta, z którego ładowany jest zasób. Wynik pokaże każdą stronę, na której występuje ten zasób.

API zwraca stack dla pojedynczej domeny, co przydaje się do potwierdzenia, że potencjalny zasób należy do tego samego środowiska:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Zwraca każdą wykrytą technologię wraz z jej kategorią. Asset pivoting jest obecnie dostępne tylko dla stron WWW, a API umożliwia wyszukiwanie dla poszczególnych domen.

### **Favicon**

Czy wiesz, że możemy znaleźć powiązane domeny i subdomeny naszego celu, wyszukując ten sam hash ikony favicon? Właśnie to robi narzędzie [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) stworzone przez [@m4ll0k2](https://twitter.com/m4ll0k2). Oto jak go używać:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Wyniki Favihash użyte do wykrywania domen współdzielących ten sam hash ikony favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Mówiąc prosto, favihash pozwala nam wykrywać domeny, które mają taki sam hash ikony favicon jak nasz cel.

![Wynik favihash użyty do wykrywania domen z tym samym hashem favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Użyj znanego hasha favicon jako pivotu w Shodan lub FOFA, aby znaleźć inne ujawnione instancje tej samej technologii.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Tak możesz **obliczyć hash faviconu** witryny (MMH3 dla bajtów faviconu **zakodowanych w base64**):

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

Możesz też pozyskiwać hashe faviconów na dużą skalę za pomocą [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), a następnie pivotować w Shodan/Censys.

Traktuj fingerprinty faviconów jako wskazówki i weryfikuj je za pomocą powiązanych sygnałów.<sup>[[3]](#references)[[4]](#references)</sup>

- **Traktuj hash jako wskaźnik, a nie dowód**: MMH3 jest kompaktowy; możliwe są kolizje, ponowne użycie ikon i celowe podszywanie się.
- **Sprawdzaj nie tylko** `/favicon.ico`: sprawdź ścieżki frameworków i buildów, pliki manifestów, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, inline data URL-e oraz tagi HTML `<link rel="icon">`.
- **Statyczne zasoby mogą być nadal dostępne za WAF/SSO/IdP**: pobierz ikonę bezpośrednio i sprawdź nagłówki `ETag`, `Last-Modified`, przekierowania oraz cache.
- **Weryfikuj dopasowania za pomocą powiązanych sygnałów**: porównaj tytuł, hash HTML/body, nagłówki, subject/SAN certyfikatu TLS, komponenty produktu i otwarte porty.
- **Grupuj według hasha HTML/body**: spójny szablon wzmacnia fingerprint; różne szablony sugerują ikonę ogólną lub współdzieloną.
- **Hash występujący wśród niepowiązanych sygnatur, portów i produktów traktuj jako potencjalną honeypot lub placeholder.**
- **W przypadku niejednoznacznych celów porównaj prawdziwą stronę z nieistniejącą ścieżką**, taką jak `/_favicon_probe_<8-hex>`; identyczne odpowiedzi hostingu lub strony parkingowej mogą wyjaśniać współdzielenie ikony.
- **Rozpocznij triage od reguł detekcji Nuclei lub publicznych zbiorów danych**, które mapują hashe faviconów na produkty i CPE.
- **Pamiętaj o luce w pokryciu skoncentrowanym na IP**: powierzchnie za CDN, routowane przez SNI, anycast oraz dostępne wyłącznie przez domenę mogą nie występować w zbiorach danych podobnych do Shodan.

### **Copyright / unikalny ciąg**

Wyszukuj na stronach WWW **ciągi, które mogą być wspólne dla różnych witryn tej samej organizacji**. Dobrym przykładem może być **ciąg copyright**. Następnie wyszukaj ten ciąg w **Google**, w innych **przeglądarkach** albo nawet w **Shodan**: `shodan search http.html:"Copyright string"`

### **Czas CRT**

Często używa się zadania cron, takiego jak

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

aby odnowić wszystkie certyfikaty na serwerze jednocześnie. Korelowanie znaczników czasu certyfikatów lub ich pozycji w logach Certificate Transparency może ujawnić powiązane domeny.<sup>[[6]](#references)</sup>

Użyj też bezpośrednio logów **Certificate Transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Informacje DMARC poczty

Możesz skorzystać ze strony, takiej jak [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com), lub narzędzia, takiego jak [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains), aby znaleźć **domeny i subdomeny współdzielące te same informacje DMARC**.\
Inną przydatną usługą jest [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Porzucony rekord A może stać się osiągalny, gdy dostawca chmury ponownie przypisze adres IP. Przywołane badania przedstawiają oportunistyczny proces, w którym uruchamia się instancję i koreluje jej adres z danymi passive DNS; scenariusze przejęcia testuj wyłącznie w ramach autoryzowanego zakresu.<sup>[[7]](#references)</sup>

### **Inne metody**

Powtarzaj odpowiednie działania wyszukiwawcze za każdym razem, gdy znajdziesz nową domenę: każdy wynik może ujawnić dodatkowe nazwy z certyfikatów, powiązania passive DNS, dopasowania faviconów i identyfikatory organizacji, które nie były widoczne na podstawie pierwotnej domeny wyjściowej.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Jak już wiesz, jak nazywa się organizacja będąca właścicielem przestrzeni adresowej IP. Możesz wyszukiwać w Shodan na podstawie tych danych, używając: `org:"Tesla, Inc."` Sprawdź znalezione hosty pod kątem nowych, nieoczekiwanych domen w certyfikacie TLS.

Możesz pobrać **certyfikat TLS** głównej strony internetowej, uzyskać **nazwę organizacji**, a następnie wyszukać tę nazwę w **certyfikatach TLS** wszystkich stron internetowych znanych **Shodanowi**, używając filtra: `ssl:"Tesla Motors"` albo narzędzia takiego jak [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)to narzędzie, które wyszukuje **domeny powiązane** z domeną główną oraz ich **subdomeny**. Jest naprawdę świetne.

**Passive DNS / Historyczne DNS**

Dane passive DNS świetnie nadają się do znajdowania **starych i zapomnianych rekordów**, które nadal wskazują adresy lub mogą zostać przejęte. Sprawdź:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Poszukiwanie podatności**

Sprawdź, czy możliwe jest [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Być może jakaś firma **używa domeny**, ale **utraciła do niej prawa własności**. Po prostu ją zarejestruj (jeśli jest wystarczająco tania) i poinformuj firmę.

Jeśli znajdziesz **domenę z innym adresem IP** niż te, które już znalazłeś podczas wykrywania zasobów, wykonaj **podstawowy skan podatności** (za pomocą Nessus lub OpenVAS) oraz [**skan portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. Zależnie od uruchomionych usług, w **tej książce znajdziesz kilka sztuczek, jak je „zaatakować”**.\
_Pamiętaj, że czasami domena jest hostowana pod adresem IP, którego klient nie kontroluje, więc nie należy ono do zakresu testów. Zachowaj ostrożność._

## Subdomeny

> Znamy wszystkie firmy objęte zakresem, wszystkie zasoby każdej z nich oraz wszystkie powiązane z nimi domeny.

Czas znaleźć wszystkie możliwe subdomeny każdej z odnalezionych domen.

> [!TIP]
> Pamiętaj, że niektóre narzędzia i techniki wyszukiwania domen mogą również pomóc w znajdowaniu subdomen.

### **DNS**

Spróbujmy znaleźć **subdomeny** na podstawie rekordów **DNS**. Powinniśmy też spróbować wykonać **Zone Transfer** (jeśli jest podatny, należy to zgłosić).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Aby znaleźć API i platformy obejmujące infrastrukturę, reputację, rejestry naruszeń i wzbogacanie danych wykraczające poza wykrywanie subdomen, zobacz [katalog API do rozpoznania i analizy zagrożeń](reconnaissance-and-threat-intelligence-apis.md).

Najszybszym sposobem na znalezienie wielu subdomen jest przeszukanie zewnętrznych źródeł. Najczęściej używane **narzędzia** to:


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

Istnieją **inne interesujące narzędzia/API**, które mogą być przydatne do znajdowania subdomen, nawet jeśli nie są bezpośrednio do tego przeznaczone, na przykład:

- [**IP.THC.ORG**](https://ip.thc.org) — darmowe API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Bezpłatne API AnubisDB**](https://github.com/jonluca/Anubis-DB)

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

- [**SecurityTrails**](https://securitytrails.com/) oferuje ograniczony darmowy dostęp do API z aktualnymi danymi DNS i subdomen; dostęp do historycznych danych DNS/IP wymaga płatnego planu.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Ten projekt bezpłatnie udostępnia **wszystkie subdomeny powiązane z programami bug-bounty**. Możesz uzyskać dostęp do tych danych również za pomocą [chaospy](https://github.com/Moaaz-0x/chaospy) albo sprawdzić zakres używany przez ten projekt: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

**Porównanie** wielu z tych narzędzi znajdziesz tutaj: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Spróbujmy znaleźć nowe **subdomeny**, przeprowadzając brute-force na serwerach DNS z użyciem możliwych nazw subdomen.

Do tego działania potrzebne będą **listy słów z typowymi nazwami subdomen, takie jak**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Potrzebne będą również adresy IP dobrych resolverów DNS. Aby wygenerować listę zaufanych resolverów DNS, możesz pobrać listę resolverów z [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) i użyć [**dnsvalidator**](https://github.com/vortexau/dnsvalidator), aby je przefiltrować. Możesz też skorzystać z: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Najbardziej polecane narzędzia do DNS brute-force to:

- [**massdns**](https://github.com/blechschmidt/massdns): To pierwsze narzędzie umożliwiające skuteczny DNS brute-force. Jest bardzo szybkie, ale podatne na false positive.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Wydaje mi się, że ten używa tylko 1 resolvera.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) to wrapper na `massdns`, napisany w Go, który umożliwia enumerowanie prawidłowych subdomen za pomocą aktywnego bruteforce, a także rozwiązywanie subdomen z obsługą wildcardów i łatwą obsługą wejścia-wyjścia.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Używa również `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) wykorzystuje asyncio do asynchronicznego brute force nazw domenowych.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Druga runda brute-force DNS

Po znalezieniu poddomen za pomocą otwartych źródeł i brute-force możesz wygenerować warianty znalezionych poddomen, aby spróbować znaleźć ich jeszcze więcej. Przydatnych jest kilka narzędzi:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Na podstawie domen i poddomen generuje permutacje.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Generuje permutacje na podstawie podanych domen i subdomen.
  - [**tutaj**](https://github.com/subfinder/goaltdns/blob/master/words.txt) znajdziesz **wordlistę** permutacji goaltdns.

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Na podstawie domen i subdomen generuje permutacje. Jeśli nie wskazano pliku z permutacjami, gotator użyje własnego.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Oprócz generowania permutacji subdomen może też próbować je rozwiązać (ale lepiej użyć wcześniej omówionych narzędzi).
  - [**Tutaj**](https://github.com/infosec-au/altdns/blob/master/words.txt) znajdziesz wordlist z permutacjami dla altdns.

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Kolejne narzędzie do wykonywania permutacji, mutacji i modyfikacji subdomen. Narzędzie będzie brute force’ować wynik (nie obsługuje DNS wildcard).
  - Listę słów z permutacjami dla dmut znajdziesz [**tutaj**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

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

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ to fuzzer do brute-force subdomen, połączony z niezwykle prostym, ale skutecznym algorytmem kierowanym odpowiedziami DNS. Wykorzystuje dostarczony zestaw danych wejściowych, taki jak dostosowana wordlista lub historyczne rekordy DNS/TLS, aby precyzyjnie generować kolejne pasujące nazwy domen i iteracyjnie rozszerzać ich zestaw na podstawie informacji zebranych podczas skanowania DNS.

```
echo www | subzuf facebook.com
```

### **Przepływ pracy związany z wykrywaniem subdomen**

Przykłady przepływów pracy Trickest łączą OSINT, brute force DNS i etapy permutacji, umożliwiając powtarzalne wykrywanie subdomen.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / wirtualne hosty**

Jeśli znajdziesz adres IP zawierający **jedną lub kilka stron internetowych** należących do subdomen, możesz spróbować **znaleźć inne subdomeny z witrynami na tym adresie IP**, szukając domen przypisanych do adresu IP w **źródłach OSINT** lub wykonując **brute force nazw domen VHost na tym adresie IP**.

#### OSINT

Możesz znaleźć **VHosts na adresach IP, używając** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **lub innych API**.

**Brute force**

Jeśli podejrzewasz, że jakaś subdomena może być ukryta na serwerze WWW, możesz spróbować wykryć ją metodą brute force:

W przypadku vhostów opartych na nazwach testuj nagłówek `Host` i użyj automatycznej kalibracji ffuf, aby odfiltrować domyślną odpowiedź.<sup>[[2]](#references)</sup>

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

Czasami można znaleźć strony, które zwracają nagłówek _**Access-Control-Allow-Origin**_ tylko wtedy, gdy w nagłówku _**Origin**_ ustawiona jest prawidłowa domena/subdomena. W takich sytuacjach można wykorzystać to zachowanie, aby **odkryć** nowe **subdomeny**.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute force bucketów**

Podczas wyszukiwania **subdomen** zwracaj uwagę, czy **wskazują** na jakiegoś rodzaju **bucket**, a jeśli tak, [**sprawdź uprawnienia**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Ponadto, ponieważ na tym etapie znasz już wszystkie domeny objęte zakresem, spróbuj [**odgadnąć możliwe nazwy bucketów metodą brute force i sprawdzić uprawnienia**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Monitorowanie**

Możesz **monitorować**, czy tworzone są **nowe subdomeny** domeny, śledząc logi **Certificate Transparency** — robi to [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py).

### **Wyszukiwanie podatności**

Sprawdź, czy możliwe są [**przejęcia subdomen**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Jeśli **subdomena** wskazuje na jakiś **bucket S3**, [**sprawdź uprawnienia**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Jeśli znajdziesz **subdomenę z adresem IP różnym** od adresów znalezionych wcześniej podczas wykrywania zasobów, wykonaj **podstawowy skan podatności** (za pomocą Nessus lub OpenVAS) oraz [**skan portów**](../pentesting-network/index.html#discovering-hosts-from-the-outside) przy użyciu **nmap/masscan/shodan**. W zależności od uruchomionych usług możesz znaleźć **w tej książce kilka sposobów na ich „zaatakowanie”**.\
_Zauważ, że subdomena może czasami być hostowana na adresie IP, którego klient nie kontroluje, a więc który nie jest objęty zakresem. Zachowaj ostrożność._

## IPs

Na początkowych etapach mogłeś **znaleźć zakresy IP, domeny i subdomeny**.\
Czas **zebrać wszystkie adresy IP z tych zakresów** oraz adresy IP dla **domen/subdomen (zapytania DNS).**

Korzystając z usług takich jak poniższe, możesz również znaleźć **wcześniejsze adresy IP używane przez domeny i subdomeny**. Te adresy IP mogą nadal należeć do klienta (i mogą pozwolić Ci znaleźć [**obejścia CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (dostęp do historycznych danych DNS/IP wymaga płatnego planu)

Możesz też sprawdzić, które domeny wskazują na konkretny adres IP, używając narzędzia [**hakip2host**](https://github.com/hakluke/hakip2host) lub internetowej usługi odwrotnego wyszukiwania IP, takiej jak [**NetAPI**](https://netapi.com/lookup-ip/).

### **Wyszukiwanie podatności**

**Wykonaj skan portów wszystkich adresów IP, które nie należą do CDN** (ponieważ najprawdopodobniej nie znajdziesz tam niczego interesującego). Wykryte działające usługi mogą **ujawnić podatności**.

**Znajdź** [**poradnik**](../pentesting-network/index.html) **o skanowaniu hostów.**

## Poszukiwanie serwerów WWW

> Znaleźliśmy wszystkie firmy i ich zasoby oraz znamy zakresy IP, domeny i subdomeny objęte zakresem. Czas poszukać serwerów WWW.

Na poprzednich etapach prawdopodobnie wykonałeś już **rozpoznanie znalezionych adresów IP i domen**, więc być może **znalazłeś już wszystkie możliwe serwery WWW**. Jeśli jednak tak się nie stało, pokażemy teraz kilka **szybkich sposobów na wyszukiwanie serwerów WWW** w zakresie.

Pamiętaj, że opisane działania będą **ukierunkowane na wykrywanie aplikacji webowych**, dlatego należy również wykonać **skanowanie podatności** i **skanowanie portów** (**jeśli pozwala na to zakres**).

[**Szybki sposób**](../pentesting-network/index.html#http-port-discovery) na wykrywanie **otwartych portów** związanych z serwerami **WWW** za pomocą [**masscan** znajdziesz tutaj](../pentesting-network/index.html#http-port-discovery).\
Inne przydatne narzędzia do wyszukiwania serwerów WWW to [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) i [**httpx**](https://github.com/projectdiscovery/httpx). Wystarczy przekazać im listę domen, a spróbują połączyć się z portami 80 (http) i 443 (https). Możesz też wskazać inne porty do sprawdzenia:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Zrzuty ekranu**

Skoro udało Ci się znaleźć **wszystkie serwery webowe** w zakresie (wśród **adresów IP** firmy oraz wszystkich jej **domen** i **subdomen**), prawdopodobnie **nie wiesz, od czego zacząć**. Uprośćmy więc sprawę: zacznijmy od robienia zrzutów ekranu wszystkich tych serwerów. Już samo **rzucenie okiem** na **stronę główną** może ujawnić **dziwne** endpointy, które są bardziej **podatne** na **podatności**.

Do realizacji tego pomysłu możesz użyć [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) lub [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Możesz też uruchomić [**eyeballer**](https://github.com/BishopFox/eyeballer) na wszystkich **zrzutach ekranu**, aby wskazał Ci, **które prawdopodobnie zawierają podatności**, a które nie.

## Zasoby chmury publicznej

Aby znaleźć potencjalne zasoby cloud należące do firmy, **zacznij od listy słów kluczowych, które ją identyfikują**. Na przykład w przypadku firmy kryptowalutowej możesz użyć słów takich jak: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Potrzebne będą Ci również wordlisty **popularnych słów używanych w nazwach bucketów**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Następnie wygeneruj z tych słów **permutacje** (więcej informacji znajdziesz w sekcji [**Druga runda brute-force DNS**](#second-dns-bruteforce-round)).

Na podstawie uzyskanych wordlist możesz użyć narzędzi takich jak [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **lub** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Pamiętaj, że szukając zasobów cloud, nie powinieneś **ograniczać się do bucketów w AWS**.

### **Szukanie podatności**

Jeśli znajdziesz takie zasoby jak **otwarte buckety lub udostępnione funkcje cloud**, powinieneś **uzyskać do nich dostęp**, sprawdzić, co oferują i czy możesz je wykorzystać.

## Emaile

Mając **domeny** i **subdomeny** objęte zakresem, masz już praktycznie wszystko, **czego potrzebujesz, aby zacząć szukać emaili**. Oto **API** i **narzędzia**, które najlepiej sprawdziły się u mnie przy wyszukiwaniu emaili firmowych:

- [**theHarvester**](https://github.com/laramies/theHarvester) - z API
- API [**https://hunter.io/**](https://hunter.io/) (darmowa wersja)
- API [**https://app.snov.io/**](https://app.snov.io/) (darmowa wersja)
- API [**https://minelead.io/**](https://minelead.io/) (darmowa wersja)

### **Szukanie podatności**

Emaile przydadzą się później do **brute-force'owania logowania do aplikacji webowych i usług uwierzytelniania** (takich jak SSH). Są też potrzebne do **phishingu**. Ponadto te API dostarczą Ci jeszcze więcej **informacji o osobie** stojącej za emailem, co jest przydatne podczas kampanii phishingowej.

## Credential Leaks

Mając **domeny,** **subdomeny** i **emaile**, możesz zacząć szukać danych uwierzytelniających, które wyciekły w przeszłości i dotyczą tych adresów email:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe dane uwierzytelniające, które wyciekły**, to bardzo łatwy sukces.

## Secrets Leaks

Credential leaks dotyczą włamań do firm, podczas których **wyciekły i zostały sprzedane poufne informacje**. Firmy mogą jednak ucierpieć z powodu **innych leaków**, których informacje nie znajdują się w tych bazach danych:

### Github Leaks

Dane uwierzytelniające i API mogą wyciec do **publicznych repozytoriów** **firmy** lub **użytkowników** pracujących w tej firmie na Githubie.\
Możesz użyć **narzędzia** [**Leakos**](https://github.com/carlospolop/Leakos), aby **pobrać** wszystkie **publiczne repozytoria** **organizacji** i jej **programistów**, a następnie automatycznie uruchomić na nich [**gitleaks**](https://github.com/gitleaks/gitleaks).

**Leakos** można też wykorzystać do uruchomienia **gitleaks** na wszystkich **tekstowych** adresach **URL przekazanych** do narzędzia, ponieważ czasami **strony webowe również zawierają sekrety**.

#### Github Dorks

Zajrzyj na stronę [GitHub dorks and leaks](github-leaked-secrets.md), aby znaleźć potencjalne **GitHub dorks** do wyszukiwania w organizacji.

### Pastes Leaks

Czasami atakujący lub po prostu pracownicy **publikują treści firmowe w serwisach typu paste**. Mogą one zawierać **poufne informacje**, ale nie muszą, jednak warto ich poszukać.\
Możesz użyć narzędzia [**Pastos**](https://github.com/carlospolop/Pastos), aby jednocześnie przeszukiwać ponad 80 serwisów typu paste.

### Google Dorks

Stare, ale sprawdzone google dorks są zawsze przydatne do znajdowania **ujawnionych informacji, które nie powinny być publiczne**. Problem w tym, że [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) zawiera kilka **tysięcy** możliwych zapytań, których nie da się uruchomić ręcznie. Możesz więc wybrać swoje ulubione 10 zapytań albo użyć **narzędzia takiego jak** [**Gorks**](https://github.com/carlospolop/Gorks), **aby uruchomić je wszystkie**.

_Zwróć uwagę, że narzędzia, które próbują przeszukać całą bazę za pomocą standardowej przeglądarki Google, nigdy nie skończą, ponieważ Google bardzo szybko Cię zablokuje._

### **Szukanie podatności**

Jeśli znajdziesz **prawidłowe dane uwierzytelniające lub tokeny API, które wyciekły**, to bardzo łatwy sukces.

## Podatności w publicznym kodzie

Jeśli okaże się, że firma udostępnia **kod open source**, możesz go **przeanalizować** i poszukać w nim **podatności**.

**W zależności od języka** możesz użyć różnych **narzędzi**; zobacz listę [narzędzi do przeglądu kodu źródłowego](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Dostępne są również bezpłatne usługi umożliwiające **skanowanie publicznych repozytoriów**, takie jak:

- [**Snyk**](https://app.snyk.io/)

## [**Metodologia pentestingu aplikacji webowych**](../../network-services-pentesting/pentesting-web/index.html)

**Większość podatności** wykrywanych przez bug hunterów znajduje się w **aplikacjach webowych**, dlatego w tym miejscu chciałbym omówić **metodologię testowania aplikacji webowych**. [**Informacje na ten temat znajdziesz tutaj**](../../network-services-pentesting/pentesting-web/index.html).

Chcę też szczególnie wspomnieć o sekcji [**Narzędzia open source do automatycznego skanowania aplikacji webowych**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), ponieważ chociaż nie należy oczekiwać, że znajdą bardzo poważne podatności, przydają się do włączenia ich do **workflow, aby uzyskać wstępne informacje o aplikacjach webowych.**

## Podsumowanie

> Gratulacje! Na tym etapie masz już za sobą **całą podstawową enumerację**. Tak, to podstawy, bo można przeprowadzić znacznie więcej enumeracji (pokażę później więcej trików).

Masz już za sobą:

1. Znalezienie wszystkich **firm** objętych zakresem
2. Znalezienie wszystkich **zasobów** należących do firm (i przeprowadzenie skanowania podatności, jeśli mieści się to w zakresie)
3. Znalezienie wszystkich **domen** należących do firm
4. Znalezienie wszystkich **subdomen** tych domen (czy możliwy jest subdomain takeover?)
5. Znalezienie wszystkich **adresów IP** (zarówno z **CDN-ów**, jak i spoza nich) objętych zakresem.
6. Znalezienie wszystkich **serwerów webowych** i zrobienie ich **zrzutów ekranu** (czy jest coś dziwnego, co warto dokładniej sprawdzić?)
7. Znalezienie wszystkich **potencjalnych zasobów chmury publicznej** należących do firmy.
8. **Emaile**, **credential leaks** i **secret leaks**, które mogą zapewnić Ci **łatwy sukces**.
9. **Pentest wszystkich znalezionych aplikacji webowych**

## **Kompletne, automatyczne narzędzia do recon**

Dostępnych jest kilka narzędzi, które wykonują część opisanych działań dla wskazanego zakresu.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Dość stare i nieaktualizowane



## References

- [1] [Jason Haddix – Metodologia bug hunterów v4.0: rozpoznanie](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – O faviconach: od ikon przeglądarki po analizę powierzchni ataku](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Wykorzystanie favicon.ico w bug bounty, OSINT i nie tylko](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Odkrywanie domen za pomocą ataku korelacji czasowej na Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Pasywne przejęcie: odkrywanie (i odtwarzanie) kosztownej kampanii subdomain takeover](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: unikalna metoda enumeracji subdomen](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Kompletny workflow wykrywania subdomen, część 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automatyczne wykrywanie subdomen metodą brute-force za pomocą workflow Trickest, część 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Zrzut ekranu z wynikiem favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
