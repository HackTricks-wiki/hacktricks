# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Aby wykryć próbę phishingu ważne jest, aby **zrozumieć techniki phishingu stosowane obecnie**. Na stronie nadrzędnej tego wpisu znajdziesz te informacje, więc jeśli nie wiesz, jakie techniki są dziś używane, polecam przejść na stronę nadrzędną i przeczytać przynajmniej tę sekcję.

Ten wpis opiera się na założeniu, że **atakujący spróbują w jakiś sposób naśladować lub użyć nazwy domeny ofiary**. Jeśli Twoja domena nazywa się `example.com` i padniesz ofiarą phishingu używając całkowicie innej nazwy domeny, takiej jak `youwonthelottery.com`, te techniki tego nie wykryją.

## Wariacje nazw domen

Dość łatwo jest **wykryć** te próby **phishingu**, które użyją **podobnej nazwy domeny** w wiadomości e-mail.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, których może użyć atakujący i **sprawdzić**, czy są **zarejestrowane** lub czy mają przypisane jakieś **IP**.

### Wyszukiwanie podejrzanych domen

Do tego celu możesz użyć dowolnego z następujących narzędzi. Zauważ, że narzędzia te automatycznie wykonują zapytania DNS, aby sprawdzić, czy domena ma przypisane jakieś IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wskazówka: Jeśli wygenerujesz listę kandydatów, wrzuć ją także do logów Twojego DNS resolvera, aby wykryć zapytania **NXDOMAIN** z wnętrza Twojej organizacji (użytkownicy próbujący dotrzeć do literówki zanim atakujący ją zarejestruje). Przekieruj do sinkhole lub wstępnie zablokuj te domeny, jeśli polityka na to pozwala.

### Bitflipping

**Krótki opis tej techniki znajdziesz na stronie nadrzędnej. Lub przeczytaj oryginalne badania w** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na przykład modyfikacja 1 bitu w domenie microsoft.com może przekształcić ją w _windnws.com._\
**Atakujący mogą zarejestrować jak najwięcej domen bit-flipping powiązanych z ofiarą, by przekierowywać prawdziwych użytkowników do swojej infrastruktury**.

**Wszystkie możliwe domeny bit-flipping powinny być również monitorowane.**

Jeśli musisz również wziąć pod uwagę homoglyph/IDN lookalikes (np. mieszanie znaków łacińskich i cyrylicy), sprawdź:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Podstawowe sprawdzenia

Gdy masz listę potencjalnych podejrzanych domen, powinieneś je **sprawdzić** (głównie porty HTTP i HTTPS), aby **zobaczyć, czy używają jakiegoś formularza logowania podobnego** do tego z domeny ofiary.\
Możesz też sprawdzić port 3333, czy jest otwarty i uruchomiony jest na nim `gophish`.\
Warto także znać **jak stara jest każda wykryta podejrzana domena** — im młodsza, tym większe ryzyko.\
Możesz również uzyskać **zrzuty ekranu** podejrzanej strony HTTP i/lub HTTPS, żeby zobaczyć, czy wygląda podejrzanie i w takim wypadku **wejść na nią, by przyjrzeć się dokładniej**.

### Zaawansowane sprawdzenia

Jeśli chcesz pójść o krok dalej, polecam **monitorować te podejrzane domeny i od czasu do czasu wyszukiwać kolejne** (codziennie? to zajmuje tylko kilka sekund/minut). Powinieneś też **sprawdzić** otwarte **porty** powiązanych IP i **wyszukać instancje `gophish` lub podobnych narzędzi** (tak, atakujący też popełniają błędy) oraz **monitorować strony HTTP i HTTPS podejrzanych domen i subdomen**, aby sprawdzić, czy skopiowały jakieś formularze logowania z serwisów ofiary.\
Aby to **zautomatyzować**, polecam mieć listę formularzy logowania domen ofiary, spiderować podejrzane strony i porównywać każdy znaleziony formularz logowania z formularzami domeny ofiary przy użyciu czegoś w rodzaju `ssdeep`.\
Jeśli zlokalizujesz formularze logowania na podejrzanych domenach, możesz spróbować **wysłać fałszywe poświadczenia** i **sprawdzić, czy następuje przekierowanie do domeny ofiary**.

---

### Polowanie po favicon i web fingerprints (Shodan/ZoomEye/Censys)

Wiele kitów phishingowych ponownie używa favicon marki, którą podszywają. Skanery ogólnokrajowe obliczają MurmurHash3 z base64-encoded faviconu. Możesz wygenerować hash i pivotować na niego:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Zapytanie do Shodan: `http.favicon.hash:309020573`
- Z narzędziami: sprawdź narzędzia społecznościowe takie jak favfreak, aby generować hashes i dorks dla Shodan/ZoomEye/Censys.

Uwagi
- Favicons są ponownie używane; traktuj dopasowania jako leads i zweryfikuj zawartość i certs przed podjęciem działań.
- Łącz z domain-age i heurystykami opartymi na słowach kluczowych, aby uzyskać lepszą precyzję.

### Przeszukiwanie telemetrii URL (urlscan.io)

`urlscan.io` przechowuje historyczne zrzuty ekranu, DOM, requests i metadane TLS przesłanych URL-i. Możesz wyszukiwać nadużycia marki i klony:

Przykładowe zapytania (UI lub API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ogranicz do niedawnych wyników: dołącz `AND date:>now-7d`

Przykład API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Z JSON-a skup się na:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` — aby wykryć bardzo nowe certyfikaty używane do lookalikes
- `task.source` values like `certstream-suspicious` — aby powiązać znaleziska z monitoringiem CT

### Wiek domeny przez RDAP (skryptowalne)

RDAP zwraca zdarzenia utworzenia w formacie czytelnym dla maszyn. Przydatne do oznaczania **nowo zarejestrowanych domen (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Wzbogacaj swój pipeline, tagując domeny według przedziałów wieku rejestracji (np. <7 days, <30 days) i priorytetyzuj triage odpowiednio.

### TLS/JAx fingerprints do wykrywania infrastruktury AiTM

Nowoczesny credential-phishing coraz częściej wykorzystuje **Adversary-in-the-Middle (AiTM)** reverse proxies (np. Evilginx) do kradzieży session tokens. Możesz dodać detekcje po stronie sieci:

- Loguj TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) na egress. W niektórych buildach Evilginx zaobserwowano stabilne wartości JA4 client/server. Generuj alerty tylko na znane-bad fingerprints jako słaby sygnał i zawsze potwierdzaj treścią oraz intel domeny.
- Proaktywnie rejestruj metadata certyfikatów TLS (issuer, SAN count, użycie wildcard, validity) dla lookalike hosts odkrytych przez CT lub urlscan i koreluj z wiekiem DNS i geolokalizacją.

> Uwaga: Traktuj fingerprints jako wzbogacenie, nie jako jedyne blokady; frameworki ewoluują i mogą randomizować lub zacierać sygnatury.

### Nazwy domen zawierające słowa kluczowe

Strona nadrzędna wspomina też technikę wariacji nazwy domeny polegającą na umieszczeniu **domeny ofiary wewnątrz większej domeny** (np. paypal-financial.com dla paypal.com).

#### Certificate Transparency

Nie da się zastosować poprzedniego podejścia „Brute-Force”, ale faktycznie **można wykryć takie phishingowe próby** dzięki Certificate Transparency. Za każdym razem gdy CA wydaje certyfikat, szczegóły stają się publiczne. Oznacza to, że przeglądając lub monitorując Certificate Transparency (CT) można **odkryć domeny zawierające słowo kluczowe w swojej nazwie**. Na przykład, jeśli atakujący wygeneruje certyfikat dla [https://paypal-financial.com](https://paypal-financial.com), widząc ten certyfikat można znaleźć słowo kluczowe "paypal" i podejrzewać użycie domeny w kampanii phishingowej.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeruje, że możesz użyć Censys do wyszukiwania certyfikatów zawierających konkretne słowo kluczowe i filtrować po dacie (tylko „nowe” certyfikaty) oraz po issuerze CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Możesz jednak zrobić „to samo” używając darmowego serwisu [**crt.sh**](https://crt.sh). Możesz **wyszukać słowo kluczowe** i opcjonalnie **filtrować** wyniki **po dacie i CA**.

![](<../../images/image (519).png>)

Korzystając z tej ostatniej opcji możesz też użyć pola Matching Identities, aby sprawdzić, czy któraś tożsamość z prawdziwej domeny pasuje do którejkolwiek ze podejrzanych domen (uwaga: domena podejrzana może być false positive).

**Inna alternatywa** to świetny projekt [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream dostarcza strumień w czasie rzeczywistym nowo wygenerowanych certyfikatów, który możesz wykorzystać do wykrywania określonych słów kluczowych (prawie) w czasie rzeczywistym. Istnieje też projekt [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), który robi dokładnie to.

Praktyczna wskazówka: przy triage trafień z CT priorytetyzuj NRDs, untrusted/unknown registrars, privacy-proxy WHOIS oraz certy z bardzo świeżymi czasami `NotBefore`. Utrzymuj allowlistę posiadanych domen/brandów, aby zmniejszyć szum.

#### **Nowe domeny**

**Jeszcze jedna alternatywa** to zebranie listy **nowo zarejestrowanych domen** dla niektórych TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) oferuje taką usługę) i **sprawdzenie słów kluczowych w tych domenach**. Jednak długie domeny zwykle używają jednego lub więcej subdomen, więc słowo kluczowe nie pojawi się w FLD i nie będziesz w stanie znaleźć phishingowej subdomeny.

Dodatkowy heurystyczny wskaźnik: traktuj niektóre file-extension TLDs (np. `.zip`, `.mov`) z dodatkową podejrzliwością przy generowaniu alertów. Często są mylone z nazwami plików w lure'ach; łącz sygnał z TLD z brand keywords i wiekiem NRD dla lepszej precyzji.

## Referencje

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
