# Wykrywanie phishingu

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Aby wykryć próbę phishingu, należy **zrozumieć stosowane obecnie techniki phishingu**. Na stronie nadrzędnej tego wpisu znajdziesz te informacje, więc jeśli nie znasz technik używanych obecnie, zalecam przejście do strony nadrzędnej i przeczytanie przynajmniej tej sekcji.

Ten wpis opiera się na założeniu, że **atakujący będą próbowali w jakiś sposób naśladować nazwę domeny ofiary lub jej użyć**. Jeśli Twoja domena nazywa się `example.com`, a phishing jest przeprowadzany z użyciem zupełnie innej nazwy domeny, takiej jak `youwonthelottery.com`, techniki te nie pozwolą go wykryć.

## Warianty nazw domen

Dość **łatwo** jest **wykryć** próby **phishingu**, które wykorzystują w wiadomości e-mail **podobną nazwę domeny**.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, których może użyć atakujący, i **sprawdzić**, czy są **zarejestrowane**, albo po prostu sprawdzić, czy używa ich jakiś **IP**.

### Znajdowanie podejrzanych domen

W tym celu możesz użyć dowolnego z poniższych narzędzi. Pamiętaj, że narzędzia te automatycznie wykonują również żądania DNS, aby sprawdzić, czy domena ma przypisany adres IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wskazówka: Jeśli wygenerujesz listę kandydatów, przekaż ją również do logów resolvera DNS, aby wykrywać **zapytania NXDOMAIN z wewnątrz organizacji** (użytkownicy próbujący uzyskać dostęp do literówki, zanim atakujący faktycznie ją zarejestruje). Jeśli zasady na to pozwalają, przekieruj te domeny do sinkhole albo zablokuj je z wyprzedzeniem.

### Bitflipping

**Krótkie wyjaśnienie tej techniki znajdziesz na stronie nadrzędnej. Możesz też przeczytać oryginalne badanie pod adresem** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Na przykład modyfikacja 1 bitu w domenie microsoft.com może przekształcić ją w _windnws.com._\
**Atakujący mogą zarejestrować jak najwięcej domen związanych z ofiarą, powstałych w wyniku bit-flippingu, aby przekierowywać legalnych użytkowników do swojej infrastruktury**.<sup>[[1]](#references)</sup>

**Należy również monitorować wszystkie możliwe nazwy domen powstałe w wyniku bit-flippingu.**

Jeśli musisz również uwzględnić homoglyph/IDN lookalikes (np. mieszanie znaków łacińskich i cyrylicy), sprawdź:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Podstawowe kontrole

Po utworzeniu listy potencjalnie podejrzanych nazw domen należy je **sprawdzić** (głównie na portach HTTP i HTTPS), aby **zobaczyć, czy używają formularza logowania podobnego** do formularza w domenie ofiary.\
Możesz również sprawdzić port 3333, aby zobaczyć, czy jest otwarty i działa na nim instancja `gophish`.\
Warto także wiedzieć, **jak stara jest każda wykryta podejrzana domena** — im młodsza, tym większe ryzyko.\
Możesz również uzyskać **zrzuty ekranu** podejrzanej strony HTTP i/lub HTTPS, aby sprawdzić, czy jest podejrzana, a w takim przypadku **uzyskać do niej dostęp i dokładniej ją przeanalizować**.

### Zaawansowane kontrole

Jeśli chcesz pójść o krok dalej, zalecam **monitorowanie tych podejrzanych domen i okresowe wyszukiwanie kolejnych** (codziennie? zajmuje to tylko kilka sekund/minut). Należy również **sprawdzać** otwarte **porty** powiązanych adresów IP i **wyszukiwać instancje `gophish` lub podobnych narzędzi** (tak, atakujący również popełniają błędy), a także **monitorować strony HTTP i HTTPS podejrzanych domen i subdomen**, aby sprawdzić, czy skopiowano z nich formularz logowania z witryn ofiary.\
Aby **zautomatyzować ten proces**, zalecam posiadanie listy formularzy logowania z domen ofiary, przeszukanie podejrzanych stron i porównanie każdego formularza logowania znalezionego w podejrzanych domenach z każdym formularzem logowania z domeny ofiary przy użyciu narzędzia takiego jak `ssdeep`.\
Jeśli zlokalizowałeś formularze logowania w podejrzanych domenach, możesz spróbować **wysłać fałszywe dane uwierzytelniające** i **sprawdzić, czy następuje przekierowanie do domeny ofiary**.

---

### Wyszukiwanie na podstawie favicon i odcisków stron internetowych (Shodan/ZoomEye/Censys)

Wiele zestawów phishingowych ponownie wykorzystuje favicon marki, którą naśladują. Skanery obejmujące cały Internet obliczają MurmurHash3 zakodowanego w base64 favicon. Możesz wygenerować hash i wykorzystać go do dalszego wyszukiwania:

Przykład w Pythonie (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Wykonaj zapytanie do Shodan: `http.favicon.hash:309020573`
- Przy użyciu narzędzi: sprawdź narzędzia społeczności, takie jak favfreak, aby generować hashe i dorki dla Shodan/ZoomEye/Censys.

Uwagi
- Favicony są ponownie wykorzystywane; traktuj dopasowania jako wskazówki i przed podjęciem działań zweryfikuj zawartość oraz certyfikaty.
- Połącz to z heurystykami dotyczącymi wieku domeny i słów kluczowych, aby zwiększyć precyzję.

### Polowanie na dane telemetryczne URL (urlscan.io)

`urlscan.io` przechowuje historyczne zrzuty ekranu, DOM, żądania i metadane TLS przesłanych URL-i. Możesz polować na nadużycia marek i klony:<sup>[[2]](#references)</sup>

Przykładowe zapytania (UI lub API):
- Znajdź strony podobne do Twojej marki, wykluczając legalne domeny: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Znajdź strony hotlinkujące Twoje zasoby: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ogranicz wyniki do ostatnich rezultatów: dodaj `AND date:>now-7d`

Przykład API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Z JSON-u analizuj:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, aby wykrywać bardzo nowe certyfikaty dla lookalike’ów
- wartości `task.source`, takie jak `certstream-suspicious`, aby powiązać ustalenia z monitorowaniem CT

### Wiek domeny za pomocą RDAP (możliwość skryptowania)

RDAP zwraca zdarzenia utworzenia w formacie czytelnym maszynowo. Jest przydatny do oznaczania **nowo zarejestrowanych domen (NRD)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Wzbogać swój pipeline, przypisując domenom przedziały wieku rejestracji (np. <7 dni, <30 dni) i odpowiednio ustalając priorytet triage.

### Odciski palca TLS/JAx do wykrywania infrastruktury AiTM

Nowoczesne kampanie phishingowe wyłudzające dane uwierzytelniające coraz częściej wykorzystują reverse proxy **Adversary-in-the-Middle (AiTM)** (np. Evilginx) do kradzieży tokenów sesji. Możesz dodać detekcję po stronie sieci:

- Rejestruj odciski palca TLS/HTTP (JA3/JA4/JA4S/JA4H) na wyjściu z sieci. Niektóre wersje Evilginx były obserwowane ze stabilnymi wartościami JA4 klienta/serwera. Generuj alerty dotyczące znanych złośliwych odcisków palca wyłącznie jako słaby sygnał i zawsze potwierdzaj je na podstawie zawartości oraz informacji o domenie.<sup>[[3]](#references)</sup>
- Proaktywnie rejestruj metadane certyfikatów TLS (wystawca, liczba SAN, użycie wildcard, okres ważności) dla podobnych hostów wykrytych za pośrednictwem CT lub urlscan i koreluj je z wiekiem DNS oraz geolokalizacją.

> Uwaga: Traktuj odciski palca jako wzbogacenie danych, a nie jako jedyny mechanizm blokowania; frameworki ewoluują i mogą randomizować lub zaciemniać te informacje.

### Nazwy domen zawierające słowa kluczowe

Strona nadrzędna wspomina również o technice modyfikacji nazwy domeny, która polega na umieszczeniu **nazwy domeny ofiary wewnątrz większej domeny** (np. paypal-financial.com dla paypal.com).

#### Certificate Transparency

Nie można zastosować wcześniejszego podejścia „Brute-Force”, ale dzięki certificate transparency **możliwe jest również wykrywanie takich prób phishingu**. Za każdym razem, gdy CA wystawia certyfikat, jego szczegóły są publikowane. Oznacza to, że odczytując dane certificate transparency lub nawet je monitorując, **możliwe jest znalezienie domen zawierających słowo kluczowe w nazwie**. Na przykład jeśli atakujący wygeneruje certyfikat dla [https://paypal-financial.com](https://paypal-financial.com), analiza certyfikatu pozwala znaleźć słowo kluczowe „paypal” i ustalić, że używany jest podejrzany email.

W artykule [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeruje się użycie Censys do wyszukiwania certyfikatów dotyczących określonego słowa kluczowego oraz filtrowania według daty (tylko „nowe” certyfikaty) i wystawcy CA „Let's Encrypt”:<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Możesz jednak zrobić „to samo” przy użyciu darmowego serwisu [**crt.sh**](https://crt.sh). Możesz **wyszukać słowo kluczowe** i w razie potrzeby **filtrować** wyniki **według daty i CA**.

![Domain names using keywords - Certificate Transparency: However, you can do "the same" using the free web crt.sh . You can search for the keyword and the filter the results by date and...](<../../images/image (519).png>)

Korzystając z tej ostatniej opcji, możesz użyć pola Matching Identities, aby sprawdzić, czy jakakolwiek tożsamość z prawdziwej domeny pasuje do którejś z podejrzanych domen (pamiętaj, że podejrzana domena może być false positive).

**Inną alternatywą** jest znakomity projekt o nazwie [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream zapewnia strumień nowo wygenerowanych certyfikatów w czasie rzeczywistym, który można wykorzystać do wykrywania określonych słów kluczowych w czasie zbliżonym do rzeczywistego. Istnieje nawet projekt o nazwie [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), który właśnie to robi.

Praktyczna wskazówka: podczas triage wyników CT nadaj priorytet NRD, niezaufanym/nieznanym registrarom, WHOIS korzystającemu z privacy-proxy oraz certyfikatom z bardzo niedawnymi wartościami `NotBefore`. Utrzymuj allowlistę posiadanych domen/marek, aby ograniczyć liczbę fałszywych alarmów.

#### **Nowe domeny**

**Ostatnią alternatywą** jest zebranie listy **nowo zarejestrowanych domen** dla niektórych TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) oferuje taką usługę) i **sprawdzenie słów kluczowych w tych domenach**. Jednak długie domeny zwykle używają jednej lub większej liczby subdomen, dlatego słowo kluczowe nie pojawi się wewnątrz FLD i nie będzie można znaleźć phishingowej subdomeny.

Dodatkowa heurystyka: traktuj określone **TLD będące rozszerzeniami plików** (np. `.zip`, `.mov`) z dodatkową podejrzliwością podczas generowania alertów. Są one często mylone z nazwami plików w lure'ach; połącz sygnał TLD ze słowami kluczowymi marek oraz wiekiem NRD, aby uzyskać większą precyzję.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
