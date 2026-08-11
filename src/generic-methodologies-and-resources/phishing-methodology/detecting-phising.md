# Wykrywanie phishingu

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Aby wykryć próbę phishingu, ważne jest **zrozumienie technik phishingu stosowanych obecnie**. Na stronie nadrzędnej tego wpisu znajdziesz te informacje, więc jeśli nie znasz technik stosowanych obecnie, zalecam przejście do strony nadrzędnej i przeczytanie przynajmniej tej sekcji.

Ten wpis opiera się na założeniu, że **atakujący będą próbować w jakiś sposób naśladować nazwę domeny ofiary lub jej użyć**. Jeśli Twoja domena nazywa się `example.com`, a padłeś ofiarą phishingu z użyciem zupełnie innej nazwy domeny, na przykład `youwonthelottery.com`, te techniki tego nie wykryją.

## Warianty nazw domen

Dość **łatwo** jest **wykryć** próby **phishingu**, które w wiadomości e-mail wykorzystują **podobną** nazwę domeny.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw domen phishingowych**, których może użyć atakujący, i **sprawdzić**, czy są **zarejestrowane**, albo po prostu sprawdzić, czy używa ich jakiś **adres IP**.

### Wyszukiwanie podejrzanych domen

W tym celu możesz użyć dowolnego z poniższych narzędzi. Oba rozwiązują nazwy potencjalnych domen, aby sprawdzić, czy są używane.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wskazówka: Jeśli wygenerujesz listę potencjalnych domen, prześlij ją również do logów resolvera DNS, aby wykrywać **zapytania NXDOMAIN z wewnątrz organizacji** (użytkownicy próbujący odwiedzić literówkę, zanim atakujący faktycznie ją zarejestruje). Jeśli pozwalają na to zasady, przekieruj te domeny do sinkhole'a lub zablokuj je z wyprzedzeniem.

### Bitflipping

**Krótkie wyjaśnienie znajdziesz na stronie nadrzędnej; podstawowe badania dotyczące bitsquattingu Windows.com znajdziesz w [opracowaniu Remy'ego Haxa](https://remyhax.xyz/posts/bitsquatting-windows/) oraz [raporcie BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Na przykład modyfikacja jednego bitu w domenie microsoft.com może przekształcić ją w _windnws.com._\
**Atakujący mogą zarejestrować możliwie wiele domen wykorzystujących bit-flipping, powiązanych z ofiarą, aby przekierowywać prawidłowych użytkowników do swojej infrastruktury**.<sup>[[1]](#references)[[2]](#references)</sup>

**Należy również monitorować wszystkie możliwe nazwy domen wykorzystujących bit-flipping.**

Jeśli musisz także uwzględnić homoglyph/IDN lookalikes (np. mieszanie znaków łacińskich i cyrylicy), sprawdź:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Podstawowe kontrole

Po utworzeniu listy potencjalnie podejrzanych nazw domen należy je **sprawdzić** (głównie porty HTTP i HTTPS), aby **zobaczyć, czy używają formularza logowania podobnego** do formularza w domenie ofiary.\
Możesz również sprawdzić port 3333, aby zobaczyć, czy jest otwarty i działa na nim instancja `gophish`.\
Warto również wiedzieć, **jak stara jest każda wykryta podejrzana domena** — im młodsza, tym większe ryzyko.\
Możesz także uzyskać **zrzuty ekranu** podejrzanej strony HTTP i/lub HTTPS, aby sprawdzić, czy jest podejrzana, a w takim przypadku **uzyskać do niej dostęp i dokładniej ją przeanalizować**.

### Zaawansowane kontrole

Jeśli chcesz posunąć się o krok dalej, zalecam **monitorowanie tych podejrzanych domen i wyszukiwanie kolejnych** od czasu do czasu (codziennie? zajmuje to tylko kilka sekund/minut). Należy również **sprawdzać** otwarte **porty** powiązanych adresów IP i **wyszukiwać instancje `gophish` lub podobnych narzędzi** (tak, atakujący również popełniają błędy), a także **monitorować strony HTTP i HTTPS podejrzanych domen oraz subdomen**, aby sprawdzić, czy skopiowano z nich jakikolwiek formularz logowania ze stron ofiary.\
Aby **zautomatyzować ten proces**, zalecam posiadanie listy formularzy logowania z domen ofiary, przeszukiwanie podejrzanych stron i porównywanie każdego formularza logowania znalezionego w podejrzanych domenach z każdym formularzem logowania z domeny ofiary za pomocą narzędzia takiego jak `ssdeep`.\
Jeśli zlokalizowałeś formularze logowania w podejrzanych domenach, możesz spróbować **wysłać losowe dane uwierzytelniające** i **sprawdzić, czy nastąpi przekierowanie do domeny ofiary**.

---

### Wyszukiwanie na podstawie favicon i fingerprintów stron (Shodan/Censys)

Wiele kitów phishingowych ponownie wykorzystuje favicony marki, którą naśladują. Shodan hashuje zakodowane w base64 dane favicon za pomocą MurmurHash3, podczas gdy Censys udostępnia własne pola hashy favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Możesz wygenerować hash zgodny z Shodan i wykorzystać go do pivotowania:

Przykład w Pythonie (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Zapytaj Shodan: `http.favicon.hash:309020573`
- Przy użyciu narzędzi: sprawdź narzędzia społeczności, takie jak favfreak, aby obliczać hashe i generować Shodan dorks.<sup>[[16]](#references)</sup>

Uwagi
- Favikony są ponownie wykorzystywane; traktuj dopasowania jako wskazówki i przed podjęciem działań zweryfikuj zawartość oraz certyfikaty.
- Połącz to z heurystykami dotyczącymi wieku domeny i słów kluczowych, aby uzyskać większą precyzję.

### Polowanie na dane telemetryczne URL (urlscan.io)

`urlscan.io` przechowuje historyczne zrzuty ekranu, DOM, żądania i metadane TLS przesłanych URL-i. Możesz polować na nadużycia marki i klony:<sup>[[8]](#references)</sup>

Przykładowe zapytania (interfejs użytkownika lub API):
- Znajdź podobne strony, wykluczając legalne domeny: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Znajdź strony hotlinkujące Twoje zasoby: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ogranicz wyniki do ostatnich rezultatów: dodaj `AND date:>now-7d`

Przykład API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Z JSON-u przejdź do:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, aby wykrywać bardzo nowe certyfikaty dla lookalike
- wartości `task.source`, takie jak `certstream-suspicious`, aby powiązać ustalenia z monitorowaniem CT

### Wiek domeny przez RDAP (skryptowalne)

RDAP zwraca czytelne maszynowo zdarzenia rejestracji. Przydatne do oznaczania **nowo zarejestrowanych domen (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Wzbogać swój pipeline, przypisując domenom przedziały wieku rejestracji (np. <7 dni, <30 dni) i odpowiednio ustalając priorytet triage.

### Odciski palców TLS/JAx do wykrywania infrastruktury AiTM

Phishing poświadczeń może wykorzystywać reverse proxy **Adversary-in-the-Middle (AiTM)** (np. Evilginx) do kradzieży tokenów sesji.<sup>[[11]](#references)</sup> Możesz dodać detekcje po stronie sieci:

- Rejestruj odciski palców TLS/HTTP (JA3/JA4/JA4S/JA4H) na wyjściu z sieci. Niektóre buildy Evilginx były obserwowane ze stabilnymi wartościami JA4 klienta/serwera. Generuj alerty dotyczące znanych złośliwych odcisków palców wyłącznie jako słaby sygnał i zawsze potwierdzaj je na podstawie treści oraz analizy domeny.<sup>[[12]](#references)</sup>
- Proaktywnie rejestruj metadane certyfikatów TLS (wystawca, liczba SAN, użycie wildcard, okres ważności) dla hostów przypominających legalne domeny, wykrytych za pośrednictwem CT lub urlscan, i koreluj je z wiekiem DNS oraz geolokalizacją.

> Uwaga: traktuj odciski palców jako wzbogacenie danych, a nie jedyną podstawę blokowania; frameworki ewoluują i mogą randomizować lub zaciemniać te informacje.

### Nazwy domen zawierające słowa kluczowe

Strona nadrzędna wspomina również o technice wariacji nazwy domeny, polegającej na umieszczeniu **nazwy domeny ofiary wewnątrz większej domeny** (np. paypal-financial.com dla paypal.com).

#### Certificate Transparency

Logi Certificate Transparency (CT) ujawniają tożsamości certyfikatów, dlatego wyszukiwanie słów kluczowych związanych z marką w nazwach Subject lub SAN może ujawnić domeny przypominające legalne (na przykład certyfikat dla `paypal-financial.com` ujawnia słowo kluczowe `paypal`). W razie potrzeby filtruj wyniki według daty wydania i CA oraz weryfikuj kandydatów, ponieważ dopasowania słów kluczowych mogą generować false positives.<sup>[[13]](#references)</sup>

Oryginalny [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) Patrika Hudaka prezentuje ten workflow w Censys, w tym filtry dotyczące daty certyfikatu i wystawcy, takiego jak Let's Encrypt.<sup>[[13]](#references)</sup>

Możesz również użyć bezpłatnej usługi [**crt.sh**](https://crt.sh), aby wyszukiwać słowo kluczowe i filtrować wyniki według daty oraz CA.<sup>[[13]](#references)</sup>

Pole Matching Identities może pomóc w porównywaniu tożsamości prawdziwej domeny z podejrzanymi domenami, ale traktuj dopasowania jako wskazówki, a nie dowód.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) przesyła aktualizacje CT niemal w czasie rzeczywistym, a [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) pobiera ten strumień, aby oceniać podejrzane nazwy certyfikatów.<sup>[[14]](#references)[[15]](#references)</sup>

Praktyczna wskazówka: podczas triage wyników CT nadaj priorytet NRD, niezaufanym/nieznanym registrarom, WHOIS z proxy prywatności oraz certyfikatom z bardzo niedawnymi wartościami `NotBefore`. Utrzymuj allowlistę własnych domen/marek, aby ograniczyć szum.

#### **Nowe domeny**

Drugą opcją jest zbieranie nowo zarejestrowanych domen według TLD (na przykład za pośrednictwem [Whoxy](https://www.whoxy.com/newly-registered-domains/)) i filtrowanie ich pod kątem słów kluczowych związanych z marką. Ta metoda pomija phishing hostowany w subdomenach, gdy słowo kluczowe nie występuje w zarejestrowanej domenie.<sup>[[13]](#references)</sup>

Dodatkowa heurystyka: traktuj niektóre **TLD będące rozszerzeniami plików** (np. `.zip`, `.mov`) z większą podejrzliwością podczas generowania alertów. W lure'ach są one często mylone z nazwami plików; połącz sygnał TLD ze słowami kluczowymi związanymi z marką oraz wiekiem NRD, aby uzyskać większą precyzję.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Przejęcie ruchu do windows.com firmy Microsoft za pomocą bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Dogłębna analiza: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Dokumentacja mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Zbiór danych właściwości webowych platformy](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – dokumentacja Search API](https://urlscan.io/docs/search/)
- [9] [Pomoc dotycząca Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: odpowiedzi JSON dla Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Taktyki tokenów: jak zapobiegać kradzieży tokenów cloud, wykrywać ją i reagować na nią](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – fingerprinting sieci za pomocą JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Wykrywanie phishingu: narzędzia i techniki](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Przedstawiamy CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
