# Wykrywanie phishingu

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Aby wykryć próbę phishingu, warto **rozumieć techniki phishingowe stosowane obecnie**. Informacje na ten temat znajdziesz na stronie nadrzędnej tego wpisu, więc jeśli nie znasz aktualnie stosowanych technik, polecam przejść na tę stronę i przeczytać przynajmniej tę sekcję.

Ten wpis opiera się na założeniu, że **atakujący spróbują w jakiś sposób naśladować nazwę domeny ofiary lub jej użyć**. Jeśli Twoja domena to `example.com`, a ktoś przeprowadza phishing, używając z jakiegoś powodu zupełnie innej nazwy domeny, na przykład `youwonthelottery.com`, te techniki jej nie wykryją.

## Warianty nazw domen

**Wykrycie** prób **phishingu**, które wykorzystują w wiadomości e-mail **podobną nazwę domeny**, jest dość **łatwe**.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, których może użyć atakujący, i **sprawdzić**, czy zostały **zarejestrowane**, albo po prostu sprawdzić, czy korzysta z nich jakiś **IP**.

### Wyszukiwanie podejrzanych domen

W tym celu możesz użyć dowolnego z poniższych narzędzi. Oba sprawdzają domeny z listy kandydatów, aby ustalić, czy są używane.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Wskazówka: Jeśli wygenerujesz listę kandydatów, przekaż ją również do logów resolvera DNS, aby wykrywać **zapytania NXDOMAIN z sieci Twojej organizacji** (użytkownicy próbujący otworzyć błędnie wpisaną domenę, zanim atakujący ją zarejestruje). Jeśli pozwalają na to zasady, skieruj ruch z tych domen do sinkhole'a lub zablokuj je zawczasu.

### Bitflipping

**Krótkie wyjaśnienie znajdziesz na stronie nadrzędnej; badania dotyczące bitsquattingu Windows.com znajdziesz w [artykule Remy'ego Haxa](https://remyhax.xyz/posts/bitsquatting-windows/) i [raporcie BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Na przykład zmiana 1 bitu w domenie microsoft.com może zmienić ją w _windnws.com._\
**Atakujący mogą zarejestrować jak najwięcej domen utworzonych przez bit-flipping, powiązanych z ofiarą, aby przekierowywać użytkowników na swoją infrastrukturę**.<sup>[[1]](#references)[[2]](#references)</sup>

**Należy również monitorować wszystkie możliwe nazwy domen utworzone przez bit-flipping.**

Jeśli chcesz też uwzględnić podobne znaki homoglifowe/IDN (np. mieszanie znaków łacińskich i cyrylickich), sprawdź:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Podstawowe kontrole

Gdy masz już listę potencjalnie podejrzanych nazw domen, **sprawdź** je (głównie porty HTTP i HTTPS), aby **ustalić, czy używają formularza logowania podobnego** do formularza w domenie ofiary.\
Możesz też sprawdzić, czy port 3333 jest otwarty i czy działa na nim instancja `gophish`.\
Warto również sprawdzić **wiek każdej wykrytej podejrzanej domeny** — im jest młodsza, tym większe ryzyko.\
Możesz też zrobić **zrzuty ekranu** podejrzanej strony HTTP i/lub HTTPS, aby ocenić, czy wygląda podejrzanie, a jeśli tak — **otworzyć ją i dokładniej sprawdzić**.

### Zaawansowane kontrole

Jeśli chcesz pójść o krok dalej, polecam **monitorować te podejrzane domeny i od czasu do czasu wyszukiwać kolejne** (codziennie? zajmuje to tylko kilka sekund lub minut). Powinieneś też **sprawdzać** otwarte **porty** powiązanych adresów IP, **szukać instancji `gophish` lub podobnych narzędzi** (tak, atakujący też popełniają błędy) oraz **monitorować strony HTTP i HTTPS podejrzanych domen i subdomen**, aby sprawdzić, czy skopiowano z nich formularze logowania ze stron ofiary.\
Aby **zautomatyzować ten proces**, polecam utworzyć listę formularzy logowania w domenach ofiary, przeskanować podejrzane strony i porównać każdy znaleziony na nich formularz logowania z każdym formularzem z domeny ofiary za pomocą narzędzia takiego jak `ssdeep`.\
Jeśli udało Ci się znaleźć formularze logowania w podejrzanych domenach, możesz spróbować **wysłać nieprawidłowe dane logowania** i **sprawdzić, czy następuje przekierowanie do domeny ofiary**.

---

### Wyszukiwanie na podstawie favicon i odcisków stron WWW (Shodan/Censys)

Wiele zestawów phishingowych ponownie wykorzystuje favicony marki, którą podszywają się pod jej przedstawiciela. Shodan oblicza hash zakodowanych w base64 danych favicony za pomocą MurmurHash3, a Censys udostępnia własne pola hashy favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Możesz wygenerować hash zgodny z Shodanem i wyszukiwać powiązane wyniki:

Przykład w Pythonie (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Query Shodan: `http.favicon.hash:309020573`
- Za pomocą narzędzi: sprawdź narzędzia społeczności, takie jak favfreak, aby obliczać hashe i generować dorki Shodan.<sup>[[16]](#references)</sup>

Uwagi
- Favikony są używane ponownie; traktuj dopasowania jako wskazówki i przed podjęciem działań zweryfikuj zawartość i certyfikaty.
- Aby zwiększyć precyzję, połącz je z heurystykami dotyczącymi wieku domeny i słów kluczowych.

### Wyszukiwanie w telemetrii URL (urlscan.io)

`urlscan.io` przechowuje historyczne zrzuty ekranu, DOM, żądania i metadane TLS przesłanych adresów URL. Możesz wyszukiwać nadużycia związane z marką i jej klony:<sup>[[8]](#references)</sup>

Przykładowe zapytania (interfejs lub API):
- Znajdź podobne domeny, wykluczając własne legalne domeny: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Znajdź witryny bezpośrednio osadzające Twoje zasoby: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Ogranicz wyniki do najnowszych: dodaj `AND date:>now-7d`

Przykład API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Z JSON-a analizuj:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays`, aby wykrywać bardzo nowe certyfikaty dla domen podszywających się pod inne
- wartości `task.source`, takie jak `certstream-suspicious`, aby powiązać wyniki z monitoringiem CT

### Wiek domeny przez RDAP (możliwość skryptowania)

RDAP zwraca zdarzenia rejestracji w formacie czytelnym maszynowo. Przydatne do oznaczania **nowo zarejestrowanych domen (NRD)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Wzbogać swój pipeline, przypisując domenom przedziały wieku rejestracji (np. <7 dni, <30 dni) i odpowiednio ustalaj priorytety triage.

### Odciski TLS/JAx pomagające wykrywać infrastrukturę AiTM

Phishing wykradający dane uwierzytelniające może wykorzystywać reverse proxy typu **Adversary-in-the-Middle (AiTM)** (np. Evilginx) do kradzieży tokenów sesji.<sup>[[11]](#references)</sup> Możesz dodać mechanizmy wykrywania po stronie sieci:

- Rejestruj odciski TLS/HTTP (JA3/JA4/JA4S/JA4H) na wyjściu z sieci. Zaobserwowano, że niektóre wersje Evilginx używają stabilnych wartości JA4 klienta/serwera. Alertuj tylko na znane złe odciski, traktując je jako słaby sygnał, i zawsze weryfikuj je na podstawie treści oraz danych o domenie.<sup>[[12]](#references)</sup>
- Proaktywnie rejestruj metadane certyfikatów TLS (wystawcę, liczbę SAN, użycie wildcard, okres ważności) dla podobnie wyglądających hostów wykrytych przez CT lub urlscan, a następnie koreluj je z wiekiem DNS i geolokalizacją.

> Uwaga: Traktuj odciski jako dodatkowe informacje, a nie jedyną podstawę blokowania; frameworki ewoluują i mogą losować lub zaciemniać te wartości.

### Nazwy domen zawierające słowa kluczowe

Strona nadrzędna wspomina również o technice modyfikowania nazwy domeny, która polega na **umieszczeniu nazwy domeny ofiary w dłuższej domenie** (np. paypal-financial.com dla paypal.com).

#### Certificate Transparency

Dzienniki Certificate Transparency (CT) ujawniają tożsamości certyfikatów, dlatego wyszukiwanie słów kluczowych marki w nazwach Subject lub SAN może ujawnić podobnie wyglądające domeny (na przykład certyfikat dla `paypal-financial.com` zawiera słowo kluczowe `paypal`). W razie potrzeby filtruj wyniki według daty wystawienia i CA oraz weryfikuj znalezione domeny, ponieważ dopasowania słów kluczowych mogą być fałszywie dodatnie.<sup>[[13]](#references)</sup>

Oryginalny [wpis Patrika Hudaka o wyszukiwaniu domen phishingowych](https://0xpatrik.com/phishing-domains/) pokazuje ten proces w Censys, w tym filtry daty certyfikatu i wystawcy, np. Let's Encrypt.<sup>[[13]](#references)</sup>

![Wyniki wyszukiwania certyfikatów w Censys użyte do identyfikacji podobnie wyglądających domen](<../../images/image (1115).png>)

Możesz też skorzystać z bezpłatnej usługi [**crt.sh**](https://crt.sh), aby wyszukiwać słowa kluczowe i filtrować wyniki według daty oraz CA.<sup>[[13]](#references)</sup>

![Wyszukiwanie słowa kluczowego w crt.sh w celu znalezienia podejrzanych tożsamości certyfikatów](<../../images/image (519).png>)

Pole Matching Identities może pomóc w porównaniu tożsamości prawdziwej domeny z podejrzanymi domenami, ale traktuj dopasowania jako tropy, a nie dowód.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) przesyła aktualizacje CT niemal w czasie rzeczywistym, a [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) przetwarza ten strumień, aby oceniać podejrzane nazwy certyfikatów.<sup>[[14]](#references)[[15]](#references)</sup>

Praktyczna wskazówka: podczas triage wyników CT nadawaj priorytet NRD, niezaufanym lub nieznanym rejestratorom, WHOIS z proxy prywatności oraz certyfikatom z bardzo niedawnymi wartościami `NotBefore`. Utrzymuj listę dozwolonych własnych domen i marek, aby ograniczyć szum.

#### **Nowe domeny**

Innym rozwiązaniem jest zbieranie nowo zarejestrowanych domen według TLD (na przykład za pośrednictwem [Whoxy](https://www.whoxy.com/newly-registered-domains/)) i filtrowanie ich według słów kluczowych marki. Ta metoda nie wykrywa phishingu hostowanego w subdomenach, jeśli słowo kluczowe nie występuje w zarejestrowanej domenie.<sup>[[13]](#references)</sup>

Dodatkowa heurystyka: traktuj niektóre **TLD będące rozszerzeniami plików** (np. `.zip`, `.mov`) z większą podejrzliwością podczas generowania alertów. W przynętach phishingowych często można je pomylić z nazwami plików; połącz sygnał TLD ze słowami kluczowymi marki i wiekiem NRD, aby zwiększyć precyzję.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Przejęcie ruchu do windows.com firmy Microsoft przez odwrócenie bitów](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Dogłębne omówienie: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Dokumentacja mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Zbiór danych właściwości internetowych platformy](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – dokumentacja Search API](https://urlscan.io/docs/search/)
- [9] [Pomoc dotycząca protokołu dostępu do danych rejestracyjnych](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: odpowiedzi JSON dla protokołu dostępu do danych rejestracyjnych](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Taktyki związane z tokenami: jak zapobiegać kradzieży tokenów chmurowych, wykrywać ją i reagować na nią](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [Blog APNIC – fingerprinting sieciowe JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Wykrywanie phishingu: narzędzia i techniki](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – przedstawiamy CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
