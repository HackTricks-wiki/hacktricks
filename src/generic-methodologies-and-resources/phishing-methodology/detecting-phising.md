# Wykrywanie Phishingu

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

Aby wykryć próbę phishingu, ważne jest, aby **zrozumieć techniki phishingowe, które są obecnie stosowane**. Na stronie głównej tego wpisu można znaleźć te informacje, więc jeśli nie jesteś świadomy, które techniki są obecnie używane, zalecam przejście do strony głównej i przeczytanie przynajmniej tej sekcji.

Ten wpis opiera się na pomyśle, że **napastnicy będą próbowali w jakiś sposób naśladować lub używać nazwy domeny ofiary**. Jeśli Twoja domena nazywa się `example.com`, a Ty jesteś ofiarą phishingu przy użyciu zupełnie innej nazwy domeny, na przykład `youwonthelottery.com`, te techniki nie ujawnią tego.

## Wariacje nazw domen

Jest to dość **łatwe** do **ujawnienia** tych **prób phishingowych**, które będą używać **podobnej nazwy domeny** w e-mailu.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, które może użyć napastnik, i **sprawdzić**, czy są **zarejestrowane**, lub po prostu sprawdzić, czy jest jakiś **adres IP** używający tej nazwy.

### Znajdowanie podejrzanych domen

W tym celu możesz użyć dowolnego z następujących narzędzi. Zauważ, że te narzędzia automatycznie wykonają również zapytania DNS, aby sprawdzić, czy domena ma przypisany jakiś adres IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Możesz znaleźć krótkie wyjaśnienie tej techniki na stronie głównej. Lub przeczytać oryginalne badania w** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na przykład, modyfikacja 1 bitu w domenie microsoft.com może przekształcić ją w _windnws.com._\
**Napastnicy mogą rejestrować tak wiele domen związanych z bit-flipping, jak to możliwe, aby przekierować legalnych użytkowników do swojej infrastruktury**.

**Wszystkie możliwe nazwy domen związane z bit-flipping powinny być również monitorowane.**

### Podstawowe kontrole

Gdy masz listę potencjalnych podejrzanych nazw domen, powinieneś je **sprawdzić** (głównie porty HTTP i HTTPS), aby **zobaczyć, czy używają jakiegoś formularza logowania podobnego** do któregoś z domen ofiary.\
Możesz również sprawdzić port 3333, aby zobaczyć, czy jest otwarty i działa instancja `gophish`.\
Interesujące jest również wiedzieć, **jak stara jest każda odkryta podejrzana domena**, im młodsza, tym bardziej ryzykowna.\
Możesz również uzyskać **zrzuty ekranu** podejrzanej strony HTTP i/lub HTTPS, aby zobaczyć, czy jest podejrzana, a w takim przypadku **uzyskać dostęp, aby przyjrzeć się bliżej**.

### Zaawansowane kontrole

Jeśli chcesz pójść o krok dalej, zalecałbym **monitorowanie tych podejrzanych domen i co jakiś czas szukać więcej** (codziennie? to zajmuje tylko kilka sekund/minut). Powinieneś również **sprawdzić** otwarte **porty** powiązanych adresów IP i **szukać instancji `gophish` lub podobnych narzędzi** (tak, napastnicy również popełniają błędy) oraz **monitorować strony HTTP i HTTPS podejrzanych domen i subdomen**, aby zobaczyć, czy skopiowały jakikolwiek formularz logowania z stron ofiary.\
Aby **zautomatyzować to**, zalecałbym posiadanie listy formularzy logowania domen ofiary, przeszukiwanie podejrzanych stron internetowych i porównywanie każdego formularza logowania znalezionego w podejrzanych domenach z każdym formularzem logowania domeny ofiary przy użyciu czegoś takiego jak `ssdeep`.\
Jeśli zlokalizowałeś formularze logowania podejrzanych domen, możesz spróbować **wysłać fałszywe dane logowania** i **sprawdzić, czy przekierowuje Cię do domeny ofiary**.

## Nazwy domen używające słów kluczowych

Strona główna wspomina również o technice wariacji nazw domen, która polega na umieszczaniu **nazwy domeny ofiary w większej domenie** (np. paypal-financial.com dla paypal.com).

### Przejrzystość certyfikatów

Nie jest możliwe zastosowanie wcześniejszego podejścia "Brute-Force", ale w rzeczywistości **możliwe jest ujawnienie takich prób phishingowych** również dzięki przejrzystości certyfikatów. Za każdym razem, gdy certyfikat jest wydawany przez CA, szczegóły są publikowane. Oznacza to, że czytając przejrzystość certyfikatów lub nawet ją monitorując, **możliwe jest znalezienie domen, które używają słowa kluczowego w swojej nazwie**. Na przykład, jeśli napastnik generuje certyfikat dla [https://paypal-financial.com](https://paypal-financial.com), przeglądając certyfikat, można znaleźć słowo kluczowe "paypal" i wiedzieć, że podejrzany e-mail jest używany.

Wpis [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeruje, że możesz użyć Censys do wyszukiwania certyfikatów dotyczących konkretnego słowa kluczowego i filtrować według daty (tylko "nowe" certyfikaty) oraz według wydawcy CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Jednak możesz zrobić "to samo" używając darmowej strony [**crt.sh**](https://crt.sh). Możesz **wyszukiwać słowo kluczowe** i **filtrować** wyniki **według daty i CA**, jeśli chcesz.

![](<../../images/image (519).png>)

Korzystając z tej ostatniej opcji, możesz nawet użyć pola Matching Identities, aby sprawdzić, czy jakakolwiek tożsamość z prawdziwej domeny pasuje do którejkolwiek z podejrzanych domen (zauważ, że podejrzana domena może być fałszywym pozytywem).

**Inną alternatywą** jest fantastyczny projekt o nazwie [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream zapewnia strumień na żywo nowo wygenerowanych certyfikatów, który możesz wykorzystać do wykrywania określonych słów kluczowych w (prawie) czasie rzeczywistym. W rzeczywistości istnieje projekt o nazwie [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), który robi dokładnie to.

### **Nowe domeny**

**Ostatnią alternatywą** jest zebranie listy **nowo zarejestrowanych domen** dla niektórych TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) oferuje taką usługę) i **sprawdzenie słów kluczowych w tych domenach**. Jednak długie domeny zazwyczaj używają jednej lub więcej subdomen, dlatego słowo kluczowe nie pojawi się w FLD i nie będziesz w stanie znaleźć subdomeny phishingowej.

{{#include ../../banners/hacktricks-training.md}}
