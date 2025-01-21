# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy i projektowanie ruchu Hacktricks autorstwa_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchom HackTricks lokalnie
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks
# Run the docker container indicating the path to the hacktricks folder
docker run --rm -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Twoja lokalna kopia HackTricks będzie **dostępna pod adresem [http://localhost:3337](http://localhost:3337)** po <5 minutach (musi zbudować książkę, bądź cierpliwy).

## Sponsorzy korporacyjni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cyberbezpieczeństwem, której hasło to **HACK THE UNHACKABLE**. Prowadzą własne badania i opracowują własne narzędzia hakerskie, aby **oferować szereg cennych usług w zakresie cyberbezpieczeństwa**, takich jak pentesting, zespoły Red i szkolenia.

Możesz sprawdzić ich **blog** pod adresem [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source w dziedzinie cyberbezpieczeństwa, takie jak HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **numer 1 w Europie** w zakresie etycznego hackingu i **platforma bug bounty.**

**Wskazówka dotycząca bug bounty**: **zarejestruj się** w **Intigriti**, premium **platformie bug bounty stworzonej przez hakerów, dla hackerów**! Dołącz do nas pod adresem [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **100 000 USD**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez **najbardziej zaawansowane** narzędzia społecznościowe na świecie.

Uzyskaj dostęp już dziś:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami bugów!

- **Wgląd w hacking:** Angażuj się w treści, które zagłębiają się w emocje i wyzwania związane z hackingiem
- **Aktualności o hackingu w czasie rzeczywistym:** Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i wglądom
- **Najnowsze ogłoszenia:** Bądź na bieżąco z najnowszymi nagrodami bug bounty i istotnymi aktualizacjami platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Niezbędne narzędzie do testów penetracyjnych

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Uzyskaj perspektywę hakera na swoje aplikacje internetowe, sieć i chmurę**

**Znajdź i zgłoś krytyczne, wykorzystywalne luki z rzeczywistym wpływem na biznes.** Użyj naszych 20+ niestandardowych narzędzi, aby zmapować powierzchnię ataku, znaleźć problemy z bezpieczeństwem, które pozwalają na eskalację uprawnień, i użyj zautomatyzowanych exploitów, aby zebrać niezbędne dowody, przekształcając swoją ciężką pracę w przekonujące raporty.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe API w czasie rzeczywistym do **uzyskiwania wyników wyszukiwania**. Zbierają dane z wyszukiwarek, obsługują proxy, rozwiązują captchy i analizują wszystkie bogate dane strukturalne za Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do zbierania danych z różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko zbiera organiczne wyniki**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, grafy wiedzy oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to **Apple, Shopify i GrubHub**.\
Aby uzyskać więcej informacji, sprawdź ich [**blog**](https://serpapi.com/blog/)**,** lub wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Szczegółowe kursy z zakresu bezpieczeństwa mobilnego](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności potrzebne do przeprowadzania badań nad lukami, testów penetracyjnych i inżynierii wstecznej, aby chronić aplikacje i urządzenia mobilne. **Opanuj bezpieczeństwo iOS i Android** dzięki naszym kursom na żądanie i **zdobądź certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.nl/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.nl) to profesjonalna firma zajmująca się cyberbezpieczeństwem z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami w dziedzinie cyberbezpieczeństwa, oferując **usługi ofensywne** z **nowoczesnym** podejściem.

WebSec to **wszystko w jednym** firma zajmująca się bezpieczeństwem, co oznacza, że robią wszystko; Pentesting, **Audyty** Bezpieczeństwa, Szkolenia w zakresie Świadomości, Kampanie Phishingowe, Przegląd Kodów, Rozwój Exploitów, Outsourcing Ekspertów ds. Bezpieczeństwa i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej w branży, WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantują najlepsze wyniki jakościowe**, jak stwierdzają na swojej stronie "**Jeśli nie możemy tego zhakować, nie płacisz!**". Aby uzyskać więcej informacji, zajrzyj na ich [**stronę**](https://websec.nl/en/) i [**blog**](https://websec.nl/blog/)!

Oprócz powyższego, WebSec jest również **zaangażowanym wsparciem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

## Licencja i zastrzeżenie

Sprawdź je w:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statystyki Github

![Statystyki Github HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
