# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logo i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchom HackTricks lokalnie
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export LANG="master" # Leave master for english
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for HindiP
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Twoja lokalna kopia HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po mniej niż 5 minut (musi zbudować książkę, bądź cierpliwy).

## Sponsorzy korporacyjni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cyberbezpieczeństwem, której slogan to **HACK THE UNHACKABLE**. Prowadzą własne badania i rozwijają własne narzędzia do hackowania, aby **oferować wiele wartościowych usług związanych z cyberbezpieczeństwem** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source związane z cyberbezpieczeństwem, takie jak HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) to najważniejsze wydarzenie związane z cyberbezpieczeństwem w **Hiszpanii** i jedno z najistotniejszych w **Europie**. Z misją promowania wiedzy technicznej, ten kongres jest gorącym punktem spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa ze wszystkich dyscyplin.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to europejska platforma nr 1 w zakresie ethical hacking i **bug bounty platform.**

**Bug bounty tip**: **zarejestruj się** na **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać nagrody do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby łatwo budować i **automatyzować workflowy** napędzane przez najbardziej **zaawansowane** narzędzia społecznościowe na świecie.

Uzyskaj dostęp już dziś:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server, aby komunikować się z doświadczonymi hackerami i łowcami bug bounty!

- **Wglądy dotyczące hackingu:** Angażuj się w treści zgłębiające emocje i wyzwania hackingowe
- **Wiadomości o hackingu w czasie rzeczywistym:** Bądź na bieżąco z szybkim tempem świata hackingu dzięki wiadomościom i analizom w czasie rzeczywistym
- **Najnowsze ogłoszenia:** Informacje o najnowszych uruchamianych bug bounty i kluczowych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Zyskaj perspektywę hackera na swoje aplikacje webowe, sieć i chmurę**

**Znajdź i zgłoś krytyczne, eksploatowalne podatności mające realny wpływ na biznes.** Użyj naszych 20+ dedykowanych narzędzi do mapowania powierzchni ataku, znajdowania problemów bezpieczeństwa umożliwiających eskalację uprawnień oraz używania zautomatyzowanych exploitów do zebrania kluczowych dowodów, przekształcając twoją pracę w przekonujące raporty.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i proste API w czasie rzeczywistym do **dostępu do wyników wyszukiwarek**. Zeskrobują wyszukiwarki, obsługują proxy, rozwiązują captche i parsują wszystkie bogate, ustrukturyzowane dane za Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do zeskrobywania różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie ogranicza się jedynie do zeskrobywania wyników organicznych**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, osadzone obrazy i wideo, knowledge graphy oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** lub wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **założyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności niezbędne do prowadzenia researchu podatności, penetration testing i reverse engineeringu, aby chronić aplikacje mobilne i urządzenia. **Opanuj bezpieczeństwo iOS i Android** dzięki naszym kursom on‑demand i **uzyskaj certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma zajmująca się cyberbezpieczeństwem z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami, dostarczając **offensive-security services** z **nowoczesnym** podejściem.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **usługi all-in-one**, co oznacza, że robią wszystko: Pentesting, **Security** Audyty, szkolenia świadomościowe, kampanie phishingowe, Code Review, rozwój exploitów, outsourcing ekspertów ds. bezpieczeństwa i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej rynkowej, WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantują najlepsze wyniki jakościowe**, jak napisano na ich stronie "**If we can't hack it, You don't pay it!**". Po więcej informacji zajrzyj na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Ponadto WebSec jest również **zaangażowanym sponsorem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) to wyszukiwarka naruszeń danych (leak). \
Oferujemy wyszukiwanie losowych ciągów (jak google) we wszystkich rodzajach data leaks, dużych i małych -- nie tylko tych największych -- na danych z wielu źródeł. \
Wyszukiwanie osób, wyszukiwanie AI, wyszukiwanie organizacji, dostęp API (OpenAPI), integracja theHarvester, wszystkie funkcje, których potrzebuje pentester.\
**HackTricks wciąż pozostaje świetną platformą edukacyjną dla nas wszystkich i jesteśmy dumni, że ją sponsorujemy!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza efektywne szkolenia z cyberbezpieczeństwa budowane i prowadzone przez ekspertów z branży. Ich programy wykraczają poza teorię, wyposażając zespoły w dogłębną wiedzę i praktyczne umiejętności, korzystając z niestandardowych środowisk odzwierciedlających rzeczywiste zagrożenia. W sprawach szkoleń niestandardowych skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treść i laboratoria tworzone na zamówienie
* Wsparcie przez narzędzia i platformy najwyższej klasy
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza wyspecjalizowane usługi cyberbezpieczeństwa dla instytucji edukacyjnych i FinTech, z naciskiem na **penetration testing, oceny bezpieczeństwa chmury** oraz **przygotowanie do zgodności** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje profesjonalistów z certyfikatami **OSCP i CISSP**, dostarczając głęboką wiedzę techniczną i wgląd zgodny ze standardami branżowymi w każdym zaangażowaniu.

Wykraczamy poza automatyczne skany dzięki **ręcznym, opartym na wywiadzie testom**, dostosowanym do środowisk o wysokim ryzyku. Od zabezpieczania danych studentów po ochronę transakcji finansowych, pomagamy organizacjom chronić to, co najważniejsze.

_„Jako obrona wymaga znajomości ofensywy, dostarczamy bezpieczeństwo poprzez zrozumienie.”_

Bądź na bieżąco z najnowszymi informacjami z zakresu cyberbezpieczeństwa, odwiedzając ich [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i deweloperom zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes w efektywny sposób. Wykorzystaj nasze AI-driven wnioski, zaawansowany framework bezpieczeństwa i intuicyjne CloudMaps GUI, aby wizualizować swoje klastry, rozumieć ich stan i działać z pewnością.

Co więcej, K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i inne).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Sprawdź je w:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
