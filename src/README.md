# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy i projekt animacji HackTricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Twoja lokalna kopia HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po <5 minutach (musi zbudować książkę, proszę o cierpliwość).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cybersecurity, której slogan to **HACK THE UNHACKABLE**. Prowadzą własne badania i rozwijają własne narzędzia hackingowe, aby **oferować kilka wartościowych usług z zakresu bezpieczeństwa** takich jak pentesting, Red teams i training.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** również wspiera open source'owe projekty związane z cybersecurity, takie jak HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) to najważniejsze wydarzenie związane z cybersecurity w **Hiszpanii** i jedno z najistotniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest gorącym punktem spotkań dla profesjonalistów technologii i cybersecurity we wszystkich dyscyplinach.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **Europe's #1** ethical hacking and bug bounty platform.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać bounty do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby w prosty sposób budować i **automate workflows** zasilane przez najbardziej **zaawansowane** community tools na świecie.

Uzyskaj dostęp już dziś:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z topowymi hackerami już dziś!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Zdobądź perspektywę hackera na swoje web apps, sieć i chmurę**

**Znajdź i zgłoś krytyczne, eksploatowalne podatności z rzeczywistym wpływem na biznes.** Użyj naszych 20+ narzędzi niestandardowych, aby zmapować attack surface, znaleźć problemy bezpieczeństwa umożliwiające eskalację uprawnień i użyć zautomatyzowanych exploitów do zebrania niezbędnych dowodów, przekształcając swoją ciężką pracę w przekonujące raporty.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i proste API w czasie rzeczywistym do **dostępu do wyników wyszukiwarek**. Scrape'ują search engines, obsługują proxies, rozwiązują captche i parsują wszystkie bogate, zstrukturane dane za Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do scrapowania różnych search engines, w tym Google, Bing, Baidu, Yahoo, Yandex i więcej.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko scrape'uje organiczne wyniki**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, inline images i videos, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to m.in. **Apple, Shopify oraz GrubHub**.\
Po więcej informacji sprawdź ich [**blog**](https://serpapi.com/blog/)**,** lub wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naucz się technologii i umiejętności wymaganych do prowadzenia vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje mobilne i urządzenia. **Opanuj iOS i Android security** poprzez nasze kursy on-demand i **uzyskaj certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cybersecurity z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami, dostarczając **offensive-security services** z **nowoczesnym** podejściem.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **usługi all-in-one**, co oznacza, że robią wszystko; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i wiele więcej.

Kolejną fajną rzeczą o WebSec jest to, że w odróżnieniu od średniej w branży WebSec **bardzo wierzy w swoje umiejętności**, do tego stopnia, że **gwarantują najlepsze wyniki**, jak podają na swojej stronie "**If we can't hack it, You don't pay it!**". Po więcej info zajrzyj na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Dodatkowo WebSec jest również **zaangażowanym sponsorem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) to wyszukiwarka data breach (leak). \
Udostępniamy wyszukiwanie losowych stringów (jak google) we wszystkich typach data leaks —dużych i małych— nie tylko tych największych— na danych z wielu źródeł. \
Wyszukiwanie osób, wyszukiwanie AI, wyszukiwanie organizacji, API (OpenAPI) access, theHarvester integration, wszystkie funkcje, których potrzebuje pentester.\
**HackTricks nadal jest świetną platformą do nauki dla nas wszystkich i jesteśmy dumni, że ją sponsorujemy!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza efektywne szkolenia z zakresu cybersecurity prowadzone przez
ekspertów z branży. Ich programy wykraczają poza teorię, wyposażając zespoły w dogłębną
wiedzę i praktyczne umiejętności, używając niestandardowych środowisk odzwierciedlających realne
zagrożenia. W sprawach dotyczących dedykowanych szkoleń skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza wyspecjalizowane usługi cybersecurity dla instytucji z sektora **Edukacji** i **FinTech**, skupiając się na **penetration testing, cloud security assessments**, oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje profesjonalistów z certyfikatami **OSCP i CISSP**, wnosząc głęboką wiedzę techniczną i branżowe doświadczenie do
każdego zlecenia.

Wykraczamy poza automatyczne skany, oferując **manualne, intelligence-driven testing** dostosowane do
środowisk o wysokim ryzyku. Od zabezpieczania rekordów studentów po ochronę transakcji finansowych,
pomagamy organizacjom bronić tego, co najważniejsze.

_„A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami ze świata cybersecurity odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes efektywnie. Wykorzystaj nasze AI-driven insights, zaawansowany security framework oraz intuicyjne CloudMaps GUI, aby wizualizować swoje klastry, rozumieć ich stan i działać z pewnością.

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
