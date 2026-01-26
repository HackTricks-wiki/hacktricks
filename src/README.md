# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loga i motion design Hacktricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **available at [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## Sponsorzy korporacyjni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cyberbezpieczeństwem, której slogan to **HACK THE UNHACKABLE**. Przeprowadzają własne badania i rozwijają własne hacking tools, aby **oferować kilka wartościowych usług z zakresu cyberbezpieczeństwa** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera także projekty open source związane z cyberbezpieczeństwem, takie jak HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) to najważniejsze wydarzenie z zakresu cyberbezpieczeństwa w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z misją **promowania wiedzy technicznej**, kongres ten stanowi gorący punkt spotkań dla profesjonalistów z dziedziny technologii i cyberbezpieczeństwa w każdej dyscyplinie.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **Europe's #1** platforma do ethical hacking i **bug bounty.**

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać bounties do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby łatwo budować i **automatyzować przepływy pracy** zasilane przez najbardziej **zaawansowane** narzędzia społecznościowe na świecie.

Uzyskaj dostęp już dziś:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackers i bug bounty hunters!

- **Hacking Insights:** Angażuj się w treści, które zgłębiają emocje i wyzwania związane z hackingiem
- **Real-Time Hack News:** Bądź na bieżąco ze szybko zmieniającym się światem hack poprzez wiadomości i analizy w czasie rzeczywistym
- **Latest Announcements:** Informuj się o najnowszych uruchamianych bug bounty i istotnych aktualizacjach platformy

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z top hackers już dziś!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje **praktyczne szkolenia z AI Security** z podejściem **engineering-first, hands-on lab**. Nasze kursy są tworzone dla security engineers, AppSec professionals i developerów, którzy chcą **budować, łamać i zabezpieczać realne aplikacje oparte na AI/LLM**.

Certyfikacja **AI Security Certification** skupia się na umiejętnościach z prawdziwego świata, w tym:
- Zabezpieczanie aplikacji zasilanych LLM i AI
- Threat modeling dla systemów AI
- Embeddings, bazy wektorowe i bezpieczeństwo RAG
- Ataki na LLM, scenariusze nadużyć i praktyczne obrony
- Wzorce bezpiecznego projektowania i aspekty wdrożeniowe

Wszystkie kursy są **on-demand**, **lab-driven** i zaprojektowane wokół **rzeczywistych kompromisów bezpieczeństwa**, nie tylko teorii.

👉 Więcej szczegółów o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i proste API w czasie rzeczywistym do **dostępu do wyników wyszukiwarek**. Skrapują wyszukiwarki, obsługują proxy, rozwiązują captchy i parsują wszystkie bogate strukturalne dane dla Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do skrapowania różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie ogranicza się do skrapowania wyników organicznych**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, inline images i filmy, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecnymi klientami SerpApi są **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** lub przetestuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności wymagane do przeprowadzania vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje mobilne i urządzenia. **Opanuj iOS i Android security** dzięki naszym kursom on-demand i **zdobądź certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma zajmująca się cyberbezpieczeństwem z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami, dostarczając **offensive-security services** z **nowoczesnym** podejściem.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **all-in-one security services**, co oznacza, że robią wszystko: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i wiele więcej.

Kolejną ciekawą rzeczą dotyczącą WebSec jest to, że w przeciwieństwie do średniej w branży WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantują najlepsze rezultaty**, jak napisano na ich stronie "**If we can't hack it, You don't pay it!**". Po więcej informacji zajrzyj na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Dodatkowo WebSec jest również **zaangażowanym sponsorem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza skuteczne szkolenia z cyberbezpieczeństwa prowadzone przez ekspertów z branży. Ich programy wykraczają poza teorię, dostarczając zespołom dogłębnego zrozumienia i praktycznych umiejętności, używając niestandardowych środowisk odzwierciedlających rzeczywiste zagrożenia. W przypadku zapytań o szkolenia szyte na miarę, skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Niestandardowa zawartość i laby
* Wsparcie topowych narzędzi i platform
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza wyspecjalizowane usługi cyberbezpieczeństwa dla instytucji z sektora **Edukacji** i **FinTech**, koncentrując się na **penetration testing, ocenach bezpieczeństwa chmury**, oraz **przygotowaniu do zgodności** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje specjalistów z certyfikatami **OSCP i CISSP**, wnosząc głęboką wiedzę techniczną i zgodność z normami branżowymi do każdego zlecenia.

Wykraczamy poza automatyczne skany dzięki **manualnemu, intelligence-driven testing** dostosowanemu do środowisk o wysokim ryzyku. Od zabezpieczania danych studentów po ochronę transakcji finansowych, pomagamy organizacjom bronić tego, co najważniejsze.

_„A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami o cyberbezpieczeństwie, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes efektywnie. Wykorzystaj nasze AI-driven insights, zaawansowany framework bezpieczeństwa i intuicyjne CloudMaps GUI, aby wizualizować swoje klastry, rozumieć ich stan i działać z pewnością.

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
