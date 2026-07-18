# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy HackTricks i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchamianie HackTricks lokalnie
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Twoja lokalna kopia HackTricks będzie dostępna pod adresem **[http://localhost:3337](http://localhost:3337)** po upływie <5 minut (książka musi zostać zbudowana, więc zachowaj cierpliwość).

Jeśli masz Docker Compose, możesz też po prostu uruchomić poniższe polecenie z katalogu głównego repozytorium:
```bash
docker compose up
```
Używa dołączonego pliku `docker-compose.yml`, aby udostępnić aktualnie checkoutowaną na hoście branch pod adresem [http://localhost:3337](http://localhost:3337) z funkcją live reload. Aby zmienić język podczas korzystania z Compose, checkoutuj wybraną branch językową przed uruchomieniem serwisu.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cybersecurity, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i tworzą własne hacking tools, aby **oferować kilka wartościowych usług cybersecurity**, takich jak pentesting, Red teams i szkolenia.

Ich **blog** znajdziesz na stronie [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source związane z cybersecurity, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **nr 1 w Europie** etyczny hacking i **bug bounty platform.**

**Bug bounty tip**: **zarejestruj się** na **Intigriti**, premium **bug bounty platform stworzoną przez hackerów dla hackerów**! Dołącz do nas już dziś pod adresem [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i zacznij zdobywać bounty o wartości do **100 000 USD**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje **praktyczne szkolenia AI Security** oparte na podejściu **engineering-first i praktycznych laboratoriach**. Nasze kursy są przeznaczone dla security engineers, specjalistów AppSec i developerów, którzy chcą **tworzyć, łamać i zabezpieczać rzeczywiste aplikacje oparte na AI/LLM**.

Certyfikacja **AI Security Certification** koncentruje się na umiejętnościach praktycznych, w tym:
- Zabezpieczaniu aplikacji opartych na LLM i AI
- Threat modeling dla systemów AI
- Embeddings, vector databases i bezpieczeństwie RAG
- Atakach na LLM, scenariuszach nadużyć i praktycznych zabezpieczeniach
- Wzorcach bezpiecznego projektowania i kwestiach związanych z wdrażaniem

Wszystkie kursy są dostępne **na żądanie**, oparte na **laboratoriach** i zaprojektowane wokół **rzeczywistych kompromisów związanych z bezpieczeństwem**, a nie wyłącznie teorii.

👉 Więcej informacji o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe w użyciu API czasu rzeczywistego umożliwiające **dostęp do wyników wyszukiwarek**. SerpApi wykonuje scraping wyszukiwarek, obsługuje proxy, rozwiązuje captche i parsuje wszystkie ustrukturyzowane dane — zarówno standardowe, jak i rozszerzone.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do scrapingu różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców **SerpApi nie ogranicza się do scrapingu wyników organicznych**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to między innymi **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** albo wypróbuj przykład w ich [**playgroundzie**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** szkoli w zakresie offensive mobile i AI security, a zajęcia prowadzą aktywni researchers — ten sam zespół, który tworzy CVE writeups i prowadzi prelekcje na Black Hat, HITB i Zer0con. Kursy odbywają się we własnym tempie, bazują na laboratoriach wykorzystujących rzeczywiste cele i są uzupełnione praktyczną certyfikacją.

Oferta obejmuje dwie ścieżki:

**Mobile Security** – iOS i Android od warstwy aplikacji po niższe poziomy: reverse engineering z użyciem Ghidra i LLDB, ARM64 exploitation, kernel internals i nowoczesne mechanizmy zabezpieczające (PAC, MTE, SELinux), a także mechanizmy jailbreak i rootowania.

**AI Security** – dwa kompletne kursy obejmujące cały obszar. Practical AI Security wyjaśnia działanie LLM, pipeline'ów RAG, AI agents i MCP oraz sposoby ich atakowania i zabezpieczania. Advanced AI Security koncentruje się na praktycznej budowie i obejmuje red teaming systemów AI na dużą skalę z użyciem Garak i PyRIT, wykorzystywanie MCP servers, umieszczanie i wykrywanie model backdoors oraz fine-tuning attacks i defenses na Apple Silicon.

Kursy i certyfikacje:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma security oparta na AI, która pomaga znajdować exploitable vulnerabilities, zanim zrobią to attackerzy.

**Code security tip**: zarejestruj się w NaxusAI — inteligentnej platformie do monitorowania vulnerability, stworzonej dla developerów i security teams! Dołącz już dziś i zacznij używać AI do **wykrywania, walidowania i naprawiania rzeczywistych zagrożeń bezpieczeństwa, zanim trafią do produkcji**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cybersecurity z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cybersecurity, świadcząc **usługi offensive security** w **nowoczesny** sposób.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferuje **kompleksowe usługi security**, co oznacza, że zajmuje się wszystkim: pentestingiem, audytami **Security**, szkoleniami awareness, kampaniami phishingowymi, Code Review, Exploit Development, outsourcingiem Security Experts i wieloma innymi usługami.

Kolejną ciekawą cechą WebSec jest to, że w przeciwieństwie do średniej branżowej firma jest **bardzo pewna swoich umiejętności** — do tego stopnia, że **gwarantuje najwyższą jakość wyników**. Na jej stronie widnieje hasło: "**If we can't hack it, You don't pay it!**". Więcej informacji znajdziesz na ich [**stronie internetowej**](https://websec.net/en/) i [**blogu**](https://websec.net/blog/)!

Ponadto WebSec jest również **zaangażowanym sponsorem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stworzone do pracy w terenie. Stworzone z myślą o Tobie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) opracowuje i prowadzi skuteczne szkolenia cybersecurity tworzone i prowadzone przez ekspertów branżowych. Ich programy wykraczają poza teorię, zapewniając zespołom dogłębne zrozumienie i praktyczne umiejętności dzięki niestandardowym środowiskom odzwierciedlającym rzeczywiste zagrożenia. W sprawie szkoleń dedykowanych skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Niestandardowe treści i laboratoria
* Wsparcie najlepszych narzędzi i platform
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions świadczy wyspecjalizowane usługi cybersecurity dla instytucji z sektorów **Education** i **FinTech**, koncentrując się na **penetration testing, cloud security assessments** oraz **compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **certyfikowanych specjalistów OSCP i CISSP**, którzy zapewniają dogłębną wiedzę techniczną i zgodne ze standardami branżowymi podejście do każdego zlecenia.

Wykraczamy poza automatyczne skanowanie, oferując **manual testing oparty na analizie i informacji** oraz dostosowany do środowisk o wysokim poziomie ryzyka. Od zabezpieczania danych studentów po ochronę transakcji finansowych — pomagamy organizacjom chronić to, co najważniejsze.

_„Skuteczna obrona wymaga znajomości ataku; zapewniamy bezpieczeństwo poprzez zrozumienie.”_

Bądź na bieżąco z najnowszymi informacjami dotyczącymi cybersecurity, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia zespołom DevOps, DevSecOps i developerom skuteczne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze informacje oparte na AI, zaawansowany framework security i intuicyjny GUI CloudMaps do wizualizacji klastrów, zrozumienia ich stanu i podejmowania działań z pełnym przekonaniem.

Ponadto K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i innymi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licencja i zastrzeżenie

Zapoznaj się z nimi tutaj:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statystyki Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
