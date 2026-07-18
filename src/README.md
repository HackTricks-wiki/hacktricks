# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy HackTricks i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchamianie HackTricks lokalnie
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
Twoja lokalna kopia HackTricks będzie dostępna pod adresem [http://localhost:3337](http://localhost:3337) po <5 minutach (książka musi się zbudować, uzbrój się w cierpliwość).

Alternatywnie, jeśli masz Docker Compose, możesz po prostu uruchomić poniższe polecenie z katalogu głównego repozytorium:
```bash
docker compose up
```
Ten plik wykorzystuje dołączony `docker-compose.yml`, aby udostępnić lokalny checkout pod adresem [http://localhost:3337](http://localhost:3337) z funkcją live reload.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma z branży cyberbezpieczeństwa, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzi własne badania i tworzy własne hacking tools, aby **oferować kilka wartościowych usług cyberbezpieczeństwa**, takich jak pentesting, Red teams i training.

Ich **blog** znajdziesz pod adresem [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source związane z cyberbezpieczeństwem, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **nr 1 w Europie** w zakresie etycznego hackingu i **platforma bug bounty.**

**Wskazówka dotycząca bug bounty**: **zarejestruj się** na **Intigriti**, premium **platformie bug bounty stworzonej przez hackerów dla hackerów**! Dołącz do nas już dziś pod adresem [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i zacznij zdobywać bounty o wartości do **100 000 $**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje **praktyczne szkolenia z AI Security** w oparciu o podejście **engineering-first i hands-on lab**. Nasze kursy są przeznaczone dla security engineerów, specjalistów AppSec i developerów, którzy chcą **tworzyć, łamać i zabezpieczać rzeczywiste aplikacje wykorzystujące AI/LLM**.

**Certyfikacja AI Security** koncentruje się na praktycznych umiejętnościach, w tym:
- Zabezpieczaniu aplikacji wykorzystujących LLM i AI
- Threat modeling systemów AI
- Embeddings, vector databases i bezpieczeństwie RAG
- Atakach na LLM, scenariuszach nadużyć i praktycznych zabezpieczeniach
- Bezpiecznych wzorcach projektowych i kwestiach związanych z wdrażaniem

Wszystkie kursy są dostępne **on-demand**, oparte na **labach** i zaprojektowane wokół **rzeczywistych kompromisów związanych z bezpieczeństwem**, a nie wyłącznie teorii.

👉 Więcej informacji o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe w użyciu API działające w czasie rzeczywistym, umożliwiające **dostęp do wyników wyszukiwarek**. SerpApi wykonuje scraping wyszukiwarek, obsługuje proxy, rozwiązuje captche i parsuje wszystkie bogate, ustrukturyzowane dane.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do scrapingu różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców **SerpApi nie wykonuje wyłącznie scrapingu wyników organicznych**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecnymi klientami SerpApi są między innymi **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** lub wypróbuj przykład w ich [**playgroundzie**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** szkoli w zakresie offensive mobile i AI security. Zajęcia prowadzą aktywni badacze – ten sam zespół, który tworzy CVE writeups i występuje na Black Hat, HITB oraz Zer0con. Kursy odbywają się we własnym tempie, bazują na labach z rzeczywistymi celami i są uzupełnione o certyfikację hands-on.

Katalog obejmuje dwie ścieżki:

**Mobile Security** – iOS i Android, od warstwy aplikacji w dół: reverse engineering z użyciem Ghidra i LLDB, ARM64 exploitation, mechanizmy wewnętrzne kernela i nowoczesne zabezpieczenia (PAC, MTE, SELinux), mechanizmy jailbreak i rootowania.

**AI Security** – dwa pełne kursy obejmujące cały obszar. Practical AI Security wyjaśnia działanie LLM, pipeline'ów RAG, agentów AI i MCP oraz sposoby ich atakowania i obrony. Advanced AI Security koncentruje się na praktycznej budowie rozwiązań na najnowszym poziomie: red teaming systemów AI na dużą skalę z użyciem Garak i PyRIT, wykorzystywaniu MCP servers, umieszczaniu i wykrywaniu model backdoors oraz fine-tuning attacks i defenses na Apple Silicon.

Kursy i certyfikacje:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma bezpieczeństwa oparta na AI, służąca do znajdowania podatności możliwych do wykorzystania, zanim zrobią to attackerzy.

**Wskazówka dotycząca bezpieczeństwa kodu**: zarejestruj się w NaxusAI, inteligentnej platformie do monitorowania podatności stworzonej dla developerów i zespołów security! Dołącz do nas już dziś i zacznij używać AI do **wykrywania, walidowania i naprawiania rzeczywistych zagrożeń bezpieczeństwa, zanim trafią na produkcję**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma z branży cyberbezpieczeństwa z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cyberbezpieczeństwa, oferując **usługi offensive security** w **nowoczesnym** wydaniu.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferuje **kompleksowe usługi security**, co oznacza, że zajmuje się wszystkim: Pentestingiem, audytami **Security**, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Outsourcingiem Security Experts i wieloma innymi obszarami.

Kolejną ciekawą rzeczą dotyczącą WebSec jest to, że w przeciwieństwie do średniej rynkowej firma jest **bardzo pewna swoich umiejętności**, do tego stopnia, że **gwarantuje najwyższą jakość wyników**. Na jej stronie widnieje hasło: "**If we can't hack it, You don't pay it!**". Więcej informacji znajdziesz na ich [**stronie**](https://websec.net/en/) i [**blogu**](https://websec.net/blog/)!

Oprócz powyższego WebSec jest również **zaangażowanym wspierającym HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stworzone do pracy w terenie. Stworzone z myślą o Tobie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i prowadzi skuteczne szkolenia z cyberbezpieczeństwa przygotowywane i prowadzone przez ekspertów
z branży. Ich programy wykraczają poza teorię, zapewniając zespołom dogłębną
wiedzę i praktyczne umiejętności dzięki niestandardowym środowiskom odzwierciedlającym rzeczywiste
zagrożenia. W sprawie szkoleń dopasowanych do potrzeb skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treści i laby tworzone na zamówienie
* Wspierane przez najlepsze narzędzia i platformy
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions świadczy wyspecjalizowane usługi cyberbezpieczeństwa dla instytucji z sektora **Education** i **FinTech**, koncentrując się na **penetration testing, cloud security assessments** oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **certyfikowanych specjalistów OSCP i CISSP**, zapewniających dogłębną wiedzę techniczną i zgodne ze standardami branżowymi doświadczenie podczas każdego zlecenia.

Wykraczamy poza automatyczne skany, oferując **manualne, oparte na analizie danych testy** dopasowane do środowisk o wysokim poziomie ryzyka. Od zabezpieczania danych studentów po ochronę transakcji finansowych pomagamy organizacjom chronić to, co najważniejsze.

_„Skuteczna obrona wymaga znajomości ataku — zapewniamy bezpieczeństwo poprzez zrozumienie.”_

Bądź na bieżąco z najnowszymi informacjami dotyczącymi cyberbezpieczeństwa, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia zespołom DevOps, DevSecOps i developerom efektywne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Korzystaj z naszych opartych na AI wskazówek, zaawansowanego security frameworka i intuicyjnego GUI CloudMaps, aby wizualizować klastry, rozumieć ich stan i działać z pełnym przekonaniem.

Ponadto K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i innymi).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licencja i zastrzeżenia

Sprawdź je tutaj:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statystyki Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
