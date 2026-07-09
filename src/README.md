# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Loga HackTricks i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Twoja lokalna kopia HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po <5 minutach (musisz poczekać, aż książka się zbuduje).

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma z branży cyberbezpieczeństwa, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i tworzą własne narzędzia hackingowe, aby **oferować kilka wartościowych usług z zakresu cyberbezpieczeństwa** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** pod adresem [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera także projekty open source z obszaru cyberbezpieczeństwa, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **najlepsza w Europie platforma** ethical hacking i **bug bounty.**

**Wskazówka bug bounty**: **zarejestruj się** w **Intigriti**, premium **bug bounty platform stworzonej przez hackerów, dla hackerów**! Dołącz do nas już dziś na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i zacznij zarabiać nagrody do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security dostarcza **praktyczne szkolenia z AI Security** z podejściem **engineering-first, hands-on lab**. Nasze kursy są tworzone dla inżynierów bezpieczeństwa, specjalistów AppSec i developerów, którzy chcą **budować, łamać i zabezpieczać rzeczywiste aplikacje oparte na AI/LLM**.

**AI Security Certification** koncentruje się na praktycznych umiejętnościach, w tym:
- Zabezpieczaniu aplikacji opartych na LLM i AI
- Threat modeling dla systemów AI
- Embeddings, vector databases i bezpieczeństwie RAG
- atakach na LLM, scenariuszach nadużyć i praktycznych zabezpieczeniach
- bezpiecznych wzorcach projektowych i kwestiach wdrożeniowych

Wszystkie kursy są **on-demand**, **lab-driven** i zaprojektowane wokół **rzeczywistych kompromisów bezpieczeństwa**, a nie tylko teorii.

👉 Więcej informacji o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe, działające w czasie rzeczywistym API do **uzyskiwania wyników wyszukiwarek**. Przeglądają wyszukiwarki, obsługują proxy, rozwiązują captchas i analizują wszystkie bogate dane strukturalne za Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do scrapowania różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko scrapuje wyniki organiczne**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** albo przetestuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** szkoli z ofensywnego mobile i AI security, a zajęcia prowadzą aktywni badacze – ten sam zespół stoi za opisami CVE i wystąpieniami na Black Hat, HITB i Zer0con. Kursy są samodzielne w realizacji, oparte na laboratoriach na prawdziwych celach i wspierane certyfikacją praktyczną.

Katalog obejmuje dwa tory:

**Mobile Security** – iOS i Android od warstwy aplikacji w dół: reverse engineering z Ghidra i LLDB, exploitation ARM64, wnętrze kernela i nowoczesne mitigations (PAC, MTE, SELinux), mechanizmy jailbreak i rooting.

**AI Security** – dwa pełne kursy obejmujące cały obszar. Practical AI Security wyjaśnia, jak działają LLMs, RAG pipelines, AI agents i MCP oraz jak je atakować i bronić. Advanced AI Security stawia na praktykę na granicy możliwości: red teaming systemów AI na dużą skalę z Garak i PyRIT, atakowanie serwerów MCP, umieszczanie i wykrywanie backdoorów w modelach oraz ataki i zabezpieczenia fine-tuningu na Apple Silicon.

Kursy i certyfikacje:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma bezpieczeństwa oparta na AI, służąca do znajdowania podatności, zanim zrobią to atakujący.

**Wskazówka code security**: zarejestruj się w NaxusAI, inteligentnej platformie do monitorowania podatności stworzonej dla developerów i zespołów bezpieczeństwa! Dołącz do nas już dziś i zacznij używać AI do **wykrywania, weryfikowania i naprawiania rzeczywistych ryzyk bezpieczeństwa, zanim trafią do produkcji**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma z branży cyberbezpieczeństwa z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cyberbezpieczeństwa, dostarczając **offensive-security services** w **nowoczesnym** podejściu.

WebSec jest międzynarodową firmą security z biurami w Amsterdamie i Wyoming. Oferują **kompleksowe usługi bezpieczeństwa**, co oznacza, że robią wszystko; Pentesting, audyty **Security**, szkolenia świadomościowe, kampanie phishingowe, code review, exploit development, outsourcing ekspertów security i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej branżowej WebSec jest **bardzo pewne swoich umiejętności**, do tego stopnia, że **gwarantują najlepszą jakość wyników**; na ich stronie widnieje: "**If we can't hack it, You don't pay it!**". Po więcej informacji zajrzyj na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Oprócz powyższego WebSec jest również **zaangażowanym wspierającym HackTricks**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza skuteczne szkolenia z cyberbezpieczeństwa, budowane i prowadzone przez ekspertów branżowych. Ich programy wykraczają poza teorię, aby wyposażyć zespoły w głębokie zrozumienie i praktyczne umiejętności, wykorzystując niestandardowe środowiska odzwierciedlające realne zagrożenia. W sprawie szkoleń szytych na miarę skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treści i laboratoria tworzone na zamówienie
* Wspierane przez narzędzia i platformy najwyższej klasy
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions świadczy wyspecjalizowane usługi cyberbezpieczeństwa dla instytucji **edukacyjnych** i **FinTech**, ze szczególnym naciskiem na **penetration testing, cloud security assessments** oraz **compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje certyfikowanych specjalistów **OSCP i CISSP**, wnoszących głęboką wiedzę techniczną i branżowy poziom ekspertyzy do każdego zlecenia.

Wykraczamy poza automatyczne skany dzięki **ręcznym, opartym na wywiadzie testom** dostosowanym do środowisk o wysokiej stawce. Od zabezpieczania danych studentów po ochronę transakcji finansowych pomagamy organizacjom bronić tego, co najważniejsze.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami z cyberbezpieczeństwa, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom wydajne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze analizy oparte na AI, zaawansowany framework bezpieczeństwa i intuicyjny GUI CloudMaps, aby wizualizować klastry, rozumieć ich stan i działać z pewnością.

Ponadto K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i inne).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licencja i zastrzeżenie

Sprawdź je w:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statystyki Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
