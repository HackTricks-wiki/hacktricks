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
Twoja lokalna kopia HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po <5 minutach (trzeba zbudować książkę, proszę o cierpliwość).

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma z branży cyberbezpieczeństwa, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i rozwijają własne narzędzia hackingowe, aby **oferować kilka wartościowych usług z zakresu cyberbezpieczeństwa** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source z zakresu cyberbezpieczeństwa, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **numer 1 w Europie** w ethical hacking i **bug bounty platform.**

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać bounty do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i łowcami bug bounty!

- **Hacking Insights:** Angażuj się w treści, które zagłębiają się w dreszcz i wyzwania hacking
- **Real-Time Hack News:** Bądź na bieżąco z dynamicznym światem hacking dzięki wiadomościom i analizom w czasie rzeczywistym
- **Latest Announcements:** Bądź poinformowany o najnowszych startujących bug bounty oraz kluczowych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij dziś współpracować z najlepszymi hackerami!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security dostarcza **praktyczne szkolenia z AI Security** w oparciu o **engineering-first, hands-on lab approach**. Nasze kursy są tworzone dla security engineerów, profesjonalistów AppSec i developerów, którzy chcą **budować, łamać i zabezpieczać prawdziwe aplikacje oparte na AI/LLM**.

**AI Security Certification** koncentruje się na umiejętnościach z prawdziwego świata, w tym:
- Zabezpieczaniu aplikacji opartych na LLM i AI
- Threat modeling dla systemów AI
- Embeddings, vector databases i bezpieczeństwie RAG
- atakach na LLM, scenariuszach nadużyć i praktycznych metodach obrony
- bezpiecznych wzorcach projektowych i kwestiach wdrożeniowych

Wszystkie kursy są **on-demand**, **lab-driven** i projektowane wokół **real-world security tradeoffs**, a nie tylko teorii.

👉 Więcej szczegółów o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe w czasie rzeczywistym API do **uzyskiwania wyników wyszukiwarek**. Scrapują wyszukiwarki, obsługują proxy, rozwiązują captchas i parsują za Ciebie wszystkie bogate dane strukturalne.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do scrapowania różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko scrapuje organic results**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecnymi klientami SerpApi są **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blog**](https://serpapi.com/blog/)**,** albo wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** szkoli w ofensywnym mobile i AI security, prowadzonym przez aktywnych badaczy – ten sam zespół stoi za writeupami CVE i wystąpieniami na Black Hat, HITB i Zer0con. Kursy są w trybie self-paced, oparte na labach na prawdziwych celach i wspierane przez hands-on certification.

Katalog obejmuje dwa tory:

**Mobile Security** – iOS i Android od warstwy aplikacji w dół: reverse engineering z Ghidra i LLDB, exploity na ARM64, wnętrze kernela i nowoczesne mitigations (PAC, MTE, SELinux), mechanika jailbreak i rooting.

**AI Security** – dwa pełne kursy obejmujące całą dziedzinę. Practical AI Security pokazuje, jak działają LLMs, potoki RAG, AI agents i MCP oraz jak je atakować i bronić. Advanced AI Security idzie mocno w stronę build-heavy na granicy możliwości: red teaming systemów AI na dużą skalę z Garak i PyRIT, eksploitowanie serwerów MCP, umieszczanie i wykrywanie backdoors w modelach oraz ataki i obronę w fine-tuning na Apple Silicon.

Kursy i certyfikacje:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma bezpieczeństwa oparta na AI, służąca do znajdowania exploitable vulnerabilities, zanim zrobią to atakujący.

**Code security tip**: zarejestruj się w NaxusAI, inteligentnej platformie monitorowania vulnerabilities stworzonej dla developerów i zespołów security! Dołącz do nas już dziś i zacznij używać AI do **wykrywania, walidowania i naprawiania realnych ryzyk bezpieczeństwa, zanim trafią do production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cyberbezpieczeństwa z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cyberbezpieczeństwa, oferując **offensive-security services** w **nowoczesnym** podejściu.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **usługi bezpieczeństwa all-in-one**, co oznacza, że robią wszystko; Pentesting, audyty **Security**, szkolenia świadomościowe, kampanie phishingowe, Code Review, Exploit Development, outsourcing ekspertów Security i wiele więcej.

Kolejną świetną rzeczą w WebSec jest to, że w przeciwieństwie do średniej branżowej WebSec jest **bardzo pewne swoich umiejętności**, do tego stopnia, że **gwarantuje najlepszą jakość wyników**; na ich stronie jest napisane "**If we can't hack it, You don't pay it!**". Po więcej informacji zajrzyj na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Oprócz powyższego WebSec jest również **zaangażowanym supporterem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza skuteczne szkolenia z cyberbezpieczeństwa budowane i prowadzone przez ekspertów z branży. Ich programy wykraczają poza teorię, aby wyposażyć zespoły w głębokie zrozumienie i praktyczne umiejętności, wykorzystując niestandardowe środowiska odzwierciedlające realne zagrożenia. W sprawie szkoleń szytych na miarę skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treści i laby tworzone na zamówienie
* Wspierane przez narzędzia i platformy najwyższej klasy
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza specjalistyczne usługi cyberbezpieczeństwa dla instytucji z sektora **Education** i **FinTech**
, ze szczególnym naciskiem na **penetration testing, cloud security assessments** oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **OSCP i CISSP
certified professionals**, wnoszących głęboką wiedzę techniczną i branżowy wgląd do
każdego zlecenia.

Wykraczamy poza automatyczne skany dzięki **manual, intelligence-driven testing** dostosowanemu do
środowisk o wysokiej stawce. Od zabezpieczania danych studentów po ochronę transakcji finansowych,
pomagamy organizacjom bronić tego, co najważniejsze.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami z cyberbezpieczeństwa, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom efektywne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze analizy oparte na AI, zaawansowany framework bezpieczeństwa i intuicyjny GUI CloudMaps, aby wizualizować klastry, rozumieć ich stan i działać pewnie.

Ponadto K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i więcej).

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
