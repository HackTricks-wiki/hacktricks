# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo i animacje Hacktricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po <5 minutach (musisz zbudować book, bądź cierpliwy).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma cybersecurity, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i rozwijają własne hacking tools, aby **oferować kilka wartościowych usług cybersecurity**, takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** pod [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source z obszaru cybersecurity, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **Europe's #1** ethical hacking i **bug bounty platform.**

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zarabiać bounty do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i bug bounty hunterami!

- **Hacking Insights:** Treści poświęcone emocjom i wyzwaniom związanym z hackingiem
- **Real-Time Hack News:** Bądź na bieżąco z dynamicznym światem hacking poprzez newsy i insighty w czasie rzeczywistym
- **Latest Announcements:** Bądź poinformowany o najnowszych bug bounty startujących na platformie i kluczowych aktualizacjach

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security dostarcza **praktyczne szkolenia z AI Security** z **engineering-first, hands-on lab approach**. Nasze kursy są tworzone dla security engineerów, specjalistów AppSec i developerów, którzy chcą **budować, łamać i zabezpieczać realne aplikacje oparte o AI/LLM**.

**AI Security Certification** koncentruje się na umiejętnościach z realnego świata, w tym:
- Zabezpieczanie aplikacji opartych na LLM i AI
- Threat modeling dla systemów AI
- Embeddings, vector databases i bezpieczeństwo RAG
- Ataki na LLM, scenariusze nadużyć i praktyczne defenses
- Bezpieczne wzorce projektowe i kwestie wdrożeniowe

Wszystkie kursy są **on-demand**, **lab-driven** i oparte na **real-world security tradeoffs**, a nie tylko na teorii.

👉 Więcej szczegółów o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe real-time APIs do **access search engine results**. Scrape'ują search engines, obsługują proxies, rozwiązują captchas i parsują za Ciebie wszystkie rich structured data.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych APIs do scrape'owania różnych search engines, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko scrape'uje organic results**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie ads, inline images i videos, knowledge graphs oraz inne elementy i funkcje obecne w wynikach search results.

Obecnymi klientami SerpApi są **Apple, Shopify i GrubHub**.\
Po więcej informacji sprawdź ich [**blog**](https://serpapi.com/blog/)**,** albo wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności potrzebne do prowadzenia vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje mobilne i urządzenia. **Opanuj iOS i Android security** dzięki naszym kursom on-demand i **uzyskaj certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma cybersecurity wspierana przez AI, służąca do znajdowania exploitable vulnerabilities, zanim zrobią to attackerzy.

**Code security tip**: zarejestruj się w NaxusAI, inteligentnej platformie do monitorowania vulnerabilities stworzonej dla developerów i zespołów security! Dołącz do nas już dziś i zacznij używać AI do **wykrywania, walidowania i naprawiania real security risks zanim trafią do production**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cybersecurity z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cybersecurity, oferując **offensive-security services** z **nowoczesnym** podejściem.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **all-in-one security services**, co oznacza, że robią wszystko; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej branżowej WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantują najlepszą jakość rezultatów**; na ich stronie widnieje: "**If we can't hack it, You don't pay it!**". Więcej informacji znajdziesz na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Oprócz powyższego WebSec jest również **zaangażowanym supporterem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) tworzy i dostarcza skuteczne szkolenia cybersecurity tworzone i prowadzone przez
ekspertów branżowych. Ich programy wykraczają poza teorię, aby wyposażyć zespoły w głębokie
zrozumienie i praktyczne umiejętności, korzystając z niestandardowych środowisk odzwierciedlających real-world
threats. W sprawie szkoleń custom skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza specjalistyczne usługi cybersecurity dla instytucji **Education** i **FinTech**
, ze szczególnym naciskiem na **penetration testing, cloud security assessments** oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **OSCP i CISSP
certified professionals**, wnosząc głęboką ekspertyzę techniczną i branżowy wgląd do
każdego zlecenia.

Wykraczamy poza automatyczne skany dzięki **manual, intelligence-driven testing** dostosowanemu do
środowisk wysokiego ryzyka. Od zabezpieczania danych studentów po ochronę transakcji finansowych,
pomagamy organizacjom bronić tego, co najważniejsze.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami o cybersecurity, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom efektywne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze AI-driven insights, zaawansowany framework security i intuicyjny CloudMaps GUI, aby wizualizować klastry, rozumieć ich stan i działać pewnie.

Ponadto K8Studio jest **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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
