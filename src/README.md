# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy i motion design Hacktricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks will be **dostępna pod [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma z branży cybersecurity, której slogan brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i tworzą własne narzędzia hackingowe, aby **oferować kilka wartościowych usług cybersecurity**, takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również projekty open source z zakresu cybersecurity, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **#1 w Europie** platforma ethical hacking i **bug bounty.**

**Bug bounty tip**: **zarejestruj się** w **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas dziś na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i zacznij zarabiać bounty do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i bug bounty hunterami!

- **Hacking Insights:** Angażuj się w treści, które zgłębiają emocje i wyzwania związane z hackingiem
- **Real-Time Hack News:** Bądź na bieżąco z dynamicznym światem hackingowym dzięki wiadomościom i informacjom w czasie rzeczywistym
- **Latest Announcements:** Bądź poinformowany o najnowszych uruchamianych bug bounty i kluczowych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security dostarcza **praktyczne szkolenia z AI Security** z podejściem **engineering-first, hands-on lab**. Nasze kursy są stworzone dla security engineerów, profesjonalistów AppSec i developerów, którzy chcą **budować, łamać i zabezpieczać prawdziwe aplikacje oparte na AI/LLM**.

**AI Security Certification** koncentruje się na umiejętnościach z realnego świata, w tym:
- Zabezpieczanie aplikacji LLM i opartych na AI
- Threat modeling dla systemów AI
- Embeddings, bazy wektorowe i bezpieczeństwo RAG
- Ataki na LLM, scenariusze nadużyć i praktyczne mechanizmy obrony
- Bezpieczne wzorce projektowe i kwestie wdrożeniowe

Wszystkie kursy są **on-demand**, **lab-driven** i zaprojektowane wokół **realnych kompromisów bezpieczeństwa**, a nie tylko teorii.

👉 Więcej szczegółów o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe API w czasie rzeczywistym do **uzyskiwania wyników wyszukiwarek**. Pobierają dane z wyszukiwarek, obsługują proxy, rozwiązują captchas i parsują wszystkie bogate dane strukturalne za Ciebie.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do pobierania danych z różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie pobiera tylko wyników organicznych**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/)**,** albo wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności potrzebne do prowadzenia vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje mobilne i urządzenia. **Opanuj bezpieczeństwo iOS oraz Androida** dzięki naszym kursom on-demand i **uzyskaj certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** to platforma cybersecurity wspierana przez AI, służąca do znajdowania podatności, które można wykorzystać, zanim zrobią to atakujący.

**Code security tip**: zarejestruj się w NaxusAI, inteligentnej platformie monitorowania podatności stworzonej dla developerów i zespołów security! Dołącz do nas dziś i zacznij używać AI do **wykrywania, walidacji i naprawiania realnych zagrożeń bezpieczeństwa, zanim trafią do produkcji**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cybersecurity z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cybersecurity, oferując **offensive-security services** w **nowoczesnym** podejściu.

WebSec jest międzynarodową firmą security z biurami w Amsterdamie i Wyoming. Oferują **all-in-one security services**, co oznacza, że robią wszystko: Pentesting, **Security** Audits, szkolenia z Awareness, kampanie Phishing, Code Review, Exploit Development, outsourcing ekspertów Security i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej branżowej WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantuje najwyższą jakość wyników**; na ich stronie widnieje: "**If we can't hack it, You don't pay it!**". Więcej informacji znajdziesz na ich [**stronie**](https://websec.net/en/) i [**blogu**](https://websec.net/blog/)!

Poza powyższym WebSec jest również **zaangażowanym wspierającym HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) rozwija i dostarcza skuteczne szkolenia cybersecurity tworzone i prowadzone przez ekspertów branżowych. Ich programy wykraczają poza teorię, aby wyposażyć zespoły w głębokie zrozumienie i praktyczne umiejętności, wykorzystując niestandardowe środowiska odzwierciedlające realne zagrożenia. W sprawie szkoleń dostosowanych do potrzeb skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treści i laboratoria tworzone na zamówienie
* Wsparcie najlepszych narzędzi i platform
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza wyspecjalizowane usługi cybersecurity dla instytucji **Education** i **FinTech**, ze szczególnym naciskiem na **penetration testing, cloud security assessments** oraz **compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **certyfikowanych specjalistów OSCP i CISSP**, wnoszących głęboką wiedzę techniczną i standardowe dla branży doświadczenie do każdego zlecenia.

Wykraczamy poza automatyczne skany dzięki **ręcznym testom opartym na analizie i intelligence**, dostosowanym do środowisk o wysokiej stawce. Od zabezpieczania danych studentów po ochronę transakcji finansowych — pomagamy organizacjom bronić tego, co najważniejsze.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami z zakresu cybersecurity, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom efektywne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze insights oparte na AI, zaawansowany framework security i intuicyjny CloudMaps GUI, aby wizualizować klastry, rozumieć ich stan i działać pewnie.

Ponadto K8Studio jest **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

To jest tekst prezentujący darmową wiki cybersecurity: <b>Hacktricks Book </b>. Ucz się teraz za darmo wszelkich hackingowych trików!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Sprawdź je w:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
