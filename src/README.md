# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo Hacktricks i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Twoja lokalna kopia HackTricks będzie **dostępna pod [http://localhost:3337](http://localhost:3337)** po <5 minutach (trzeba zbudować książkę, bądź cierpliwy).

## Sponsorzy korporacyjni

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma z branży cyberbezpieczeństwa, której motto brzmi **HACK THE UNHACKABLE**. Prowadzą własne badania i tworzą własne narzędzia hackingowe, aby **oferować kilka cennych usług cyberbezpieczeństwa** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera także projekty open source z zakresu cyberbezpieczeństwa, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **najlepsza w Europie platforma** ethical hacking i **bug bounty.**

**Wskazówka dotycząca bug bounty**: **zarejestruj się** w **Intigriti**, premium **bug bounty platform created by hackers, for hackers**! Dołącz do nas na [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) już dziś i zacznij zdobywać nagrody do **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i łowcami bug bounty!

- **Hacking Insights:** Angażuj się w treści, które zagłębiają się w emocje i wyzwania hacking
- **Real-Time Hack News:** Bądź na bieżąco z dynamicznym światem hacking dzięki wiadomościom i analizom w czasie rzeczywistym
- **Latest Announcements:** Bądź na bieżąco z najnowszymi uruchomieniami bug bounty i kluczowymi aktualizacjami platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij dziś współpracować z najlepszymi hackerami!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security dostarcza **praktyczne szkolenia z AI Security** w oparciu o **engineering-first, hands-on lab approach**. Nasze kursy są tworzone dla inżynierów bezpieczeństwa, specjalistów AppSec i developerów, którzy chcą **budować, łamać i zabezpieczać prawdziwe aplikacje oparte na AI/LLM**.

**AI Security Certification** koncentruje się na praktycznych umiejętnościach, w tym:
- Zabezpieczanie aplikacji opartych na LLM i AI
- Threat modeling dla systemów AI
- Embeddings, vector databases i bezpieczeństwo RAG
- Ataki na LLM, scenariusze nadużyć i praktyczne zabezpieczenia
- Bezpieczne wzorce projektowe i kwestie wdrożeniowe

Wszystkie kursy są **on-demand**, oparte na **labach** i zaprojektowane wokół **rzeczywistych kompromisów bezpieczeństwa**, a nie tylko teorii.

👉 Więcej szczegółów o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** oferuje szybkie i łatwe w użyciu API czasu rzeczywistego do **uzyskiwania wyników wyszukiwania**. Pobierają dane z wyszukiwarek, obsługują proxy, rozwiązują captchas i parsują za Ciebie wszystkie bogate dane strukturalne.

Subskrypcja jednego z planów SerpApi obejmuje dostęp do ponad 50 różnych API do pobierania danych z różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi nie tylko pobiera wyniki organiczne**. Odpowiedzi SerpApi konsekwentnie zawierają wszystkie reklamy, obrazy i filmy inline, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to **Apple, Shopify i GrubHub**.\
Więcej informacji znajdziesz na ich [**blog**](https://serpapi.com/blog/)**,** albo wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Poznaj technologie i umiejętności potrzebne do prowadzenia vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje i urządzenia mobilne. **Opanuj bezpieczeństwo iOS i Android** dzięki naszym kursom on-demand i **zdobądź certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cyberbezpieczeństwa z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami cyberbezpieczeństwa, świadcząc **usługi offensive-security** w **nowoczesnym** podejściu.

WebSec jest międzynarodową firmą bezpieczeństwa z biurami w Amsterdamie i Wyoming. Oferują **kompleksowe usługi bezpieczeństwa**, co oznacza, że robią wszystko; Pentesting, audyty **Security**, szkolenia Awareness, kampanie phishingowe, Code Review, Exploit Development, outsourcing ekspertów ds. bezpieczeństwa i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej w branży WebSec jest **bardzo pewne swoich umiejętności**, do tego stopnia, że **gwarantują najlepszą jakość wyników**; na ich stronie widnieje: "**If we can't hack it, You don't pay it!**". Więcej informacji znajdziesz na ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Oprócz powyższego WebSec jest także **zaangażowanym zwolennikiem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) opracowuje i dostarcza skuteczne szkolenia z cyberbezpieczeństwa tworzone i prowadzone przez ekspertów branżowych. Ich programy wykraczają poza teorię, aby wyposażyć zespoły w głębokie zrozumienie i praktyczne umiejętności, wykorzystując niestandardowe środowiska odzwierciedlające rzeczywiste zagrożenia. W sprawie szkoleń szytych na miarę skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Treści i laby tworzone na zamówienie
* Wspierane przez najwyższej klasy narzędzia i platformy
* Projektowane i prowadzone przez praktyków

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza specjalistyczne usługi cyberbezpieczeństwa dla instytucji **edukacyjnych** i **FinTech**, ze szczególnym naciskiem na **penetration testing, cloud security assessments** oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje **profesjonalistów certyfikowanych OSCP i CISSP**, wnoszących głęboką wiedzę techniczną i standardy branżowe do
każdego zlecenia.

Wykraczamy poza automatyczne skanowanie dzięki **manualnemu, opartemu na analizie wywiadowczej testowaniu**, dostosowanemu do środowisk o wysokiej stawce. Od zabezpieczania danych studentów po ochronę transakcji finansowych,
pomagamy organizacjom bronić tego, co najważniejsze.

_„Wysokiej jakości obrona wymaga znajomości ofensywy; zapewniamy bezpieczeństwo poprzez zrozumienie.”_

Bądź na bieżąco z najnowszymi informacjami o cyberbezpieczeństwie, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i developerom wydajne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze analizy oparte na AI, zaawansowany framework bezpieczeństwa i intuicyjny GUI CloudMaps, aby wizualizować swoje klastry, rozumieć ich stan i działać pewnie.

Ponadto K8Studio jest **kompatybilne ze wszystkimi głównymi dystrybucjami kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift i więcej).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Sprawdź je tutaj:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
