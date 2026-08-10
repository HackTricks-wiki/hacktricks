# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy HackTricks i motion design autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchom HackTricks lokalnie
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
Lokalna kopia HackTricks będzie dostępna pod adresem [http://localhost:3337](http://localhost:3337) po upływie **<5 minut** (musi zbudować książkę, prosimy o cierpliwość).

Alternatywnie, jeśli masz Docker Compose, możesz po prostu uruchomić następujące polecenie z katalogu głównego repozytorium:
```bash
docker compose up
```
Ten proces wykorzystuje dołączony plik `docker-compose.yml` do udostępniania aktualnie wybranej na hoście gałęzi pod adresem [http://localhost:3337](http://localhost:3337) z funkcją live reload. Aby zmienić język podczas korzystania z Compose, wybierz żądaną gałąź językową przed uruchomieniem usługi.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber świadczy usługi penetration testing, audytów bezpieczeństwa, tworzenia exploitów i prowadzenia badań, dostarcza narzędzia oraz oferuje usługi zwiększające świadomość bezpieczeństwa. Na stronie opisano zespół penetration testerów, programistów i badaczy bezpieczeństwa z ponad dziesięcioletnim doświadczeniem.<sup>[[1]](#references)</sup>

Ich **blog** znajdziesz pod adresem [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** wspiera również projekty open source związane z cyberbezpieczeństwem, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti to dostawca usług bezpieczeństwa opartych na crowdsourcingu, oferujący bug bounty i penetration testing za pośrednictwem globalnej społeczności badaczy. Platforma łączy ciągłą obsługę bug bounty z dostępnymi na żądanie usługami PTaaS oraz zarządzanymi programami ujawniania podatności.<sup>[[2]](#references)</sup>

**Wskazówka dotycząca bug bounty**: Dołącz do Intigriti przez [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i poznaj ich programy bug bounty.

---

### [Modern Security – Platforma szkoleń z AI i bezpieczeństwa aplikacji](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje praktyczne szkolenia z bezpieczeństwa AI we własnym tempie, przeznaczone dla security engineerów, specjalistów AppSec i programistów. Certyfikacja AI Security obejmuje podstawy LLM i agentów, RAG i vector databases, modelowanie zagrożeń, prompt injection i ataki MCP oraz architekturę obronną.<sup>[[3]](#references)</sup>

👉 Więcej informacji o kursie AI Security:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** udostępnia API dla Google i innych wyszukiwarek, zwracające ustrukturyzowane dane SERP z funkcjami takimi jak wyniki zależne od lokalizacji, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/), wypróbuj przykład w ich [**playgroundzie**](https://serpapi.com/playground) lub [**utwórz bezpłatne konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Zaawansowane kursy z bezpieczeństwa urządzeń mobilnych i AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** oferuje kursy z bezpieczeństwa urządzeń mobilnych i AI we własnym tempie. Katalog obejmuje audytowanie i reverse engineering aplikacji mobilnych za pomocą narzędzi takich jak Ghidra, Frida i LLDB, a także laboratoria dotyczące ataków i obrony AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Przejrzyj [katalog kursów 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Skaner bezpieczeństwa oparty na AI](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** promuje platformę offensive-AI, która mapuje kod i infrastrukturę, a następnie wykorzystuje agentów statycznych i dynamicznych do znajdowania oraz weryfikowania możliwych do wykorzystania słabości, dostarczając dowody proof-of-concept i wskazówki dotyczące naprawy.<sup>[[7]](#references)</sup>

**Wskazówka dotycząca bezpieczeństwa kodu**: Poznaj Naxus do wykrywania podatności w kodzie i infrastrukturze.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec świadczy usługi penetration testing, subskrypcje bezpieczeństwa, staffing oraz ocenę podatności. Na stronie podano, że firma działa międzynarodowo i zajmuje się offensive security, defensive security oraz obszarem governance, risk and compliance.<sup>[[8]](#references)</sup>

Więcej informacji znajdziesz na ich [**stronie internetowej**](https://websec.net/en/) lub [**blogu**](https://websec.net/blog/).

Oprócz powyższego WebSec jest również **zaangażowanym sponsorem HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stworzone do pracy w terenie. Stworzone z myślą o Tobie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) oferuje prowadzone przez ekspertów szkolenia z cyberbezpieczeństwa, z niestandardowymi materiałami i laboratoriami opartymi na rzeczywistych infrastrukturach. Programy są dostosowane do potrzeb organizacji i obejmują cały proces — od oceny po wdrożenie.<sup>[[9]](#references)</sup> W sprawie indywidualnych szkoleń skontaktuj się [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Niestandardowe materiały i laboratoria
* Wsparcie najlepszych narzędzi i platform
* Projektowane i prowadzone przez praktyków

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions koncentruje się na doradztwie z zakresu cyberbezpieczeństwa dla sektorów **Education** i **FinTech**, obejmującym oceny cloud, wewnętrzne i zewnętrzne penetration tests, oceny podatności oraz wsparcie w zakresie compliance.<sup>[[10]](#references)</sup>

Bądź na bieżąco z najnowszymi informacjami dotyczącymi cyberbezpieczeństwa, odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - Inteligentniejszy GUI do zarządzania Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio to desktopowe IDE dla Kubernetes z wizualizacją CloudMaps, nawigacją między klastrami, RBAC, Helm, logami, widokami YAML i terminala. Dostawca twierdzi, że program łączy się przez kubeconfig bez instalowania agentów i obsługuje macOS, Windows, Linux oraz klastry air-gapped.<sup>[[11]](#references)</sup>

---

## Licencja i zastrzeżenie

Zobacz wpis HackTricks Values & FAQ w sekcji References poniżej.

## Statystyki Github

![Statystyki Github HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certyfikacja AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktyczne bezpieczeństwo AI: ataki, obrona i zastosowania](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Polecenie Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Film promujący sponsoring WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursy Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Wartości HackTricks i FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
