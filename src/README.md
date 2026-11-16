# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy i motion design HackTricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_.

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
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Twoja lokalna kopia HackTricks będzie **dostępna pod adresem [http://localhost:3337](http://localhost:3337)** za mniej niż 5 minut (książka musi się zbudować, więc uzbrój się w cierpliwość).

Jeśli masz Docker Compose, możesz też po prostu uruchomić poniższe polecenie z katalogu głównego repozytorium:

```bash
docker compose up
```

Ta konfiguracja używa dołączonego pliku `docker-compose.yml`, aby udostępniać aktualnie wybraną na hoście gałąź pod adresem [http://localhost:3337](http://localhost:3337) z automatycznym odświeżaniem. Aby zmienić język podczas korzystania z Compose, przed uruchomieniem usługi przełącz się na odpowiednią gałąź językową.

## Partnerzy HackTricks

---

## Przyjaciele HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber świadczy usługi pentestów, audytów bezpieczeństwa, tworzenia exploitów i prowadzenia badań, dostarcza narzędzia oraz prowadzi działania zwiększające świadomość bezpieczeństwa. Na stronie opisuje zespół pentesterów, programistów i badaczy bezpieczeństwa z ponad dziesięcioletnim doświadczeniem.<sup>[[1]](#references)</sup>

Odwiedź ich **blog**: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** wspiera również projekty open source z zakresu cyberbezpieczeństwa, takie jak HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti to dostawca usług crowdsourcingowych z zakresu bezpieczeństwa, oferujący bug bounty i pentesty za pośrednictwem globalnej społeczności badaczy. Platforma łączy stały zakres programów bug bounty z usługą PTaaS na żądanie oraz zarządzanymi programami ujawniania podatności.<sup>[[2]](#references)</sup>

**Wskazówka dotycząca bug bounty**: Dołącz do Intigriti przez [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) i poznaj ich programy bug bounty.

---

### [Modern Security – platforma szkoleń z bezpieczeństwa AI i aplikacji](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security oferuje szkolenia z bezpieczeństwa AI, które można realizować we własnym tempie i które obejmują praktyczne ćwiczenia. Są przeznaczone dla inżynierów bezpieczeństwa, specjalistów AppSec i programistów. Certyfikacja AI Security obejmuje podstawy LLM i agentów, RAG i wektorowe bazy danych, modelowanie zagrożeń, ataki prompt injection i MCP oraz architekturę obronną.<sup>[[3]](#references)</sup>

👉 Więcej informacji o kursie AI Security:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** udostępnia API dla Google i innych wyszukiwarek, zwracające uporządkowane dane SERP z funkcjami takimi jak wyniki zależne od lokalizacji, Maps, Shopping i Knowledge Graph.<sup>[[4]](#references)</sup>

Więcej informacji znajdziesz na ich [**blogu**](https://serpapi.com/blog/), wypróbuj przykład w ich [**środowisku testowym**](https://serpapi.com/playground) lub [**utwórz bezpłatne konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – zaawansowane kursy z bezpieczeństwa urządzeń mobilnych i AI](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** oferuje kursy z bezpieczeństwa urządzeń mobilnych i AI, które można realizować we własnym tempie. Program obejmuje audyt i analizę wsteczną aplikacji mobilnych przy użyciu narzędzi takich jak Ghidra, Frida i LLDB, a także laboratoria poświęcone atakom i obronie w obszarze AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Zapoznaj się z [katalogiem kursów 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – autonomiczne ofensywne bezpieczeństwo](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** to platforma ofensywnego bezpieczeństwa oparta na AI, służąca do kompleksowego skanowania zewnętrznej powierzchni ataku, audytów aplikacji mobilnych, testów black-box aplikacji webowych i przeglądów kodu źródłowego. Jej agenci weryfikują możliwe do wykorzystania podatności i przedstawiają możliwe do prześledzenia dowody, exploity proof of concept oraz konkretne zalecenia naprawcze.<sup>[[7]](#references)</sup>

**Wskazówka dotycząca audytu bezpieczeństwa**: Użyj Naxus do kompleksowych, autonomicznych audytów zasobów zewnętrznych, aplikacji mobilnych i webowych oraz kodu źródłowego.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec oferuje pentesty, subskrypcje usług bezpieczeństwa, usługi kadrowe i oceny podatności. Na stronie podaje, że działa na całym świecie i zajmuje się bezpieczeństwem ofensywnym i defensywnym oraz zarządzaniem, ryzykiem i zgodnością.<sup>[[8]](#references)</sup>

Więcej informacji znajdziesz na ich [**stronie internetowej**](https://websec.net/en/) lub [**blogu**](https://websec.net/blog/).

Oprócz powyższych działań WebSec jest również **zaangażowanym sponsorem HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Stworzone do pracy w terenie. Stworzone z myślą o Tobie.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) oferuje szkolenia z cyberbezpieczeństwa prowadzone przez ekspertów, z autorskimi materiałami i laboratoriami opartymi na rzeczywistej infrastrukturze. Programy są dostosowywane do potrzeb organizacji i obejmują zagadnienia od oceny po wdrożenie.<sup>[[9]](#references)</sup> W sprawie szkoleń dostosowanych do potrzeb skontaktuj się z nimi [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Autorskie materiały i laboratoria
* Wsparcie najlepszych narzędzi i platform
* Programy opracowane i prowadzone przez praktyków

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions koncentruje się na konsultingu z zakresu cyberbezpieczeństwa dla **edukacji** i **FinTech**, oferując m.in. ocenę bezpieczeństwa chmury, wewnętrzne i zewnętrzne pentesty, oceny podatności oraz wsparcie w zakresie zgodności.<sup>[[10]](#references)</sup>

Odwiedź nasz [**blog**](https://www.lasttowersolutions.com/blog), aby być na bieżąco z najnowszymi informacjami z zakresu cyberbezpieczeństwa.

---

### [K8Studio - inteligentniejszy GUI do zarządzania Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio to desktopowe IDE dla Kubernetes z wizualizacją CloudMaps, nawigacją po wielu klastrach, RBAC, Helm, logami, YAML i widokami terminala. Według producenta łączy się za pomocą kubeconfig bez instalowania agentów i obsługuje macOS, Windows, Linux oraz klastry odizolowane od sieci.<sup>[[11]](#references)</sup>

---

## Licencja i zastrzeżenia

Zobacz wpis HackTricks Values & FAQ w poniższych odnośnikach.

## Statystyki GitHub

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

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
- [14] [Film o sponsorowaniu WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Kursy Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Wartości HackTricks i FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
