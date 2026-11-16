# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_HackTricks-Logos und Motion Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks lokal ausführen

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

Deine lokale Kopie von HackTricks ist nach <5 Minuten **unter [http://localhost:3337](http://localhost:3337)** verfügbar (das Buch muss erst erstellt werden, hab also etwas Geduld).

Alternativ kannst du mit Docker Compose einfach Folgendes im Stammverzeichnis des Repositorys ausführen:

```bash
docker compose up
```

Dies verwendet die enthaltene `docker-compose.yml`, um den auf dem Host aktuell ausgecheckten Branch unter [http://localhost:3337](http://localhost:3337) mit Live-Reload bereitzustellen. Um bei der Verwendung von Compose die Sprache zu wechseln, wechsle vor dem Starten des Dienstes zum gewünschten Sprach-Branch.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bietet Penetrationstests, Sicherheitsaudits, Exploit- und Forschungsarbeiten, Tools sowie Services zur Sicherheitsbewusstseinsbildung. Auf der Website beschreibt das Unternehmen ein Team aus Penetrationstestern, Programmierern und Sicherheitsforschern mit mehr als zehn Jahren Erfahrung.<sup>[[1]](#references)</sup>

Hier findest du ihren **Blog**: [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** unterstützt außerdem Cybersecurity-Open-Source-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ist ein Crowdsourcing-Anbieter für Security, der über eine globale Researcher-Community Bug-Bounty- und Penetration-Testing-Services anbietet. Die Plattform kombiniert eine kontinuierliche Bug-Bounty-Abdeckung mit On-Demand-PTaaS und verwalteten Programmen zur Offenlegung von Schwachstellen.<sup>[[2]](#references)</sup>

**Bug-Bounty-Tipp**: Melde dich über [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei Intigriti an und erkunde die Bug-Bounty-Programme.

---

### [Modern Security – Trainingsplattform für KI- und Anwendungssicherheit](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet selbstgesteuerte, praxisorientierte KI-Sicherheitsschulungen für Security Engineers, AppSec-Fachleute und Entwickler. Die KI-Sicherheitszertifizierung behandelt Grundlagen zu LLMs und Agents, RAG und Vektordatenbanken, Threat Modeling, Prompt-Injection- und MCP-Angriffe sowie defensive Architekturen.<sup>[[3]](#references)</sup>

👉 Weitere Informationen zum KI-Sicherheitskurs:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet APIs für Google und andere Suchmaschinen, die strukturierte SERP-Daten mit Funktionen wie standortbezogenen Ergebnissen, Maps, Shopping und Knowledge-Graph-Ergebnissen zurückgeben.<sup>[[4]](#references)</sup>

Weitere Informationen findest du in ihrem [**Blog**](https://serpapi.com/blog/). Probiere ein Beispiel in ihrer [**Sandbox**](https://serpapi.com/playground) aus oder [**erstelle ein kostenloses Konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Umfassende Kurse zu Mobile- und KI-Sicherheit](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bietet selbstgesteuerte Kurse zu Mobile- und KI-Sicherheit. Das Kursangebot umfasst Audits und Reverse Engineering von mobilen Anwendungen mit Tools wie Ghidra, Frida und LLDB sowie Labs zu KI-/LLM-Angriffen und -Abwehr.<sup>[[5]](#references)[[6]](#references)</sup>

Sieh dir den [Kurskatalog von 8kSec Academy](https://academy.8ksec.io/) an.

---

### [NaxusAI – Autonome offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** ist eine KI-gestützte Plattform für offensive Security, die vollständige Scans externer Angriffsflächen, Audits mobiler Apps, Black-Box-Tests von Webanwendungen und Reviews von Quellcode durchführt. Die Agents validieren ausnutzbare Findings und liefern nachvollziehbare Nachweise, Proof-of-Concept-Exploits und umsetzbare Empfehlungen zur Behebung.<sup>[[7]](#references)</sup>

**Tipp für Sicherheitsaudits**: Verwende Naxus für vollständig autonome Audits externer Assets, mobiler Apps, Webanwendungen und Quellcode.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bietet Penetrationstests, Security-Abonnements, Personalvermittlung und Schwachstellenanalysen an. Laut Website ist das Unternehmen international tätig und deckt offensive Security, defensive Security sowie Governance, Risk und Compliance ab.<sup>[[8]](#references)</sup>

Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) oder im [**Blog**](https://websec.net/blog/).

Zusätzlich zu den oben genannten Angeboten ist WebSec ein **engagierter Unterstützer von HackTricks**.

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für den Einsatz entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bietet von Experten geleitete Cybersecurity-Schulungen mit speziell entwickelten Inhalten und Labs, die auf realen Infrastrukturen basieren. Die Programme sind auf die Anforderungen von Organisationen zugeschnitten und reichen von der Bewertung bis zur Implementierung.<sup>[[9]](#references)</sup> Für Anfragen zu maßgeschneiderten Schulungen kannst du dich [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) melden.

**Was ihre Schulungen auszeichnet:**
* Speziell entwickelte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entwickelt und durchgeführt

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions konzentriert sich auf Cybersecurity-Beratung für **Bildung** und **FinTech**, darunter Cloud-Assessments, interne und externe Penetrationstests, Schwachstellenanalysen und Unterstützung bei Compliance.<sup>[[10]](#references)</sup>

Bleib über die neuesten Entwicklungen in der Cybersecurity informiert und auf dem Laufenden, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

---

### [Beaki — Essen, das zu dir passt](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** ist ein personalisierter Lebensmittelscanner, Kalorienzähler und Ernährungstracker. Scanne Barcodes und Supermarktregale, fotografiere oder beschreibe Mahlzeiten und Restaurantmenüs und erhalte nachvollziehbare Bewertungen, die auf deine Ziele, Ernährung, Allergien und dein Gesundheitsprofil abgestimmt sind. Beaki erfasst außerdem Kalorien und Makronährstoffe und erstellt personalisierte Essenspläne mit Einkaufslisten.<sup>[[11]](#references)</sup>

[**Lade Beaki kostenlos herunter**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) für Android oder iPhone.

---

## Lizenz & Haftungsausschluss

Siehe den Eintrag „HackTricks Values & FAQ“ im Abschnitt „References“ unten.

## GitHub-Statistiken

![HackTricks-GitHub-Statistiken](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [KI-Sicherheitszertifizierung – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktische KI-Sicherheit: Angriffe, Abwehr und Anwendungen](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Intigriti-HackTricks-Empfehlungslink](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-Sponsoringvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber-Helmets-Kurse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks-Werte & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
