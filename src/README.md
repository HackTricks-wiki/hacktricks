# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-Logos und Motion Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Deine lokale Kopie von HackTricks ist nach <5 Minuten unter **[http://localhost:3337](http://localhost:3337)** verfügbar (das Buch muss erst erstellt werden, hab etwas Geduld).

Alternativ kannst du mit Docker Compose einfach Folgendes im Stammverzeichnis des Repos ausführen:

```bash
docker compose up
```

Dies verwendet die mitgelieferte `docker-compose.yml`, um den aktuell auf dem Host ausgecheckten Branch unter [http://localhost:3337](http://localhost:3337) mit Live-Reload bereitzustellen. Um bei Verwendung von Compose die Sprache zu ändern, wechsle vor dem Starten des Dienstes zum gewünschten Sprach-Branch.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bietet Penetrationstests, Sicherheitsaudits, Exploit- und Forschungsarbeit, Tools sowie Services zur Sensibilisierung für Sicherheit. Laut Website besteht das Team aus Penetrationstestern, Programmierern und Sicherheitsforschern mit mehr als zehn Jahren Erfahrung.<sup>[[1]](#references)</sup>

Den **Blog** findest du unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** unterstützt außerdem Cybersecurity-Open-Source-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ist ein Crowdsourced-Security-Anbieter, der über eine globale Researcher-Community Bug-Bounty- und Penetration-Testing-Services anbietet. Die Plattform verbindet eine kontinuierliche Bug-Bounty-Abdeckung mit bedarfsgesteuertem PTaaS und verwalteten Programmen zur Offenlegung von Schwachstellen.<sup>[[2]](#references)</sup>

**Bug-Bounty-Tipp**: Tritt Intigriti über [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und entdecke die Bug-Bounty-Programme.

---

### [Modern Security – KI- und Application-Security-Trainingsplattform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet selbstgesteuerte, praxisorientierte KI-Sicherheitsschulungen für Security Engineers, AppSec-Experten und Entwickler. Die KI-Sicherheitszertifizierung behandelt die Grundlagen von LLMs und Agents, RAG und Vektordatenbanken, Threat Modeling, Prompt-Injection- und MCP-Angriffe sowie defensive Architektur.<sup>[[3]](#references)</sup>

👉 Weitere Informationen zum KI-Sicherheitskurs:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet APIs für Google und andere Suchmaschinen und liefert strukturierte SERP-Daten mit Funktionen wie standortbezogenen Ergebnissen, Maps, Shopping und Knowledge-Graph-Ergebnissen.<sup>[[4]](#references)</sup>

Weitere Informationen findest du im [**Blog**](https://serpapi.com/blog/). Probiere ein Beispiel im [**Playground**](https://serpapi.com/playground) aus oder [**erstelle ein kostenloses Konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Umfassende Kurse zu Mobile- und KI-Sicherheit](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Die **8kSec Academy** bietet selbstgesteuerte Kurse zu Mobile- und KI-Sicherheit. Das Kursangebot umfasst Audits und Reverse Engineering von Mobile-Apps mit Tools wie Ghidra, Frida und LLDB sowie KI/LLM-Angriffs- und Verteidigungslabs.<sup>[[5]](#references)[[6]](#references)</sup>

Durchstöbere den [Kurskatalog der 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Autonome Offensive Security](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** ist eine KI-gestützte Offensive-Security-Plattform für umfassende Scans externer Angriffsflächen, Audits von Mobile-Apps, Web-Black-Box-Tests und Source-Code-Reviews. Die Agents validieren ausnutzbare Befunde und liefern nachvollziehbare Belege, Proof-of-Concept-Exploits und konkrete Maßnahmen zur Behebung.<sup>[[7]](#references)</sup>

**Tipp für Sicherheitsaudits**: Nutze Naxus für autonome Audits von Anfang bis Ende – für externe Assets, Mobile-Apps, Web-Apps und Source Code.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bietet Penetrationstests, Sicherheitsabonnements, Personalvermittlung und Schwachstellenanalysen. Laut Website ist das Unternehmen international tätig und deckt Offensive Security, Defensive Security sowie Governance, Risk und Compliance ab.<sup>[[8]](#references)</sup>

Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) oder im [**Blog**](https://websec.net/blog/).

Zusätzlich zu den oben genannten Leistungen ist WebSec ein **engagierter Unterstützer von HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für den Einsatz entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bietet von Experten geleitete Cybersecurity-Schulungen mit maßgeschneiderten Inhalten und Labs, die auf realen Infrastrukturen basieren. Die Programme werden auf die Anforderungen der Organisation zugeschnitten und reichen von der Bewertung bis zur Implementierung.<sup>[[9]](#references)</sup> Für Anfragen zu individuellen Schulungen wende dich [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) an das Team.

**Das zeichnet die Schulungen aus:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entwickelt und geleitet

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions konzentriert sich auf Cybersecurity-Beratung für **Bildung** und **FinTech**, darunter Cloud-Assessments, interne und externe Penetrationstests, Schwachstellenanalysen und Unterstützung bei der Compliance.<sup>[[10]](#references)</sup>

Bleib auf dem neuesten Stand der Cybersecurity und besuche unseren [**Blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio – Die intelligentere GUI zur Verwaltung von Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ist eine Kubernetes-Desktop-IDE mit CloudMaps-Visualisierung, Navigation über mehrere Cluster, RBAC, Helm, Logs sowie YAML- und Terminalansichten. Laut Anbieter erfolgt die Verbindung über kubeconfig, ohne Agents zu installieren. Unterstützt werden macOS, Windows, Linux und isolierte Cluster ohne Netzwerkverbindung.<sup>[[11]](#references)</sup>

---

## Lizenz & Haftungsausschluss

Siehe den Eintrag „HackTricks Values & FAQ“ in den folgenden Referenzen.

## GitHub-Statistiken

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [KI-Sicherheitszertifizierung – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktische KI-Sicherheit: Angriffe, Abwehrmaßnahmen und Anwendungen](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti-HackTricks-Empfehlungslink](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-Sponsoringvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber-Helmets-Kurse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks-Werte & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
