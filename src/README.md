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
Deine lokale Kopie von HackTricks wird nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) verfügbar sein (das Buch muss erstellt werden, bitte hab Geduld).

Alternativ kannst du, wenn du Docker Compose hast, einfach Folgendes aus dem Stammverzeichnis des Repositories ausführen:
```bash
docker compose up
```
Dies verwendet die enthaltene `docker-compose.yml`, um den aktuell auf dem Host ausgecheckten Branch unter [http://localhost:3337](http://localhost:3337) mit Live Reload bereitzustellen. Um bei Verwendung von Compose die Sprache zu ändern, checke vor dem Starten des Dienstes den gewünschten Sprach-Branch aus.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bietet Penetrationstests, Sicherheitsprüfungen, Exploit- und Forschungsarbeiten, Tools sowie Services zur Förderung des Sicherheitsbewusstseins an. Auf der Website wird ein Team aus Penetrationstestern, Programmierern und Sicherheitsforschern mit mehr als zehn Jahren Erfahrung beschrieben.<sup>[[1]](#references)</sup>

Du kannst ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen.

**STM Cyber** unterstützt außerdem Open-Source-Projekte im Bereich Cybersicherheit wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ist ein Anbieter für Crowdsourced Security, der über eine globale Community von Researchern Bug-Bounty- und Penetration-Testing-Services anbietet. Die Plattform kombiniert kontinuierliche Bug-Bounty-Abdeckung mit On-Demand-PTaaS und verwalteten Programmen zur Offenlegung von Schwachstellen.<sup>[[2]](#references)</sup>

**Bug-Bounty-Tipp**: Tritt Intigriti über [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und erkunde die Bug-Bounty-Programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet praxisnahe AI-Sicherheitsschulungen im Selbststudium für Security Engineers, AppSec-Experten und Entwickler an. Die AI Security Certification deckt LLM- und Agent-Grundlagen, RAG und Vector Databases, Threat Modeling, Prompt-Injection- und MCP-Angriffe sowie defensive Architekturen ab.<sup>[[3]](#references)</sup>

👉 Weitere Informationen zum AI-Sicherheitskurs:
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet APIs für Google und andere Suchmaschinen an und liefert strukturierte SERP-Daten mit Funktionen wie standortbezogenen Ergebnissen, Maps-, Shopping- und Knowledge-Graph-Ergebnissen.<sup>[[4]](#references)</sup>

Weitere Informationen findest du in ihrem [**Blog**](https://serpapi.com/blog/). Du kannst außerdem ein Beispiel in ihrem [**Playground**](https://serpapi.com/playground) ausprobieren oder [**ein kostenloses Konto erstellen**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bietet Mobile- und AI-Sicherheitskurse im Selbststudium an. Der Katalog umfasst Auditing und Reverse Engineering von Mobile-Anwendungen mit Tools wie Ghidra, Frida und LLDB sowie AI/LLM-Angriffs- und Abwehr-Labs.<sup>[[5]](#references)[[6]](#references)</sup>

Durchsuche den [Kurskatalog der 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** vermarktet eine offensive AI-Plattform, die Code und Infrastruktur abbildet und anschließend statische und dynamische Agents verwendet, um ausnutzbare Schwachstellen mit Proof-of-Concept-Nachweisen und Anleitungen zur Behebung zu finden und zu validieren.<sup>[[7]](#references)</sup>

**Tipp zur Codesicherheit**: Erkunde Naxus zur auf Code und Infrastruktur ausgerichteten Schwachstellenerkennung.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bietet Penetrationstests, Security-Subscriptions, Personalvermittlung und Services zur Schwachstellenbewertung an. Laut Website ist das Unternehmen international tätig und deckt offensive Security, defensive Security sowie Governance-, Risk- und Compliance-Arbeiten ab.<sup>[[8]](#references)</sup>

Weitere Informationen findest du auf ihrer [**Website**](https://websec.net/en/) oder in ihrem [**Blog**](https://websec.net/blog/).

Zusätzlich zu den oben genannten Leistungen ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für die Praxis entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bietet von Experten geleitete Cybersicherheitsschulungen mit individuell erstellten Inhalten und Labs, die auf realen Infrastrukturen basieren. Die Programme sind auf die Anforderungen von Organisationen zugeschnitten und reichen von der Bewertung bis zur Implementierung.<sup>[[9]](#references)</sup> Für Anfragen zu maßgeschneiderten Schulungen kannst du dich [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) melden.

**Was ihre Schulungen auszeichnet:**
* Individuell erstellte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entwickelt und unterrichtet

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions konzentriert sich auf Cybersicherheitsberatung für **Bildung** und **FinTech**, einschließlich Cloud-Bewertungen, interner und externer Penetrationstests, Schwachstellenbewertungen und Compliance-Unterstützung.<sup>[[10]](#references)</sup>

Bleibe informiert und auf dem neuesten Stand der Cybersicherheit, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ist eine Kubernetes-Desktop-IDE mit CloudMaps-Visualisierung, Multi-Cluster-Navigation, RBAC, Helm sowie Ansichten für Logs, YAML und Terminals. Laut Anbieter stellt die Software über kubeconfig eine Verbindung her, ohne Agents zu installieren, und unterstützt macOS, Windows, Linux sowie air-gapped Cluster.<sup>[[11]](#references)</sup>

---

## Lizenz und Haftungsausschluss

Siehe den Eintrag zu HackTricks Values & FAQ in den unten aufgeführten References.

## Github-Statistiken

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [AI-Sicherheitszertifizierung – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Praktische AI-Sicherheit: Angriffe, Abwehrmaßnahmen und Anwendungen](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Intigriti-HackTricks-Empfehlungslink](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec-Sponsoringvideo](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber-Helmets-Kurse](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
