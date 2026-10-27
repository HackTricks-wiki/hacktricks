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

Deine lokale Kopie von HackTricks ist nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) **verfügbar** (das Buch muss erst erstellt werden; bitte hab Geduld).

Alternativ kannst du, wenn du Docker Compose hast, einfach Folgendes im Stammverzeichnis des Repos ausführen:

```bash
docker compose up
```

Dies verwendet die mitgelieferte `docker-compose.yml`, um den auf dem Host aktuell ausgecheckten Branch mit Live-Reload unter [http://localhost:3337](http://localhost:3337) bereitzustellen. Um bei Verwendung von Compose die Sprache zu wechseln, checke vor dem Starten des Dienstes den gewünschten Sprach-Branch aus.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bietet Penetrationstests, Sicherheitsaudits, Exploit- und Forschungsarbeiten, Tools sowie Security-Awareness-Dienstleistungen an. Laut eigener Website besteht das Team aus Penetrationstestern, Programmierern und Sicherheitsforschern mit mehr als einem Jahrzehnt Erfahrung.<sup>[[1]](#references)</sup>

Den **Blog** findest du unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** unterstützt außerdem Open-Source-Cybersicherheitsprojekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ist ein Crowdsourcing-Anbieter für Sicherheit, der über eine globale Researcher-Community Bug-Bounty- und Penetrationstest-Dienstleistungen anbietet. Die Plattform verbindet kontinuierliche Bug-Bounty-Abdeckung mit On-Demand-PTaaS und verwalteten Vulnerability-Disclosure-Programmen.<sup>[[2]](#references)</sup>

**Bug-Bounty-Tipp**: Melde dich über [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei Intigriti an und entdecke die Bug-Bounty-Programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet praxisorientierte AI-Sicherheitsschulungen im Selbststudium für Security Engineers, AppSec-Fachkräfte und Entwickler. Die AI Security Certification behandelt die Grundlagen von LLMs und Agents, RAG und Vektordatenbanken, Threat Modeling, Prompt-Injection- und MCP-Angriffe sowie defensive Architektur.<sup>[[3]](#references)</sup>

👉 Weitere Informationen zum AI-Security-Kurs:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet APIs für Google und andere Suchmaschinen, die strukturierte SERP-Daten mit Funktionen wie standortbezogenen Ergebnissen, Maps, Shopping und Knowledge-Graph-Ergebnissen liefern.<sup>[[4]](#references)</sup>

Weitere Informationen findest du im [**Blog**](https://serpapi.com/blog/). Probiere ein Beispiel im [**Playground**](https://serpapi.com/playground) aus oder [**erstelle ein kostenloses Konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Die **8kSec Academy** bietet Mobile- und AI-Security-Kurse im Selbststudium. Das Angebot umfasst Audits und Reversing von Mobile-Anwendungen mit Tools wie Ghidra, Frida und LLDB sowie AI/LLM-Angriff- und Verteidigungslabs.<sup>[[5]](#references)[[6]](#references)</sup>

Sieh dir den [Kurskatalog der 8kSec Academy](https://academy.8ksec.io/) an.

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** bewirbt eine offensive AI-Plattform, die Code und Infrastruktur erfasst und anschließend statische und dynamische Agents einsetzt, um ausnutzbare Schwachstellen mit Proof-of-Concept-Belegen und Hinweisen zur Behebung zu finden und zu validieren.<sup>[[7]](#references)</sup>

**Tipp zur Code-Sicherheit**: Entdecke Naxus zur Suche nach Schwachstellen in Code und Infrastruktur.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bietet Penetrationstests, Security-Abonnements, Personalvermittlung und Schwachstellenanalysen an. Laut eigener Website ist das Unternehmen international tätig und deckt Offensive Security, Defensive Security sowie Governance, Risk und Compliance ab.<sup>[[8]](#references)</sup>

Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) oder im [**Blog**](https://websec.net/blog/).

Zusätzlich zu den oben genannten Leistungen ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für den Praxiseinsatz entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bietet von Experten geleitete Cybersicherheitsschulungen mit individuell entwickelten Inhalten und Labs, die auf realen Infrastrukturen basieren. Die Programme sind auf die Anforderungen von Unternehmen zugeschnitten und reichen von der Bewertung bis zur Implementierung.<sup>[[9]](#references)</sup> Für Anfragen zu individuellen Schulungen wende dich [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) an das Team.

**Was diese Schulungen besonders macht:**
* Individuell entwickelte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entwickelt und unterrichtet

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions konzentriert sich auf Cybersicherheitsberatung für **Bildung** und **FinTech**. Dazu gehören Cloud-Assessments, interne und externe Penetrationstests, Schwachstellenanalysen und Unterstützung bei Compliance.<sup>[[10]](#references)</sup>

Bleib auf dem Laufenden über die neuesten Entwicklungen im Bereich Cybersicherheit und besuche unseren [**Blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio ist eine Kubernetes-IDE für den Desktop mit CloudMaps-Visualisierung, Navigation über mehrere Cluster hinweg sowie RBAC-, Helm-, Logs-, YAML- und Terminalansichten. Laut Anbieter verbindet sich K8Studio über kubeconfig, ohne Agents zu installieren, und unterstützt macOS, Windows, Linux sowie netzwerkisolierte Cluster.<sup>[[11]](#references)</sup>

---

## Lizenz & Haftungsausschluss

Siehe den Eintrag „HackTricks Values & FAQ“ im Abschnitt References weiter unten.

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
- [16] [HackTricks-Werte & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
