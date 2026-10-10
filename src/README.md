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

Deine lokale Kopie von HackTricks ist nach weniger als 5 Minuten unter **[http://localhost:3337](http://localhost:3337)** verfügbar (das Buch muss erst erstellt werden, hab also etwas Geduld).

Alternativ kannst du mit Docker Compose einfach Folgendes im Stammverzeichnis des Repos ausführen:

```bash
docker compose up
```

Diese Methode verwendet die mitgelieferte `docker-compose.yml`, um den aktuell auf dem Host ausgecheckten Branch unter [http://localhost:3337](http://localhost:3337) mit Live-Reload bereitzustellen. Wenn du Compose verwendest und die Sprache wechseln möchtest, checke vor dem Starten des Dienstes den gewünschten Sprach-Branch aus.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber bietet Penetrationstests, Sicherheitsaudits, Exploit- und Forschungsarbeit, Tools sowie Security-Awareness-Dienstleistungen an. Auf der Website wird ein Team aus Penetrationstestern, Programmierern und Sicherheitsforschern mit mehr als zehn Jahren Erfahrung beschrieben.<sup>[[1]](#references)</sup>

Den **Blog** findest du unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** unterstützt auch Cybersecurity-Open-Source-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti ist ein Crowdsourced-Sicherheitsanbieter, der über eine globale Researcher-Community Bug-Bounty- und Penetration-Testing-Dienstleistungen anbietet. Die Plattform kombiniert kontinuierliche Bug-Bounty-Abdeckung mit On-Demand-PTaaS und verwalteten Vulnerability-Disclosure-Programmen.<sup>[[2]](#references)</sup>

**Bug-Bounty-Tipp**: Melde dich über [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei Intigriti an und erkunde die Bug-Bounty-Programme.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet praxisorientierte AI-Sicherheitsschulungen im Selbststudium für Security Engineers, AppSec-Experten und Entwickler an. Die AI Security Certification behandelt die Grundlagen von LLMs und Agenten, RAG und Vector-Datenbanken, Threat Modeling, Prompt-Injection- und MCP-Angriffe sowie defensive Architektur.<sup>[[3]](#references)</sup>

👉 Weitere Informationen zum AI-Sicherheitskurs:  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet APIs für Google und andere Suchmaschinen und liefert strukturierte SERP-Daten mit Funktionen wie standortbezogenen Ergebnissen, Maps, Shopping und Knowledge-Graph-Ergebnissen.<sup>[[4]](#references)</sup>

Weitere Informationen findest du im [**Blog**](https://serpapi.com/blog/). Probiere ein Beispiel im [**Playground**](https://serpapi.com/playground) aus oder [**erstelle ein kostenloses Konto**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bietet Mobile- und AI-Sicherheitskurse im Selbststudium an. Das Angebot umfasst Audits und Reverse Engineering mobiler Anwendungen mit Tools wie Ghidra, Frida und LLDB sowie Labs zu AI/LLM-Angriffen und -Abwehr.<sup>[[5]](#references)[[6]](#references)</sup>

Sieh dir den [Kurskatalog der 8kSec Academy](https://academy.8ksec.io/) an.

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** vermarktet eine Offensive-AI-Plattform, die Code und Infrastruktur erfasst und anschließend statische und dynamische Agenten einsetzt, um ausnutzbare Schwachstellen mit Proof-of-Concept-Nachweisen und Empfehlungen zur Behebung zu finden und zu validieren.<sup>[[7]](#references)</sup>

**Code-Sicherheitstipp**: Entdecke Naxus zur Erkennung von Schwachstellen in Code und Infrastruktur.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec bietet Penetrationstests, Security-Abonnements, Personalvermittlung und Schwachstellenanalysen an. Laut Website ist das Unternehmen international tätig und deckt Offensive Security, Defensive Security sowie Governance, Risk und Compliance ab.<sup>[[8]](#references)</sup>

Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) oder im [**Blog**](https://websec.net/blog/).

Darüber hinaus ist WebSec ein **engagierter Unterstützer von HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="CyberHelmets-Logo"><figcaption></figcaption></figure>


**Für den Einsatz entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) bietet von Experten geleitete Cybersecurity-Schulungen mit eigens entwickelten Inhalten und Labs, die auf realen Infrastrukturen basieren. Die Programme sind auf die Anforderungen von Unternehmen zugeschnitten und reichen von der Bewertung bis zur Implementierung.<sup>[[9]](#references)</sup> Für Anfragen zu maßgeschneiderten Schulungen wende dich [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks) an das Team.

**Was diese Schulungen auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entwickelt und geleitet

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="Last-Tower-Logo"><figcaption></figcaption></figure>

Last Tower Solutions konzentriert sich auf Cybersecurity-Beratung für **Bildung** und **FinTech**, darunter Cloud-Assessments, interne und externe Penetrationstests, Schwachstellenanalysen und Compliance-Unterstützung.<sup>[[10]](#references)</sup>

Bleib über die neuesten Entwicklungen in der Cybersecurity informiert und auf dem Laufenden – besuche unseren [**Blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="K8Studio-Logo"><figcaption></figcaption></figure>

K8Studio ist eine Kubernetes-Desktop-IDE mit CloudMaps-Visualisierung, Multi-Cluster-Navigation, RBAC, Helm, Logs, YAML- und Terminalansichten. Laut Anbieter verbindet sich das Tool über kubeconfig, ohne Agents zu installieren, und unterstützt macOS, Windows, Linux sowie Air-Gapped-Cluster.<sup>[[11]](#references)</sup>

---

## Lizenz und Haftungsausschluss

Siehe den Eintrag „HackTricks Values & FAQ“ unter References weiter unten.

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
- [12] [Intigriti HackTricks referral](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [WebSec sponsorship video](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Cyber Helmets courses](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
