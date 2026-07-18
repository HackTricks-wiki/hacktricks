# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos und Motion Design von Hacktricks von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### HackTricks lokal ausführen
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
Deine lokale Kopie von HackTricks wird nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) verfügbar sein (das Buch muss erstellt werden, hab etwas Geduld).

Alternativ kannst du, wenn du Docker Compose hast, einfach Folgendes aus dem Stammverzeichnis des Repositories ausführen:
```bash
docker compose up
```
Dies verwendet die enthaltene `docker-compose.yml`, um deinen lokalen Checkout unter [http://localhost:3337](http://localhost:3337) mit Live Reload bereitzustellen.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen mit dem Slogan **HACK THE UNHACKABLE**. Das Unternehmen betreibt eigene Forschung und entwickelt eigene Hacking-Tools, um **mehrere wertvolle Cybersecurity-Services anzubieten**, darunter Pentesting, Red Teams und Training.

Du kannst ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen.

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **Nr. 1** für ethisches Hacking und eine **Bug-Bounty-Plattform.**

**Bug-Bounty-Tipp**: **Registriere dich** bei **Intigriti**, einer hochwertigen **Bug-Bounty-Plattform, die von Hackern für Hacker entwickelt wurde**! Besuche uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties von bis zu **100.000 $** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praxisorientiertes AI-Security-Training** mit einem **Engineering-First-Ansatz und praktischen Labs**. Unsere Kurse richten sich an Security Engineers, AppSec-Experten und Entwickler, die **reale, von AI/LLM betriebene Anwendungen entwickeln, angreifen und absichern** möchten.

Die **AI-Security-Zertifizierung** konzentriert sich auf praxisnahe Fähigkeiten, darunter:
- Absicherung von LLM- und AI-Anwendungen
- Threat Modeling für AI-Systeme
- Embeddings, Vector-Datenbanken und RAG-Security
- LLM-Angriffe, Missbrauchsszenarien und praktische Abwehrmaßnahmen
- Sichere Design Patterns und Deployment-Aspekte

Alle Kurse sind **on-demand**, **lab-basiert** und auf **praxisnahe Security-Abwägungen** statt nur auf Theorie ausgerichtet.

👉 Weitere Informationen zum AI-Security-Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs für den **Zugriff auf Suchmaschinenergebnisse**. Das Unternehmen scrapt Suchmaschinen, verwaltet Proxies, löst Captchas und analysiert alle umfangreichen strukturierten Daten für dich.

Ein Abonnement eines der SerpApi-Angebote umfasst den Zugriff auf mehr als 50 verschiedene APIs zum Scrapen unterschiedlicher Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und weitere.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur organische Ergebnisse**. Die Antworten von SerpApi enthalten zuverlässig alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs sowie weitere in den Suchergebnissen vorhandene Elemente und Funktionen.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Weitere Informationen findest du in ihrem [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**Playground**](https://serpapi.com/playground)** aus.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up)** ein kostenloses Konto erstellen.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Die **8kSec Academy** bildet dich in offensiver Mobile- und AI-Security aus, unterrichtet von aktiven Researchern – demselben Team hinter den CVE-Writups und Vorträgen bei Black Hat, HITB und Zer0con. Die Kurse sind im eigenen Tempo absolvierbar, basieren auf Labs mit realen Zielen und werden durch eine praxisorientierte Zertifizierung ergänzt.

Der Katalog umfasst zwei Bereiche:

**Mobile Security** – iOS und Android von der App-Ebene abwärts: Reverse Engineering mit Ghidra und LLDB, ARM64-Exploitation, Kernel-Internals und moderne Mitigations (PAC, MTE, SELinux), Jailbreak- und Rooting-Mechanismen.

**AI Security** – zwei vollständige Kurse, die das gesamte Themengebiet abdecken. Practical AI Security vermittelt, wie LLMs, RAG-Pipelines, AI-Agents und MCP funktionieren und wie man sie angreift und verteidigt. Advanced AI Security ist stark praxisorientiert und behandelt modernste Themen: Red Teaming von AI-Systemen im großen Maßstab mit Garak und PyRIT, das Ausnutzen von MCP-Servern, das Einpflanzen und Erkennen von Model-Backdoors sowie Fine-Tuning-Angriffe und -Abwehrmaßnahmen auf Apple Silicon.

Kurse und Zertifizierungen:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine AI-gestützte Security-Plattform, um ausnutzbare Schwachstellen zu finden, bevor Angreifer dies tun.

**Code-Security-Tipp**: Registriere dich bei NaxusAI, einer intelligenten Plattform zur Überwachung von Schwachstellen, die für Entwickler und Security-Teams entwickelt wurde! Beginne noch heute und nutze AI zum **Erkennen, Validieren und Beheben realer Sicherheitsrisiken, bevor diese die Produktion erreichen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit dabei unterstützt**, sich durch **Offensive-Security-Services** mit einem **modernen** Ansatz vor den neuesten Cybersecurity-Bedrohungen zu **schützen**.

WebSec ist ein internationales Security-Unternehmen mit Niederlassungen in Amsterdam und Wyoming. Das Unternehmen bietet **All-in-One-Security-Services** an, also praktisch alles: Pentesting, **Security** Audits, Awareness-Trainings, Phishing-Kampagnen, Code-Reviews, Exploit Development, Outsourcing von Security-Experten und vieles mehr.

Eine weitere Besonderheit von WebSec ist, dass das Unternehmen im Gegensatz zum Branchendurchschnitt **sehr großes Vertrauen in seine Fähigkeiten** hat – so sehr, dass es **die bestmöglichen Ergebnisse garantiert**. Auf der Website heißt es: "**If we can't hack it, You don't pay it!**". Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) und im [**Blog**](https://websec.net/blog/)!

Darüber hinaus ist WebSec ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für die Praxis entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und bietet effektive Cybersecurity-Trainings an, die von
Branchenexperten konzipiert und geleitet werden. Die Programme gehen über
Theorie hinaus und vermitteln Teams ein umfassendes
Verständnis sowie praxisnahe Fähigkeiten. Dabei kommen individuelle Umgebungen zum Einsatz, die reale
Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneiderten Trainings kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training besonders macht:**
* Individuell entwickelte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern konzipiert und vermittelt

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für Einrichtungen im Bereich **Bildung** und **FinTech** an, mit einem Schwerpunkt auf **Penetrationstests, Cloud-Security-Assessments** und **Compliance-Readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte
Fachleute**, die tiefgehendes technisches Know-how und branchenübliche Expertise in jedes
Engagement einbringen.

Wir gehen über automatisierte Scans hinaus und führen **manuelle, informationsgestützte Tests** durch, die auf
Umgebungen mit hohen Anforderungen zugeschnitten sind. Vom Schutz von Schüler- und Studentendaten bis zum Schutz
von Finanztransaktionen helfen wir Organisationen dabei, das zu verteidigen, was am wichtigsten ist.

_„Eine hochwertige Verteidigung erfordert das Verständnis des Angriffs – wir bieten Security durch Verständnis.“_

Bleibe informiert und auf dem neuesten Stand der Cybersecurity, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Die K8Studio-IDE ermöglicht es DevOps-, DevSecOps-Teams und Entwicklern, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-gestützten Erkenntnisse, das fortschrittliche Security-Framework und die intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und sicher zu handeln.

Darüber hinaus ist K8Studio **mit allen wichtigen Kubernetes-Distributionen** kompatibel (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und weitere).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Lizenz & Haftungsausschluss

Siehe:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub-Statistiken

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
