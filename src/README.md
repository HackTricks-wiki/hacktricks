# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos & Motion Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Deine lokale Kopie von HackTricks ist nach weniger als 5 Minuten unter [http://localhost:3337](http://localhost:3337) verfügbar (das Buch muss erstellt werden, bitte hab Geduld).

Alternativ kannst du, wenn du Docker Compose hast, einfach Folgendes im Stammverzeichnis des Repositories ausführen:
```bash
docker compose up
```
Dies verwendet die enthaltene `docker-compose.yml`, um den aktuell auf dem Host ausgecheckten Branch unter [http://localhost:3337](http://localhost:3337) mit Live-Reload bereitzustellen. Um bei Verwendung von Compose die Sprache zu ändern, checke vor dem Start des Service den gewünschten Sprach-Branch aus.

## HackTricks-Partner

---

## HackTricks-Freunde

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen mit dem Slogan **HACK THE UNHACKABLE**. Das Unternehmen führt eigene Research durch und entwickelt eigene Hacking-Tools, um **mehrere wertvolle Cybersecurity-Services anzubieten**, darunter Pentesting, Red Teams und Training.

Du kannst den **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen.

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **Nummer 1** für ethisches Hacking und die **Bug-Bounty-Plattform**.

**Bug-Bounty-Tipp**: **Registriere dich** bei **Intigriti**, einer erstklassigen **Bug-Bounty-Plattform, die von Hackern für Hacker entwickelt wurde**! Besuche uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties von bis zu **100.000 $** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI- und Application-Security-Trainingsplattform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praxisnahes AI-Security-Training** mit einem **Engineering-first- und praxisorientierten Laboransatz**. Unsere Kurse richten sich an Security Engineers, AppSec-Experten und Entwickler, die **echte AI-/LLM-basierte Anwendungen entwickeln, angreifen und absichern** möchten.

Die **AI-Security-Zertifizierung** konzentriert sich auf praxisrelevante Fähigkeiten, darunter:
- Absicherung von LLM- und AI-basierten Anwendungen
- Threat Modeling für AI-Systeme
- Embeddings, Vektordatenbanken und RAG-Security
- LLM-Angriffe, Missbrauchsszenarien und praktische Abwehrmaßnahmen
- Sichere Design-Patterns und Überlegungen zur Bereitstellung

Alle Kurse sind **on-demand**, **laborbasiert** und auf **praxisnahe Security-Abwägungen** statt ausschließlich auf Theorie ausgerichtet.

👉 Weitere Informationen zum AI-Security-Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs für den **Zugriff auf Suchmaschinenergebnisse**. Das Unternehmen scraped Suchmaschinen, verwaltet Proxies, löst Captchas und analysiert alle umfangreichen strukturierten Daten für dich.

Ein Abonnement eines der SerpApi-Tarife beinhaltet den Zugriff auf mehr als 50 verschiedene APIs zum Scraping verschiedener Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und weitere.\
Im Gegensatz zu anderen Anbietern scraped **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten zuverlässig alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs sowie weitere in den Suchergebnissen vorhandene Elemente und Funktionen.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Weitere Informationen findest du im [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel im [**Playground**](https://serpapi.com/playground)**.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up)** ein kostenloses Konto erstellen.**

---

### [8kSec Academy – Umfangreiche Mobile- und AI-Security-Kurse](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** bildet dich in offensiver Mobile- und AI-Security aus, unterrichtet von aktiven Researchern – demselben Team hinter den CVE-Writeups und Vorträgen bei Black Hat, HITB und Zer0con. Die Kurse können im eigenen Tempo absolviert werden, basieren auf Laboren mit realen Zielen und werden durch eine praxisorientierte Zertifizierung ergänzt.

Das Angebot umfasst zwei Bereiche:

**Mobile Security** – iOS und Android von der App-Schicht abwärts: Reverse Engineering mit Ghidra und LLDB, ARM64-Exploitation, Kernel-Internals und moderne Mitigations (PAC, MTE, SELinux), Jailbreak- und Rooting-Mechanismen.

**AI Security** – zwei vollständige Kurse, die das gesamte Themengebiet abdecken. Practical AI Security erklärt, wie LLMs, RAG-Pipelines, AI-Agents und MCP funktionieren und wie man sie angreift und verteidigt. Advanced AI Security ist stark auf die praktische Umsetzung an der technologischen Spitze ausgerichtet: Red Teaming von AI-Systemen im großen Maßstab mit Garak und PyRIT, Ausnutzung von MCP-Servern, Einfügen und Erkennen von Model-Backdoors sowie Fine-Tuning-Angriffe und -Abwehrmaßnahmen auf Apple Silicon.

Kurse und Zertifizierungen:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI-gestützter Security-Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine AI-gestützte Security-Plattform, um ausnutzbare Schwachstellen zu finden, bevor Angreifer dies tun.

**Tipp zur Code-Security**: Registriere dich bei NaxusAI, einer intelligenten Plattform zur Überwachung von Schwachstellen, die für Entwickler und Security-Teams entwickelt wurde! Nutze noch heute AI zum **Erkennen, Validieren und Beheben realer Security-Risiken, bevor diese die Produktion erreichen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **auf der ganzen Welt dabei unterstützt, sich** durch **Offensive-Security-Services** mit einem **modernen** Ansatz gegen die neuesten Cybersecurity-Bedrohungen zu **schützen**.

WebSec ist ein internationales Security-Unternehmen mit Niederlassungen in Amsterdam und Wyoming. Das Unternehmen bietet **all-in-one Security-Services** an, das heißt: Es wird alles abgedeckt – Pentesting, **Security** Audits, Awareness-Trainings, Phishing-Kampagnen, Code Review, Exploit Development, Outsourcing von Security-Experten und vieles mehr.

Ein weiterer Vorteil von WebSec ist, dass das Unternehmen im Gegensatz zum Branchendurchschnitt **sehr großes Vertrauen in seine Fähigkeiten** hat – sogar so sehr, dass es **die bestmöglichen Ergebnisse garantiert**. Auf der Website heißt es: "**If we can't hack it, You don't pay it!**". Weitere Informationen findest du auf der [**Website**](https://websec.net/en/) und im [**Blog**](https://websec.net/blog/)!

Zusätzlich zu den oben genannten Leistungen ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für die Praxis entwickelt. Auf dich zugeschnitten.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und bietet effektive Cybersecurity-Trainings an, die von Branchenexperten konzipiert und durchgeführt werden. Die Programme gehen über reine Theorie hinaus und vermitteln Teams ein tiefes Verständnis sowie praxisnahe Fähigkeiten. Dabei kommen speziell entwickelte Umgebungen zum Einsatz, die reale Bedrohungen widerspiegeln. Für Anfragen zu individuellen Trainings kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihre Trainings auszeichnet:**
* Individuell entwickelte Inhalte und Labore
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern konzipiert und unterrichtet

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für Institutionen aus den Bereichen **Bildung** und **FinTech**, mit Schwerpunkt auf **Penetrationstests, Cloud-Security-Assessments** und **Compliance-Bereitschaft** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte Fachkräfte**, die tiefgehende technische Expertise und branchenübliche Standards in jeden Auftrag einbringen.

Wir gehen über automatisierte Scans hinaus und führen **manuelle, intelligence-basierte Tests** durch, die auf Umgebungen mit hohen Anforderungen zugeschnitten sind. Vom Schutz von Studierendendaten bis zur Absicherung von Finanztransaktionen helfen wir Organisationen dabei, das zu verteidigen, was am wichtigsten ist.

_„Eine hochwertige Verteidigung erfordert Kenntnisse über den Angriff – wir bieten Security durch Verständnis.“_

Bleibe über die neuesten Entwicklungen in der Cybersecurity informiert, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - Die intelligentere GUI zur Verwaltung von Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

Die K8Studio IDE ermöglicht es DevOps-, DevSecOps-Teams und Entwicklern, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-gestützten Erkenntnisse, das fortschrittliche Security-Framework und die intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und sicher zu handeln.

Darüber hinaus ist K8Studio **mit allen wichtigen Kubernetes-Distributionen kompatibel** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und weitere).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Lizenz und Haftungsausschluss

Weitere Informationen findest du hier:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub-Statistiken

![HackTricks-GitHub-Statistiken](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
