# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks Logos & Motion-Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ihre lokale Kopie von HackTricks wird **unter [http://localhost:3337](http://localhost:3337) verfügbar sein** nach <5 Minuten (das Buch muss noch gebaut werden, bitte haben Sie Geduld).

## Corporate-Sponsoren

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** ist. Sie betreiben eigene Forschung und entwickeln eigene Hacking-Tools, um **verschiedene wertvolle Cybersecurity-Services** wie pentesting, Red teams und Training anzubieten.

Sie können ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen.

**STM Cyber** unterstützt auch Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ist die bedeutendste Cybersecurity-Veranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit der **Mission, technisches Wissen zu fördern**, ist dieser Kongress ein zentraler Treffpunkt für Technologie- und Cybersecurity-Fachleute aus allen Disziplinen.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas #1 ethical hacking und bug bounty platform.

**Bug bounty tip**: **melde dich an** für **Intigriti**, eine Premium bug bounty platform created by hackers, for hackers! Trete uns bei unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Nutze [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu **automatisieren**, angetrieben von den weltweit **fortschrittlichsten** Community-Tools.

Jetzt Zugang erhalten:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um dich mit erfahrenen Hackern und bug bounty hunters auszutauschen!

- **Hacking-Einblicke:** Beschäftige dich mit Inhalten, die die Faszination und die Herausforderungen des Hackings beleuchten
- **Echtzeit-Hack-News:** Bleibe auf dem Laufenden in der schnelllebigen Hacking-Welt durch Echtzeit-Nachrichten und Einblicke
- **Neueste Ankündigungen:** Erfahre von neuen bug bounties und wichtigen Plattform-Updates

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **bei** und beginne noch heute mit der Zusammenarbeit mit Top-Hackern!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praktische AI Security Schulungen** mit einem **engineering-first, hands-on Lab-Ansatz**. Unsere Kurse sind für Security Engineers, AppSec-Profis und Entwickler konzipiert, die echte AI/LLM-basierte Anwendungen **bauen, angreifen und absichern** wollen.

Die **AI Security Certification** konzentriert sich auf praxisnahe Fähigkeiten, einschließlich:
- Absicherung von LLM- und AI-gestützten Anwendungen
- Threat Modeling für AI-Systeme
- Embeddings, Vektor-Datenbanken und RAG-Sicherheit
- LLM-Angriffe, Missbrauchsszenarien und praktische Abwehrmaßnahmen
- Sichere Design-Patterns und Deployment-Überlegungen

Alle Kurse sind **on-demand**, **lab-driven** und um reale Sicherheits-Tradeoffs herum gestaltet, nicht nur Theorie.

👉 Mehr Details zum AI Security Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **Search Engine Results** zuzugreifen. Sie scrapen Suchmaschinen, übernehmen Proxy-Handling, lösen Captchas und parsen alle reichhaltigen strukturierten Daten für dich.

Ein Abonnement eines SerpApi-Plans beinhaltet Zugriff auf über 50 verschiedene APIs zum Scrapen verschiedener Suchmaschinen, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scraped **SerpApi** nicht nur organische Ergebnisse. SerpApi-Antworten enthalten konsistent alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs und andere Elemente und Features, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Für mehr Informationen sieh dir ihren [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Du kannst **ein kostenloses Konto erstellen** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die nötig sind, um Vulnerability Research, penetration testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS- und Android-Sicherheit** durch unsere On-Demand-Kurse und **lasse dich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit** gegen die neuesten Cybersecurity-Bedrohungen schützt, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **All-in-One Security Services**, das heißt sie decken alles ab: pentesting, **Security** Audits, Awareness Trainings, Phishing-Kampagnen, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Ein weiteres cooles Detail über WebSec ist, dass sie im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in ihre Fähigkeiten** sind, so sehr, dass sie **die besten Qualitätsresultate garantieren** — auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos schau dir ihre [**Website**](https://websec.net/en/) und den [**Blog**](https://websec.net/blog/) an!

Zusätzlich ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


Für den praktischen Einsatz entwickelt. Rund um dich aufgebaut.\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersecurity-Schulungen, die von Branchenexperten erstellt und geleitet werden. Ihre Programme gehen über die Theorie hinaus, um Teams mit tiefem Verständnis und praxisnahen Fähigkeiten auszustatten, indem sie kundenspezifische Umgebungen nutzen, die reale Bedrohungen widerspiegeln. Für maßgeschneiderte Trainingsanfragen kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihre Trainings auszeichnet:**
* Individuell erstellte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Entwickelt und gelehrt von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für **Education** und **FinTech** Institutionen, mit Fokus auf **penetration testing, cloud security assessments** und **Compliance-Readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte Professionals**, die tiefes technisches Fachwissen und Branchenstandard-Einblicke in jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus und bieten **manuelle, intelligence-driven Tests**, zugeschnitten auf hochriskante Umgebungen. Vom Schutz von Studentendaten bis hin zur Absicherung finanzieller Transaktionen helfen wir Organisationen, das zu verteidigen, was am meisten zählt.

_„Eine hochwertige Verteidigung erfordert das Verständnis des Angriffs; wir bieten Sicherheit durch Verständnis.“_

Bleibe informiert und auf dem neuesten Stand der Cybersecurity, indem du ihren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-getriebenen Insights, fortschrittliches Sicherheits-Framework und die intuitive CloudMaps GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Darüber hinaus ist K8Studio **kompatibel mit allen major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Siehe:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
