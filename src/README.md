# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-Logos & Motion-Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ihre lokale Kopie von HackTricks ist in ca. **verfügbar unter [http://localhost:3337](http://localhost:3337)** nach <5 Minuten (das Buch muss gebaut werden, bitte geduldig sein).

## Unternehmenssponsoren

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** lautet. Sie betreiben eigene Forschung und entwickeln eigene hacking tools, um mehrere wertvolle Cybersecurity-Services wie pentesting, Red teams und Training anzubieten.

Sie können ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen.

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ist das relevanteste Cybersecurity-Event in **Spain** und eines der wichtigsten in **Europe**. Mit der **Mission, technisches Wissen zu fördern**, ist dieser Kongress ein lebendiger Treffpunkt für Technologie- und Cybersecurity-Profis aus allen Disziplinen.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist **Europe's #1** ethical hacking und **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, eine premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Nutze [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den weltweit **most advanced** Community-Tools angetrieben werden.

Zugang erhalten:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server, um mit erfahrenen hackers und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginne noch heute mit der Zusammenarbeit mit Top-Hackern!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Erhalte eine hacker's perspective auf deine Web-Apps, dein Netzwerk und Cloud**

**Finde und melde kritische, ausnutzbare Schwachstellen mit echtem geschäftlichem Einfluss.** Nutze unsere 20+ custom tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die eine Privilegieneskalation ermöglichen, und automatisierte Exploits zu verwenden, um essenzielle Beweise zu sammeln — so wird deine Arbeit in aussagekräftige Reports verwandelt.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **search engine results** zuzugreifen. Sie scrapen search engines, managen proxies, lösen captchas und parsen alle reichhaltigen strukturierten Daten für dich.

Ein Abonnement eines SerpApi-Plans beinhaltet Zugriff auf über 50 verschiedene APIs zum Scrapen unterschiedlicher search engines, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scraped **SerpApi** nicht nur organische Ergebnisse. SerpApi-Antworten enthalten konsistent alle Ads, Inline-Bilder und Videos, Knowledge Graphs und andere Elemente und Features, die in den Suchergebnissen vorhanden sind.

Aktuelle SerpApi-Kunden sind **Apple, Shopify, and GrubHub**.\
Für mehr Informationen schaue dir ihren [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Du kannst **ein kostenloses Konto erstellen** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die erforderlich sind, um Vulnerability Research, penetration testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS und Android security** durch unsere On-Demand-Kurse und **lasse dich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit schützt** vor den neuesten Cybersecurity-Bedrohungen, indem es offensive-security services mit einem **modernen** Ansatz anbietet.

WebSec ist ein international security company mit Büros in Amsterdam und Wyoming. Sie bieten **all-in-one security services**, das heißt sie übernehmen alles: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Ein weiterer cooler Punkt bei WebSec ist, dass sie im Vergleich zum Branchendurchschnitt **sehr selbstbewusst in ihren Fähigkeiten** sind, so sehr, dass sie **die besten Ergebnisse garantieren**; auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos schaue dir ihre [**website**](https://websec.net/en/) und ihren [**blog**](https://websec.net/blog/) an!

Zusätzlich ist WebSec ein **engagierter Unterstützer** von HackTricks.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ist eine data breach (leak) search engine. \
Wir bieten random string search (like google) über alle Arten von data leaks, große und kleine --nicht nur die großen-- über Daten aus mehreren Quellen. \
Personensuche, AI search, organization search, API (OpenAPI) access, theHarvester integration, alle Features, die ein pentester braucht.\
**HackTricks bleibt eine großartige Lernplattform für uns alle und wir sind stolz, sie zu sponsern!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektives Cybersecurity-Training, erstellt und geleitet von Industry Experts. Ihre Programme gehen über Theorie hinaus und statten Teams mit tiefem Verständnis und umsetzbaren Fähigkeiten aus, mit maßgeschneiderten Umgebungen, die reale Bedrohungen widerspiegeln. Für maßgeschneiderte Trainingsanfragen kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Custom-built content und Labs
* Unterstützt von Top-Tier-Tools und Plattformen
* Entwickelt und gelehrt von Practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions liefert spezialisierte Cybersecurity-Services für **Education** und **FinTech**
Institutionen, mit Fokus auf **penetration testing, cloud security assessments**, und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP und CISSP
zertifizierte Professionals**, die tiefes technisches Fachwissen und Branchen-Standard-Insights in
jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, intelligence-driven Testing**, maßgeschneidert für
hochkritische Umgebungen. Vom Schutz von Studentendaten bis zur Absicherung finanzieller Transaktionen,
helfen wir Organisationen, das Wichtigste zu verteidigen.

_„Eine qualitativ hochwertige Verteidigung erfordert Kenntnisse der Offensive, wir bieten Sicherheit durch Verständnis.“_

Bleibe informiert und auf dem neuesten Stand der Cybersecurity, indem du ihren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler, Kubernetes-Cluster effizient zu verwalten, zu überwachen und zu sichern. Nutze unsere AI-driven Insights, fortschrittliches Security-Framework und intuitive CloudMaps GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Darüber hinaus ist K8Studio **kompatibel mit allen großen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Siehe dort:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub-Statistiken

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
