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
Ihre lokale Kopie von HackTricks wird nach <5 Minuten unter **[http://localhost:3337](http://localhost:3337)** verfügbar sein (das Buch muss gebaut werden, bitte geduldig sein).

## Unternehmenssponsoren

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** lautet. Sie betreiben eigene Forschung und entwickeln eigene Hacking-Tools, um **mehrere wertvolle Cybersecurity-Services anzubieten**, wie pentesting, Red teams und Training.

Sie können ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) besuchen

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ist die relevanteste Cybersecurity-Veranstaltung in **Spain** und eine der wichtigsten in **Europe**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein heißer Treffpunkt für Technologie- und Cybersecurity-Profis in allen Disziplinen.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist **Europe's #1** ethical hacking und **bug bounty platform.**

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Nutze [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu **automatisieren**, die von den weltweit **fortschrittlichsten** Community-Tools unterstützt werden.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Join [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) server to communicate with experienced hackers and bug bounty hunters!

- **Hacking Insights:** Engage with content that delves into the thrill and challenges of hacking
- **Real-Time Hack News:** Keep up-to-date with fast-paced hacking world through real-time news and insights
- **Latest Announcements:** Stay informed with the newest bug bounties launching and crucial platform updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) and start collaborating with top hackers today!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **Search-Engine-Results** zuzugreifen. Sie scrapen Suchmaschinen, handhaben Proxies, lösen Captchas und parsen alle reichhaltigen strukturierten Daten für Sie.

Ein Abonnement eines SerpApi-Plans umfasst Zugriff auf über 50 verschiedene APIs zum Scrapen verschiedener Suchmaschinen, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur die organischen Ergebnisse**. SerpApi-Antworten enthalten konsequent alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs und andere Elemente und Features, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Für weitere Informationen sehen Sie sich ihren [**Blog**](https://serpapi.com/blog/)**,** oder probieren Sie ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Sie können **hier** [**ein kostenloses Konto erstellen**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die erforderlich sind, um Vulnerability Research, penetration testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS- und Android-Sicherheit** durch unsere On-Demand-Kurse und **lasse dich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit schützt** vor den neuesten Cybersecurity-Bedrohungen, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Security-Unternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **All-in-One-Security-Services** an, was bedeutet, dass sie alles abdecken: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campaigns, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Ein weiterer Pluspunkt von WebSec ist, dass sie im Vergleich zum Branchendurchschnitt **sehr selbstbewusst in ihren Fähigkeiten** sind, so sehr, dass sie **die besten Qualitätsresultate garantieren** — auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos besuchen Sie ihre [**website**](https://websec.net/en/) und ihren [**blog**](https://websec.net/blog/)!

Zusätzlich ist WebSec ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersecurity-Trainings, die von Branchenexperten erstellt und geleitet werden. Ihre Programme gehen über die Theorie hinaus, um Teams mit tiefem Verständnis und umsetzbaren Fähigkeiten auszustatten, wobei benutzerdefinierte Umgebungen reale Bedrohungen widerspiegeln. Für maßgeschneiderte Trainingsanfragen kontaktieren Sie uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützung durch erstklassige Tools und Plattformen
* Entworfen und unterrichtet von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für **Education** und **FinTech** Institutionen, mit Fokus auf **penetration testing, cloud security assessments**, und **compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP und CISSP zertifizierte Fachleute**, die tiefgehende technische Expertise und Branchenstandards in jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, intelligence-driven Testing**, zugeschnitten auf risikoreiche Umgebungen. Vom Schutz von Studentendaten bis hin zum Schutz finanzieller Transaktionen helfen wir Organisationen, das zu verteidigen, was am wichtigsten ist.

_„Eine qualitativ hochwertige Verteidigung erfordert Kenntnis der Offensive, wir bieten Sicherheit durch Verständnis.“_

Bleiben Sie informiert und auf dem neuesten Stand der Cybersecurity, indem Sie unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchen.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE ermöglicht es DevOps, DevSecOps und Entwicklern, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutzen Sie unsere KI-gestützten Einblicke, fortschrittliches Security-Framework und die intuitive CloudMaps-GUI, um Ihre Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Außerdem ist K8Studio **kompatibel mit allen gängigen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Lizenz & Haftungsausschluss

Prüfen Sie diese in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## GitHub-Statistiken

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
