# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-Logos & Motion Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Ihre lokale Kopie von HackTricks wird nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) **verfügbar sein** (es muss das Buch erstellen, bitte haben Sie Geduld).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** lautet. Sie führen eigene Forschung durch und entwickeln ihre eigenen hacking tools, um **mehrere wertvolle Cybersecurity-Services** wie pentesting, Red Teams und Trainings anzubieten.

Ihr **Blog** ist unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) verfügbar

**STM Cyber** unterstützt außerdem Open-Source-Projekte im Bereich Cybersecurity wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **#1** Plattform für ethisches Hacking und **bug bounty platform.**

**Bug bounty tip**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**bug bounty platform created by hackers, for hackers**! Kommen Sie noch heute zu uns unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginnen Sie, Bounties von bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Beschäftigen Sie sich mit Inhalten, die in den Nervenkitzel und die Herausforderungen des Hacking eintauchen
- **Real-Time Hack News:** Bleiben Sie mit dem schnelllebigen Hacking world durch Echtzeit-Nachrichten und Insights auf dem Laufenden
- **Latest Announcements:** Bleiben Sie über die neuesten bug bounties, die starten, und wichtige Plattform-Updates informiert

**Treten Sie uns bei auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginnen Sie noch heute mit top Hackern zusammenzuarbeiten!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security liefert **praxisnahes AI Security Training** mit einem **engineering-first, hands-on lab approach**. Unsere Kurse sind für Security Engineers, AppSec-Profis und Entwickler gebaut, die **echte von AI/LLM-powered applications** bauen, brechen und absichern wollen.

Die **AI Security Certification** konzentriert sich auf reale Fähigkeiten, einschließlich:
- Absichern von LLM and AI-powered applications
- Threat modeling für AI systems
- Embeddings, vector databases und RAG Security
- LLM attacks, missbräuchliche Szenarien und praktische Verteidigungen
- Sichere Designmuster und Überlegungen zur Bereitstellung

Alle Kurse sind **on-demand**, **lab-driven** und auf **real-world security tradeoffs** ausgerichtet, nicht nur auf Theorie.

👉 Weitere Details zum AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs für den **Zugriff auf Suchmaschinenergebnisse**. Sie scrapen Suchmaschinen, handhaben Proxies, lösen captchas und parsen alle umfangreichen strukturierten Daten für Sie.

Ein Abonnement für einen der Tarife von SerpApi umfasst Zugriff auf über 50 verschiedene APIs zum Scraping verschiedener Suchmaschinen, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten durchgehend alle Anzeigen, Inline-Bilder und Videos, Knowledge Graphs und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Weitere Informationen finden Sie in ihrem [**Blog**](https://serpapi.com/blog/)**,** oder probieren Sie ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Sie können [**hier**](https://serpapi.com/users/sign_up) ein **kostenloses Konto erstellen**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lernen Sie die Technologien und Fähigkeiten, die erforderlich sind, um Vulnerability Research, Penetration Testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistern Sie iOS and Android security** durch unsere on-demand-Kurse und **lassen Sie sich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine AI-powered Security Platform, um ausnutzbare Vulnerabilities zu finden, bevor Angreifer es tun.

**Code Security tip**: Melden Sie sich bei NaxusAI an, einer intelligenten Vulnerability-Monitoring-Plattform, die für Entwickler und Security-Teams gebaut wurde! Kommen Sie noch heute zu uns und beginnen Sie, AI zu nutzen, um **reale Sicherheitsrisiken zu erkennen, zu validieren und zu beheben, bevor sie die Produktion erreichen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das **Unternehmen auf der ganzen Welt** dabei hilft, sich gegen die neuesten Cybersecurity-Bedrohungen zu **schützen**, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Security-Unternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **all-in-one security services** an, was bedeutet, dass sie alles machen; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Ein weiteres cooles Ding an WebSec ist, dass sie im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in ihre Fähigkeiten** sind, so sehr, dass sie **die beste Qualität der Ergebnisse garantieren**, auf ihrer Website steht "**If we can't hack it, You don't pay it!**". Für mehr Infos werfen Sie einen Blick auf ihre [**Website**](https://websec.net/en/) und ihren [**Blog**](https://websec.net/blog/)!

Zusätzlich zu dem oben genannten ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersecurity-Trainings, die von Branchenexperten entwickelt und geleitet werden. Ihre Programme gehen über die Theorie hinaus, um Teams mit tiefem Verständnis und umsetzbaren Fähigkeiten auszustatten, indem sie benutzerdefinierte Umgebungen nutzen, die reale Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneiderten Trainings kontaktieren Sie uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Gestützt auf erstklassige Tools und Plattformen
* Entworfen und unterrichtet von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions liefert spezialisierte Cybersecurity-Services für **Bildungs-** und **FinTech**
-Institutionen, mit Fokus auf **penetration testing, cloud security assessments** und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte Fachleute**, die tiefes technisches Know-how und branchenübliche Einblicke in
jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellen, intelligence-driven testing**, das auf
hochkritische Umgebungen zugeschnitten ist. Vom Schutz von Schülerdaten bis zur Sicherung finanzieller Transaktionen helfen wir Organisationen, das Wichtigste zu verteidigen.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bleiben Sie informiert und auf dem neuesten Stand mit den aktuellsten Cybersecurity-Themen, indem Sie unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchen.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler dazu, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutzen Sie unsere AI-driven insights, das fortschrittliche Security-Framework und die intuitive CloudMaps-GUI, um Ihre Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Außerdem ist K8Studio **kompatibel mit allen wichtigen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Prüfen Sie diese unter:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
