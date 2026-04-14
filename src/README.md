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
Your local copy of HackTricks wird **nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) verfügbar sein** (es muss das Buch bauen, bitte geduldig sein).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** ist. Sie führen eigene Forschung durch und entwickeln eigene hacking tools, um **mehrere wertvolle Cybersecurity-Services anzubieten**, wie pentesting, Red teams und training.

Du kannst ihren **blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) ansehen

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **#1** ethische hacking- und **bug bounty platform.**

**Bug bounty tip**: **melde dich an** für **Intigriti**, eine Premium-**bug bounty platform created by hackers, for hackers**! Schließe dich uns noch heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) an und beginne, Bounties von bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Beschäftige dich mit Inhalten, die in den Nervenkitzel und die Herausforderungen von hacking eintauchen
- **Real-Time Hack News:** Bleibe mit der schnelllebigen hacking world durch Echtzeit-Nachrichten und Einblicke auf dem Laufenden
- **Latest Announcements:** Bleibe über die neuesten laufenden bug bounties und wichtige Plattform-Updates informiert

**Komm zu uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginne noch heute, mit Top-Hackern zusammenzuarbeiten!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praktisches AI Security training** mit einem **engineering-first, hands-on lab approach**. Unsere Kurse sind für Security engineers, AppSec professionals und developers konzipiert, die **echte AI/LLM-powered applications bauen, angreifen und absichern** wollen.

Die **AI Security Certification** konzentriert sich auf praxisnahe Fähigkeiten, einschließlich:
- Absicherung von LLM and AI-powered applications
- Threat modeling für AI systems
- Embeddings, vector databases und RAG security
- LLM attacks, abuse scenarios und praktische Abwehrmaßnahmen
- Sichere Designmuster und Überlegungen zur Bereitstellung

Alle Kurse sind **on-demand**, **lab-driven** und auf **real-world security tradeoffs** ausgerichtet, nicht nur auf Theorie.

👉 Mehr Details zum AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **search engine results** zuzugreifen. Sie scrapen search engines, handhaben Proxies, lösen captchas und parsen alle angereicherten strukturierten Daten für dich.

Ein Abo für einen der SerpApi-Pläne beinhaltet Zugriff auf über 50 verschiedene APIs zum Scrapen verschiedener search engines, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scraped **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten durchgehend alle Anzeigen, Inline-Bilder und Videos, knowledge graphs und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden zählen **Apple, Shopify und GrubHub**.\
Weitere Informationen findest du in ihrem [**blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up) ein **kostenloses Konto erstellen**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die erforderlich sind, um vulnerability research, penetration testing und reverse engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS- und Android-Sicherheit** durch unsere On-Demand-Kurse und **lasse dich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen auf der ganzen Welt dabei hilft, sich gegen die neuesten Cybersecurity-Bedrohungen zu **schützen**, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **all-in-one security services** an, das heißt, sie machen alles; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Eine weitere coole Sache an WebSec ist, dass sie im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in ihre Fähigkeiten** sind, so sehr, dass sie **die beste Qualitätsresultate garantieren**, es steht auf ihrer Website "**If we can't hack it, You don't pay it!**". Für mehr Infos wirf einen Blick auf ihre [**website**](https://websec.net/en/) und [**blog**](https://websec.net/blog/)!

Zusätzlich dazu ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersecurity-Trainings, die von
Branchenexperten entwickelt und geleitet werden. Ihre Programme gehen über die Theorie hinaus und statten Teams mit tiefem
Verständnis und umsetzbaren Fähigkeiten aus, indem sie maßgeschneiderte Umgebungen verwenden, die reale
Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneiderten Schulungen kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Entworfen und unterrichtet von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für **Education**- und **FinTech**
-Institutionen, mit Schwerpunkt auf **penetration testing, cloud security assessments** und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte
Fachleute**, die tiefes technisches Know-how und branchenspezifische Einblicke in
jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellen, intelligence-driven testing**, die auf
anspruchsvolle Umgebungen zugeschnitten sind. Von der Sicherung von Schülerdaten bis zum Schutz finanzieller Transaktionen
helfen wir Organisationen, das zu verteidigen, was am wichtigsten ist.

_“Eine hochwertige Verteidigung erfordert, den Angriff zu kennen; wir bieten Sicherheit durch Verständnis.”_

Bleibe informiert und auf dem neuesten Stand mit den aktuellen Entwicklungen in der Cybersecurity, indem du unseren [**blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und developers dazu, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-gestützten Einblicke, das fortschrittliche Sicherheitsframework und die intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Vertrauen zu handeln.

Außerdem ist K8Studio **kompatibel mit allen wichtigen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Sieh sie dir an unter:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
