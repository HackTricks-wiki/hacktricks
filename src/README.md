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

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersicherheitsunternehmen, dessen Slogan **HACK THE UNHACKABLE** ist. Sie betreiben eigene Forschung und entwickeln ihre eigenen Hacking-Tools, um **mehrere wertvolle Cybersicherheitsdienste** anzubieten, wie pentesting, Red teams und Training.

Du kannst ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) ansehen

**STM Cyber** unterstützt auch Open-Source-Cybersicherheitsprojekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **#1** Plattform für ethisches Hacking und **bug bounty**.

**Bug bounty tip**: **Melde dich an** bei **Intigriti**, einer Premium-**bug bounty**-Plattform, die von Hackern für Hacker entwickelt wurde! Tritt uns noch heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties von bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Beschäftige dich mit Inhalten, die sich mit dem Reiz und den Herausforderungen von hacking befassen
- **Real-Time Hack News:** Bleibe mit Echtzeit-Nachrichten und Einblicken über die schnelllebige hacking world auf dem Laufenden
- **Latest Announcements:** Bleibe über die neuesten gestarteten bug bounties und wichtige Plattform-Updates informiert

**Tritt uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) **bei** und beginne noch heute, mit Top-Hackern zusammenzuarbeiten!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praktisches AI-Security-Training** mit einem **engineering-first, hands-on lab approach**. Unsere Kurse sind für Security Engineers, AppSec-Profis und Entwickler gemacht, die **echte KI/LLM-gestützte Anwendungen bauen, angreifen und absichern** wollen.

Die **AI Security Certification** konzentriert sich auf praxisnahe Fähigkeiten, darunter:
- Absicherung von LLM- und KI-gestützten Anwendungen
- Threat modeling für AI systems
- Embeddings, vector databases und RAG security
- LLM attacks, Missbrauchsszenarien und praktische Abwehrmaßnahmen
- Sichere Designmuster und Überlegungen zur Bereitstellung

Alle Kurse sind **on-demand**, **lab-driven** und auf **real-world security tradeoffs** ausgerichtet, nicht nur auf Theorie.

👉 Mehr Details zum AI-Security-Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um auf **search engine results** zuzugreifen. Sie scrapen Suchmaschinen, handhaben Proxies, lösen Captchas und parsen für dich alle reichhaltigen strukturierten Daten.

Ein Abonnement eines SerpApi-Tarifs umfasst Zugriff auf über 50 verschiedene APIs zum Scraping unterschiedlicher Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten durchgängig alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Für weitere Informationen sieh dir ihren [**Blog**](https://serpapi.com/blog/)**,** an oder teste ein Beispiel in ihrem [**Playground**](https://serpapi.com/playground)**.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up) **ein kostenloses Konto erstellen**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die erforderlich sind, um Vulnerability Research, Penetration Testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS- und Android-Security** durch unsere On-Demand-Kurse und **lasse dich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine KI-gestützte Sicherheitsplattform, um ausnutzbare Schwachstellen zu finden, bevor Angreifer es tun.

**Code security tip**: Melde dich bei NaxusAI an, einer intelligenten Plattform zur Schwachstellenüberwachung, die für Entwickler und Security-Teams entwickelt wurde! Tritt uns noch heute bei und beginne, KI für das **Erkennen, Validieren und Beheben echter Sicherheitsrisiken zu nutzen, bevor sie die Produktion erreichen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersicherheitsunternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit** dabei hilft, sich gegen die neuesten Cybersicherheitsbedrohungen zu **schützen**, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **all-in-one security services** an, was bedeutet, dass sie alles machen: Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing und vieles mehr.

Ein weiterer cooler Punkt an WebSec ist, dass WebSec im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in seine Fähigkeiten** ist, so sehr, dass sie **die beste Qualitätsausgabe garantieren**; auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Informationen wirf einen Blick auf ihre [**Website**](https://websec.net/en/) und ihren [**Blog**](https://websec.net/blog/)!

Zusätzlich zu den oben genannten Punkten ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Für den Einsatz gemacht. Für dich gemacht.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert wirksames Cybersicherheits-Training, das von
Branchenexperten entwickelt und geleitet wird. Ihre Programme gehen über Theorie hinaus und statten Teams mit tiefem
Verständnis und umsetzbaren Fähigkeiten aus, wobei benutzerdefinierte Umgebungen verwendet werden, die reale
Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneidertem Training kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Benutzerdefinierte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Entworfen und unterrichtet von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersicherheitsdienste für **Education**- und **FinTech**-Institutionen mit Fokus auf **penetration testing, cloud security assessments** und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-zertifizierte Fachleute**, die bei
jeder Zusammenarbeit tiefes technisches Fachwissen und branchenübliche Einblicke einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, intelligence-driven testing**, das auf
anspruchsvolle Umgebungen zugeschnitten ist. Vom Schutz von Schülerakten bis zur Absicherung von Finanztransaktionen
helfen wir Organisationen, das Wichtigste zu verteidigen.

_„Eine hochwertige Verteidigung erfordert, den Angriff zu kennen; wir bieten Sicherheit durch Verständnis.“_

Bleibe informiert und auf dem Laufenden mit den neuesten Cybersecurity-Themen, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler dazu, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere KI-gestützten Einblicke, das fortschrittliche Sicherheitsframework und die intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Außerdem ist K8Studio **mit allen wichtigen kubernetes distributions kompatibel** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Dies ist ein Text, um das kostenlose Cybersecurity-Wiki <b>Hacktricks Book </b> vorzustellen. Lerne jetzt kostenlos alle Arten von hacking tricks daraus!

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Sieh sie dir an in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
