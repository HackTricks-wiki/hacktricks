# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design by_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your lokale Kopie von HackTricks wird nach <5 Minuten **unter [http://localhost:3337](http://localhost:3337) verfügbar sein** (das Buch muss gebaut werden, bitte geduldig sein).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersicherheitsunternehmen mit dem Slogan **HACK THE UNHACKABLE**. Sie betreiben eigene Forschung und entwickeln ihre eigenen Hacking-Tools, um **mehrere wertvolle Cybersicherheitsdienste** wie pentesting, Red teams und Schulungen anzubieten.

Du kannst ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) ansehen.

**STM Cyber** unterstützt außerdem Open-Source-Cybersicherheitsprojekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **#1** Plattform für Ethical Hacking und **bug bounty**.

**Bug bounty-Tipp**: **Melde dich an** für **Intigriti**, eine Premium-**bug bounty**-Plattform, erstellt von Hackern, für Hacker! Tritt uns heute bei [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties von bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy)-Server bei, um mit erfahrenen Hackern und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Beschäftige dich mit Inhalten, die in die Faszination und Herausforderungen des Hackings eintauchen
- **Real-Time Hack News:** Bleibe mit Echtzeit-News und Einblicken in der schnelllebigen Hacking-Welt auf dem Laufenden
- **Latest Announcements:** Bleibe über die neuesten startenden bug bounties und wichtige Plattform-Updates informiert

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginne noch heute, mit Top-Hackern zusammenzuarbeiten!

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security liefert **praktisches AI-Security-Training** mit einem **engineering-first, hands-on lab approach**. Unsere Kurse sind für Security Engineers, AppSec-Profis und Entwickler konzipiert, die **echte AI/LLM-gestützte Anwendungen bauen, brechen und absichern** wollen.

Die **AI Security Certification** konzentriert sich auf praxisnahe Fähigkeiten, darunter:
- Absicherung von LLM- und AI-gestützten Anwendungen
- Threat Modeling für AI-Systeme
- Embeddings, Vektordatenbanken und RAG-Security
- LLM-Angriffe, Missbrauchsszenarien und praktische Abwehrmaßnahmen
- Sichere Designmuster und Überlegungen zur Bereitstellung

Alle Kurse sind **on-demand**, **lab-driven** und um **real-world security tradeoffs** herum gestaltet, nicht nur Theorie.

👉 Mehr Details zum AI-Security-Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **Zugriff auf Suchmaschinenergebnisse** zu erhalten. Sie scrapen Suchmaschinen, handhaben Proxies, lösen Captchas und parsen alle reichhaltigen strukturierten Daten für dich.

Ein Abonnement eines SerpApi-Plans umfasst Zugriff auf über 50 verschiedene APIs zum Scrapen verschiedener Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten durchgängig alle Anzeigen, Inline-Bilder und Videos, Knowledge Graphs und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Weitere Informationen findest du in ihrem [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**Playground**](https://serpapi.com/playground)**.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up)** ein kostenloses Konto erstellen**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** schult dich in offensiver Mobile- und AI-Security, unterrichtet von aktiven Forschern – dem gleichen Team hinter den CVE-Writups und Vorträgen auf Black Hat, HITB und Zer0con. Die Kurse sind selbstgesteuert, auf Labs an realen Targets aufgebaut und durch eine praxisnahe Zertifizierung ergänzt.

Der Katalog umfasst zwei Schwerpunkte:

**Mobile Security** – iOS und Android von der App-Ebene abwärts: Reverse Engineering mit Ghidra und LLDB, ARM64 Exploitation, Kernel-Interna und moderne Mitigations (PAC, MTE, SELinux), Jailbreak- und Rooting-Mechaniken.

**AI Security** – zwei vollständige Kurse, die das Feld abdecken. Practical AI Security behandelt, wie LLMs, RAG-Pipelines, AI Agents und MCP funktionieren und wie man sie angreift und verteidigt. Advanced AI Security geht an der Frontlinie stärker in die Entwicklung: Red Teaming von AI-Systemen im großen Maßstab mit Garak und PyRIT, Ausnutzen von MCP-Servern, Platzieren und Erkennen von Model Backdoors sowie Fine-Tuning-Angriffe und Verteidigungen auf Apple Silicon.

Kurse und Zertifizierungen:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine AI-gestützte Sicherheitsplattform, um ausnutzbare Schwachstellen zu finden, bevor Angreifer es tun.

**Code security-Tipp**: Melde dich für NaxusAI an, eine smarte Plattform zur Schwachstellenüberwachung, entwickelt für Entwickler und Security-Teams! Tritt uns heute bei und beginne, AI zu nutzen, um **echte Sicherheitsrisiken zu erkennen, zu validieren und zu beheben, bevor sie die Produktion erreichen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersicherheitsunternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit** dabei hilft, sich gegen die neuesten Cybersicherheitsbedrohungen zu **schützen**, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **all-in-one security services**, das heißt, sie machen alles; Pentesting, **Security** Audits, Awareness-Schulungen, Phishing-Kampagnen, Code Review, Exploit Development, Auslagerung von Security-Experten und vieles mehr.

Noch ein cooler Punkt an WebSec ist, dass sie sich im Gegensatz zum Branchendurchschnitt **sehr sicher in ihren Fähigkeiten** sind, und zwar so sehr, dass sie **die beste Qualität der Ergebnisse garantieren**; auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos wirf einen Blick auf ihre [**Website**](https://websec.net/en/) und ihren [**Blog**](https://websec.net/blog/)!

Zusätzlich dazu ist WebSec auch ein **engagierter Unterstützer von HackTricks**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersicherheitsschulungen, die von
Branchenexperten entwickelt und geleitet werden. Ihre Programme gehen über Theorie hinaus, um Teams mit tiefem
Verständnis und umsetzbaren Fähigkeiten auszustatten, unter Einsatz maßgeschneiderter Umgebungen, die realweltliche
Bedrohungen widerspiegeln. Für Anfragen zu kundenspezifischen Schulungen kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihre Schulungen auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Von Praktikern entworfen und unterrichtet

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersicherheitsdienste für **Education**- und **FinTech**
-Institutionen mit Fokus auf **penetration testing, cloud security assessments** und
**Compliance-Bereitschaft** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-
zertifizierte Fachleute**, die tiefes technisches Fachwissen und branchentypische Einblicke in
jeden Auftrag einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, nachrichtengesteuertem Testing**, das auf
hochriskante Umgebungen zugeschnitten ist. Vom Schutz von Schülerdaten bis zur Absicherung von Finanztransaktionen
helfen wir Organisationen, das zu verteidigen, was am wichtigsten ist.

_„Eine qualitativ hochwertige Verteidigung erfordert Kenntnis des Angriffs, wir bieten Sicherheit durch Verständnis.“_

Bleib informiert und auf dem Laufenden über die neuesten Entwicklungen in der Cybersicherheit, indem du unseren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps-, DevSecOps- und Entwicklerteams, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-gestützten Einblicke, das fortschrittliche Security-Framework und die intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Vertrauen zu handeln.

Außerdem ist K8Studio **kompatibel mit allen großen kubernetes distributionen** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Check them in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
