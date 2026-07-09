# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks Logos & Motion Design von_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Your local copy of HackTricks wird **nach <5 Minuten unter [http://localhost:3337](http://localhost:3337) verfügbar sein** (es muss das Buch bauen, bitte hab Geduld).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** lautet. Sie führen eigene Forschung durch und entwickeln ihre eigenen Hacking-Tools, um **mehrere wertvolle Cybersecurity-Services anzubieten**, wie pentesting, Red teams und Schulungen.

Du kannst ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) ansehen

**STM Cyber** unterstützt auch Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas **#1** Plattform für ethisches Hacking und **bug bounty platform.**

**Bug bounty tip**: Melde dich für **Intigriti** an, eine Premium-**bug bounty platform created by hackers, for hackers**! Mach heute mit unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) und beginne, Bounties von bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security bietet **praktisches AI Security Training** mit einem **engineering-first, hands-on lab approach**. Unsere Kurse sind für Security Engineers, AppSec-Profis und Entwickler gedacht, die **realen AI/LLM-powered applications** aufbauen, angreifen und absichern wollen.

Die **AI Security Certification** konzentriert sich auf praxisnahe Fähigkeiten, darunter:
- Absichern von LLM- und AI-powered applications
- Threat modeling für AI systems
- Embeddings, vector databases und RAG security
- LLM attacks, Abuse-Szenarien und praktische Abwehr
- Sichere Designmuster und Deployment-Überlegungen

Alle Kurse sind **on-demand**, **lab-driven** und auf **real-world security tradeoffs** ausgelegt, nicht nur auf Theorie.

👉 Weitere Details zum AI Security-Kurs:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um auf **search engine results** zuzugreifen. Sie scrapen Suchmaschinen, handhaben Proxies, lösen captchas und parsen alle reichhaltigen strukturierten Daten für dich.

Ein Abonnement für einen der SerpApi-Tarife umfasst Zugang zu über 50 verschiedenen APIs zum Scraping verschiedener Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern scrapt **SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten durchgehend alle Ads, inline images und Videos, knowledge graphs und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Zu den aktuellen SerpApi-Kunden gehören **Apple, Shopify und GrubHub**.\
Weitere Informationen findest du in ihrem [**blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Du kannst [**hier**](https://serpapi.com/users/sign_up) ein **kostenloses Konto erstellen**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** schult dich in offensiver Mobile- und AI-Security, unterrichtet von aktiven Forschern – demselben Team hinter den CVE-Writeups und Talks auf Black Hat, HITB und Zer0con. Die Kurse sind im eigenen Tempo absolvierbar, basieren auf Labs an realen Zielen und werden durch eine praxisnahe Zertifizierung ergänzt.

Der Katalog umfasst zwei Tracks:

**Mobile Security** – iOS und Android von der App-Schicht abwärts: Reverse Engineering mit Ghidra und LLDB, ARM64 exploitation, Kernel-Interna und moderne Mitigations (PAC, MTE, SELinux), Jailbreak- und Rooting-Mechaniken.

**AI Security** – zwei vollständige Kurse, die das Feld abdecken. Practical AI Security behandelt, wie LLMs, RAG-Pipelines, AI agents und MCP funktionieren und wie man sie angreift und verteidigt. Advanced AI Security geht an die Frontlinie und ist stark build-orientiert: Red teaming von AI systems im großen Maßstab mit Garak und PyRIT, Ausnutzen von MCP-Servern, Platzieren und Erkennen von model backdoors sowie Fine-Tuning-Angriffe und -Abwehr auf Apple Silicon.

Kurse und Zertifizierungen:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** ist eine AI-powered security platform, um ausnutzbare Schwachstellen zu finden, bevor Angreifer es tun.

**Code security tip**: Melde dich für NaxusAI an, eine smarte Plattform zur Schwachstellenüberwachung, entwickelt für Entwickler und Security-Teams! Mach heute mit und nutze AI, um **reale Sicherheitsrisiken zu erkennen, zu validieren und zu beheben, bevor sie in die Produktion gelangen**!

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit** dabei hilft, sich gegen die neuesten Cybersecurity-Bedrohungen zu **schützen**, indem es **offensive-security services** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Security-Unternehmen mit Niederlassungen in Amsterdam und Wyoming. Sie bieten **all-in-one security services** an, was bedeutet, dass sie alles machen: Pentesting, **Security** Audits, Awareness-Trainings, Phishing-Kampagnen, Code Review, Exploit Development, Outsourcing von Security-Experten und vieles mehr.

Ein weiteres cooles Ding an WebSec ist, dass sie im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in ihre Fähigkeiten** sind, so sehr, dass sie **die beste Ergebnisqualität garantieren**; auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos schau dir ihre [**website**](https://websec.net/en/) und ihren [**blog**](https://websec.net/blog/) an!

Zusätzlich zu den oben genannten Punkten ist WebSec auch ein **engagierter Unterstützer von HackTricks**.

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektive Cybersecurity-Schulungen, entwickelt und geleitet von
Branchenexperten. Ihre Programme gehen über Theorie hinaus, um Teams mit tiefem
Verständnis und umsetzbaren Fähigkeiten auszustatten, mithilfe von maßgeschneiderten Umgebungen, die reale
Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneiderten Schulungen kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihre Schulungen auszeichnet:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Services für **Education**- und **FinTech**-
Institutionen, mit Fokus auf **penetration testing, cloud security assessments** und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP- und CISSP-
zertifizierte Fachleute**, die tiefes technisches Fachwissen und branchenübliche Einblicke in
jedes Engagement einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, intelligence-driven testing**, zugeschnitten auf
Umgebungen mit hohem Risiko. Vom Schutz von Schülerdaten bis zur Absicherung finanzieller Transaktionen
helfen wir Organisationen, das zu verteidigen, was am wichtigsten ist.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bleib informiert und auf dem neuesten Stand in Sachen Cybersecurity, indem du unseren [**blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere AI-driven insights, das fortschrittliche Security-Framework und die intuitive CloudMaps GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Vertrauen zu handeln.

Außerdem ist K8Studio **kompatibel mit allen wichtigen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## License & Disclaimer

Siehe sie in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
