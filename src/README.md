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
Ihre lokale Kopie von HackTricks wird nach weniger als 5 Minuten unter **[http://localhost:3337](http://localhost:3337)** verfügbar sein (das Buch muss gebaut werden, bitte haben Sie Geduld).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersecurity-Unternehmen, dessen Slogan **HACK THE UNHACKABLE** ist. Sie führen eigene Forschung durch und entwickeln eigene Hacking-Tools, um **mehrere wertvolle Cybersecurity-Dienstleistungen anzubieten**, wie pentesting, Red teams und Schulungen.

Sie können ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) ansehen.

**STM Cyber** unterstützt außerdem Open-Source-Cybersecurity-Projekte wie HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ist die bedeutendste Cybersecurity-Veranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein zentraler Treffpunkt für Technologie- und Cybersecurity-Profis aus allen Disziplinen.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist Europas #1 für ethical hacking und **bug bounty platform.**

**Bug bounty tip**: **Registriere dich** für **Intigriti**, eine Premium-**bug bounty platform created by hackers, for hackers**! Trete uns heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) bei und beginne, Prämien bis zu **$100,000** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Nutze [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und zu automatisieren, die von den weltweit **fortschrittlichsten** Community-Tools angetrieben werden.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Tritt dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und bug bounty hunters zu kommunizieren!

- **Hacking Insights:** Beschäftige dich mit Inhalten, die den Nervenkitzel und die Herausforderungen des Hackens behandeln
- **Real-Time Hack News:** Bleibe durch Echtzeit-Nachrichten und -Einblicke über die schnelllebige Hack-Welt auf dem Laufenden
- **Latest Announcements:** Bleibe informiert über die neuesten bug bounties und wichtige Plattform-Updates

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) und beginne noch heute, mit Top-Hackern zusammenzuarbeiten!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Erhalte die Perspektive eines Hackers auf deine Web-Apps, dein Netzwerk und Cloud**

**Finde und melde kritische, ausnutzbare Schwachstellen mit echtem Geschäftseinfluss.** Nutze unsere über 20 maßgeschneiderten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die dir erlauben, Privilegien zu escalate, und verwende automatisierte Exploits, um wichtige Beweise zu sammeln und deine Arbeit in überzeugende Berichte zu verwandeln.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **Suchmaschinenergebnisse zuzugreifen**. Sie scrapen Suchmaschinen, managen Proxys, lösen Captchas und parsen alle reichhaltigen strukturierten Daten für dich.

Ein Abonnement eines SerpApi-Plans beinhaltet Zugriff auf über 50 verschiedene APIs zum Scrapen unterschiedlicher Suchmaschinen, darunter Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Unterschied zu anderen Anbietern **scrapt SerpApi nicht nur organische Ergebnisse**. SerpApi-Antworten enthalten konsistent alle Anzeigen, Inline-Bilder und -Videos, Knowledge Graphs und andere Elemente und Features, die in den Suchergebnissen vorhanden sind.

Aktuelle SerpApi-Kunden sind **Apple, Shopify und GrubHub**.\
Für mehr Informationen schau dir ihren [**Blog**](https://serpapi.com/blog/)**,** oder probiere ein Beispiel in ihrem [**playground**](https://serpapi.com/playground)**.**\
Du kannst **hier** ein kostenloses Konto erstellen: [**https://serpapi.com/users/sign_up**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lerne die Technologien und Fähigkeiten, die erforderlich sind, um Vulnerability Research, penetration testing und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistere iOS- und Android-Sicherheit** durch unsere On-Demand-Kurse und **erhalte Zertifizierungen**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersecurity-Unternehmen mit Sitz in **Amsterdam**, das Unternehmen **weltweit** dabei hilft, sich gegen die neuesten Cybersecurity-Bedrohungen zu schützen, indem es **Offensive-Security-Dienstleistungen** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **All-in-One-Sicherheitsdienste** an, was bedeutet, dass sie alles abdecken; Pentesting, **Security** Audits, Awareness Trainings, Phishing-Kampagnen, Code Review, Exploit-Entwicklung, Security-Experten-Outsourcing und vieles mehr.

Eine weitere coole Sache an WebSec ist, dass WebSec im Vergleich zum Branchendurchschnitt **sehr selbstsicher in ihren Fähigkeiten** ist, so sehr, dass sie **die besten Qualitätsresultate garantieren**, wie auf ihrer Website steht: "**If we can't hack it, You don't pay it!**". Für mehr Infos, schau dir ihre [**Website**](https://websec.net/en/) und ihren [**Blog**](https://websec.net/blog/) an!

Zusätzlich ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ist eine data breach (leak) search engine. \
Wir bieten Random-String-Suche (wie Google) über alle Arten von data leaks, großen und kleinen -- nicht nur die großen -- über Daten aus mehreren Quellen. \
People search, AI search, organization search, API (OpenAPI) access, theHarvester integration, alle Features, die ein pentester braucht.\
**HackTricks continues to be a great learning platform for us all and we're proud to be sponsoring it!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) entwickelt und liefert effektives Cybersecurity-Training, das von Branchenexperten erstellt und geleitet wird. Ihre Programme gehen über Theorie hinaus und vermitteln Teams tiefgehendes Verständnis und umsetzbare Fähigkeiten, unter Verwendung maßgeschneiderter Umgebungen, die reale Bedrohungen widerspiegeln. Für Anfragen zu maßgeschneidertem Training, kontaktiere uns [**hier**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Was ihr Training auszeichnet:**
* Maßgeschneiderte Inhalte und Labs
* Unterstützt durch erstklassige Tools und Plattformen
* Entworfen und gelehrt von Praktikern

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions bietet spezialisierte Cybersecurity-Dienstleistungen für **Education** und **FinTech**
Institutionen an, mit einem Fokus auf **penetration testing, cloud security assessments**, und
**compliance readiness** (SOC 2, PCI-DSS, NIST). Unser Team umfasst **OSCP und CISSP
zertifizierte Fachkräfte**, die tiefgehende technische Expertise und branchenübliche Einsichten in
jede Zusammenarbeit einbringen.

Wir gehen über automatisierte Scans hinaus mit **manuellem, intelligence-driven Testing**, das auf
hochbrisante Umgebungen zugeschnitten ist. Vom Schutz von Studentendaten bis zur Absicherung finanzieller Transaktionen helfen wir Organisationen, das zu verteidigen, was am wichtigsten ist.

_„Eine qualitativ hochwertige Verteidigung erfordert das Wissen über den Angriff; wir bieten Sicherheit durch Verständnis.“_

Bleibe informiert und auf dem neuesten Stand der Cybersecurity, indem du ihren [**Blog**](https://www.lasttowersolutions.com/blog) besuchst.

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE befähigt DevOps, DevSecOps und Entwickler, Kubernetes-Cluster effizient zu verwalten, zu überwachen und abzusichern. Nutze unsere KI-gestützten Insights, modernes Sicherheitsframework und intuitive CloudMaps-GUI, um deine Cluster zu visualisieren, ihren Zustand zu verstehen und mit Zuversicht zu handeln.

Zudem ist K8Studio **kompatibel mit allen wichtigen kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift und mehr).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Siehe dazu:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
