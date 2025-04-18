# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks-Logos & Motion Design von_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Führen Sie HackTricks lokal aus
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
# "hi" for Hindi
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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git checkout $LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Your local copy of HackTricks will be **verfügbar unter [http://localhost:3337](http://localhost:3337)** nach <5 Minuten (es muss das Buch erstellen, haben Sie Geduld).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) ist ein großartiges Cybersicherheitsunternehmen, dessen Slogan **HACK THE UNHACKABLE** ist. Sie führen eigene Forschungen durch und entwickeln eigene Hacking-Tools, um **verschiedene wertvolle Cybersicherheitsdienste** wie Pentesting, Red Teams und Schulungen anzubieten.

Sie können ihren **Blog** unter [**https://blog.stmcyber.com**](https://blog.stmcyber.com) einsehen.

**STM Cyber** unterstützt auch Open-Source-Projekte im Bereich Cybersicherheit wie HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) ist die relevanteste Cybersicherheitsveranstaltung in **Spanien** und eine der wichtigsten in **Europa**. Mit **der Mission, technisches Wissen zu fördern**, ist dieser Kongress ein brodelnder Treffpunkt für Technologie- und Cybersicherheitsexperten in jeder Disziplin.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** ist die **Nummer 1 in Europa** für ethisches Hacking und **Bug-Bounty-Plattform.**

**Bug-Bounty-Tipp**: **Melden Sie sich an** bei **Intigriti**, einer Premium-**Bug-Bounty-Plattform, die von Hackern für Hacker erstellt wurde**! Schließen Sie sich uns heute unter [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) an und beginnen Sie, Belohnungen von bis zu **100.000 $** zu verdienen!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um Workflows einfach zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.

Zugang heute erhalten:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Treten Sie dem [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) Server bei, um mit erfahrenen Hackern und Bug-Bounty-Jägern zu kommunizieren!

- **Hacking Insights:** Engagieren Sie sich mit Inhalten, die in die Aufregung und Herausforderungen des Hackens eintauchen
- **Echtzeit-Hack-Nachrichten:** Bleiben Sie auf dem Laufenden über die schnelllebige Welt des Hackens durch Echtzeitnachrichten und Einblicke
- **Neueste Ankündigungen:** Bleiben Sie informiert über die neuesten Bug-Bounties und wichtige Plattform-Updates

**Treten Sie uns auf** [**Discord**](https://discord.com/invite/N3FrSbmwdy) bei und beginnen Sie noch heute mit der Zusammenarbeit mit Top-Hackern!

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - Das essentielle Toolkit für Penetrationstests

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Erhalten Sie die Perspektive eines Hackers auf Ihre Webanwendungen, Netzwerke und Cloud**

**Finden und melden Sie kritische, ausnutzbare Schwachstellen mit echtem Geschäftsauswirkungen.** Verwenden Sie unsere 20+ benutzerdefinierten Tools, um die Angriffsfläche zu kartieren, Sicherheitsprobleme zu finden, die Ihnen ermöglichen, Berechtigungen zu eskalieren, und automatisierte Exploits zu verwenden, um wesentliche Beweise zu sammeln, die Ihre harte Arbeit in überzeugende Berichte verwandeln.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** bietet schnelle und einfache Echtzeit-APIs, um **auf Suchmaschinenergebnisse** zuzugreifen. Sie scrapen Suchmaschinen, verwalten Proxys, lösen Captchas und parsen alle strukturierten Daten für Sie.

Ein Abonnement eines der SerpApi-Pläne umfasst den Zugriff auf über 50 verschiedene APIs zum Scrapen verschiedener Suchmaschinen, einschließlich Google, Bing, Baidu, Yahoo, Yandex und mehr.\
Im Gegensatz zu anderen Anbietern **scrapt SerpApi nicht nur organische Ergebnisse**. Die Antworten von SerpApi enthalten konsequent alle Anzeigen, Inline-Bilder und Videos, Wissensgraphen und andere Elemente und Funktionen, die in den Suchergebnissen vorhanden sind.

Aktuelle SerpApi-Kunden sind **Apple, Shopify und GrubHub**.\
Für weitere Informationen besuchen Sie ihren [**Blog**](https://serpapi.com/blog/)**,** oder probieren Sie ein Beispiel in ihrem [**Playground**](https://serpapi.com/playground)**.**\
Sie können **hier ein kostenloses Konto erstellen** [**hier**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Detaillierte Mobile Security Kurse](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Lernen Sie die Technologien und Fähigkeiten, die erforderlich sind, um Schwachstellenforschung, Penetrationstests und Reverse Engineering durchzuführen, um mobile Anwendungen und Geräte zu schützen. **Meistern Sie die Sicherheit von iOS und Android** durch unsere On-Demand-Kurse und **lassen Sie sich zertifizieren**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) ist ein professionelles Cybersicherheitsunternehmen mit Sitz in **Amsterdam**, das **Unternehmen auf der ganzen Welt** hilft, sich gegen die neuesten Bedrohungen der Cybersicherheit zu schützen, indem es **offensive Sicherheitsdienste** mit einem **modernen** Ansatz anbietet.

WebSec ist ein internationales Sicherheitsunternehmen mit Büros in Amsterdam und Wyoming. Sie bieten **All-in-One-Sicherheitsdienste** an, was bedeutet, dass sie alles abdecken; Pentesting, **Sicherheits**-Audits, Awareness-Trainings, Phishing-Kampagnen, Code-Überprüfungen, Exploit-Entwicklung, Outsourcing von Sicherheitsexperten und vieles mehr.

Ein weiterer cooler Aspekt von WebSec ist, dass WebSec im Gegensatz zum Branchendurchschnitt **sehr zuversichtlich in ihre Fähigkeiten ist**, so sehr, dass sie **die besten Qualitätsresultate garantieren**, es steht auf ihrer Website: "**Wenn wir es nicht hacken können, zahlen Sie nicht!**". Für weitere Informationen werfen Sie einen Blick auf ihre [**Website**](https://websec.net/en/) und [**Blog**](https://websec.net/blog/)!

Zusätzlich zu den oben genannten ist WebSec auch ein **engagierter Unterstützer von HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) ist eine Suchmaschine für Datenverletzungen (leak). \
Wir bieten eine zufällige Zeichenfolgen-Suche (wie Google) über alle Arten von Datenlecks, groß und klein – nicht nur die großen – über Daten aus mehreren Quellen. \
Menschen-Suche, KI-Suche, Organisationssuche, API (OpenAPI) Zugriff, dieHarvester-Integration, alle Funktionen, die ein Pentester benötigt.\
**HackTricks bleibt eine großartige Lernplattform für uns alle und wir sind stolz darauf, sie zu sponsern!**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

## License & Disclaimer

Überprüfen Sie sie in:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
