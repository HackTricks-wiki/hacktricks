# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logotypy i motion design HackTricks autorstwa_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Uruchom HackTricks lokalnie
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
Twoja lokalna kopia HackTricks będzie **available at [http://localhost:3337](http://localhost:3337)** za mniej niż 5 minut (trzeba zbudować książkę, bądź cierpliwy).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) to świetna firma zajmująca się cybersecurity, której slogan to **HACK THE UNHACKABLE**. Prowadzą własne badania i rozwijają własne narzędzia, aby **oferować kilka wartościowych usług w zakresie cybersecurity** takich jak pentesting, Red teams i szkolenia.

Możesz sprawdzić ich **blog** na [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** wspiera również otwarte projekty cybersecurity takie jak HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) to najważniejsze wydarzenie z zakresu cybersecurity w **Hiszpanii** i jedno z najważniejszych w **Europie**. Z **misją promowania wiedzy technicznej**, ten kongres jest wrzącym punktem spotkań dla profesjonalistów technologii i cybersecurity we wszystkich dyscyplinach.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** to **Europe's #1** ethical hacking and bug bounty platform.

**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), aby w prosty sposób budować i **automatyzować workflowy** napędzane przez najbardziej **zaawansowane** narzędzia społecznościowe na świecie.

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

**SerpApi** oferuje szybkie i łatwe API w czasie rzeczywistym do **dostępu do wyników wyszukiwarek**. Scrape'ują wyszukiwarki, obsługują proxy, rozwiązują captchy i parsują wszystkie bogate, strukturalne dane za Ciebie.

Subskrypcja jednego z planów SerpApi daje dostęp do ponad 50 różnych API do scrape'owania różnych wyszukiwarek, w tym Google, Bing, Baidu, Yahoo, Yandex i innych.\
W przeciwieństwie do innych dostawców, **SerpApi doesn’t just scrape organic results**. Odpowiedzi SerpApi regularnie zawierają wszystkie reklamy, inline images and videos, knowledge graphs oraz inne elementy i funkcje obecne w wynikach wyszukiwania.

Obecni klienci SerpApi to między innymi **Apple, Shopify i GrubHub**.\
Po więcej informacji sprawdź ich [**blog**](https://serpapi.com/blog/)**,** lub wypróbuj przykład w ich [**playground**](https://serpapi.com/playground)**.**\
Możesz **utworzyć darmowe konto** [**tutaj**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Naucz się technologii i umiejętności potrzebnych do prowadzenia vulnerability research, penetration testing i reverse engineering, aby chronić aplikacje mobilne i urządzenia. **Opanuj iOS i Android security** dzięki naszym kursom on-demand i **zdobądź certyfikat**:

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) to profesjonalna firma cybersecurity z siedzibą w **Amsterdamie**, która pomaga **chronić** firmy **na całym świecie** przed najnowszymi zagrożeniami dzięki świadczeniu **offensive-security services** z **nowoczesnym** podejściem.

WebSec to międzynarodowa firma security z biurami w Amsterdamie i Wyoming. Oferują **all-in-one security services**, co oznacza, że robią wszystko; Pentesting, **Security** Audyty, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing i wiele więcej.

Kolejną fajną rzeczą w WebSec jest to, że w przeciwieństwie do średniej w branży WebSec jest **bardzo pewny swoich umiejętności**, do tego stopnia, że **gwarantuje najlepsze wyniki**, jak podają na swojej stronie "**If we can't hack it, You don't pay it!**". Po więcej informacji zobacz ich [**website**](https://websec.net/en/) i [**blog**](https://websec.net/blog/)!

Dodatkowo WebSec jest również **zaangażowanym sponsorem HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) opracowuje i dostarcza skuteczne szkolenia z zakresu cybersecurity tworzone i prowadzone przez
ekspertów z branży. Ich programy wykraczają poza teorię, wyposażając zespoły w głębokie
zrozumienie i praktyczne umiejętności, wykorzystując niestandardowe środowiska odzwierciedlające realne
zagrożenia. W przypadku zapytań o szkolenia szyte na miarę, skontaktuj się z nami [**tutaj**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Co wyróżnia ich szkolenia:**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions dostarcza wyspecjalizowane usługi cybersecurity dla instytucji z sektora **Edukacja** i **FinTech**, ze szczególnym uwzględnieniem **penetration testing, cloud security assessments**, oraz
**compliance readiness** (SOC 2, PCI-DSS, NIST). Nasz zespół obejmuje profesjonalistów z certyfikatami **OSCP i CISSP**, wnosząc głęboką wiedzę techniczną i standardowe branżowe spojrzenie do
każdego projektu.

Idziemy dalej niż automatyczne skany, oferując **manual, intelligence-driven testing** dostosowane do
środowisk o wysokim ryzyku. Od zabezpieczania rekordów studentów po ochronę transakcji finansowych,
pomagamy organizacjom bronić tego, co najważniejsze.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Bądź na bieżąco z najnowszymi informacjami z cybersecurity odwiedzając nasz [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE umożliwia DevOps, DevSecOps i deweloperom efektywne zarządzanie, monitorowanie i zabezpieczanie klastrów Kubernetes. Wykorzystaj nasze AI-driven insights, zaawansowany security framework i intuicyjne CloudMaps GUI, aby wizualizować swoje klastry, zrozumieć ich stan i działać z pewnością.

Co więcej, K8Studio jest **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Sprawdź je w:

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
