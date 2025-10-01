# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos Hacktricks et motion design par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Exécuter HackTricks localement
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
Votre copie locale de HackTricks sera **available at [http://localhost:3337](http://localhost:3337)** après <5 minutes (il doit construire le book, soyez patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils réalisent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services de cybersécurité précieux** comme pentesting, Red teams et training.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source en cybersécurité comme HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir le savoir-faire technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est **Europe's #1** ethical hacking and **bug bounty platform.**

Astuce bug bounty : **sign up** for **Intigriti**, une plateforme bug bounty premium **créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) dès aujourd'hui, et commencez à gagner des bounties jusqu'à **$100,000**!

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** propulsés par les outils communautaires les **plus avancés** au monde.

Obtenez l'accès aujourd'hui :

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des bug bounty hunters !

- **Hacking Insights :** Participez à du contenu qui explore le frisson et les défis du hacking
- **Real-Time Hack News :** Restez à jour avec le monde du hacking via des news et insights en temps réel
- **Latest Announcements :** Soyez informé des nouveaux bug bounties lancés et des mises à jour cruciales des plateformes

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos web apps, votre réseau et le cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact réel sur le business.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité permettant d'escalader des privilèges, et utiliser des exploits automatisés pour collecter des preuves essentielles, transformant votre travail en rapports convaincants.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs en temps réel rapides et faciles pour **accéder aux résultats des moteurs de recherche**. Ils scrappent les moteurs de recherche, gèrent les proxies, résolvent les captchas, et parse toutes les données structurées riches pour vous.

Un abonnement à l'un des plans de SerpApi inclut l'accès à plus de 50 APIs différentes pour scraper différents moteurs de recherche, y compris Google, Bing, Baidu, Yahoo, Yandex, et plus.\
Contrairement à d'autres fournisseurs, **SerpApi ne se contente pas de scraper les résultats organiques**. Les réponses SerpApi incluent systématiquement toutes les annonces, images et vidéos inline, knowledge graphs, et autres éléments et fonctionnalités présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify, et GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **create a free account** [**here**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences requises pour effectuer de la recherche de vulnérabilités, du penetration testing, et du reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours on-demand et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** les entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **offensive-security services** avec une approche **moderne**.

WebSec est une société de sécurité internationale avec des bureaux à Amsterdam et Wyoming. Ils offrent des **all-in-one security services** ce qui signifie qu'ils font tout ; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing et bien plus.

Autre point intéressant concernant WebSec : contrairement à la moyenne de l'industrie, WebSec est **très confiant dans ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats**, comme indiqué sur leur site "**If we can't hack it, You don't pay it!**". Pour plus d'infos, jetez un œil à leur [**website**](https://websec.net/en/) et à leur [**blog**](https://websec.net/blog/)!

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) est un moteur de recherche de data breach (leak). \
Nous fournissons une recherche de chaînes aléatoires (comme google) sur tous types de data leaks, grands et petits --pas seulement les gros-- à partir de données provenant de multiples sources. \
Recherche de personnes, recherche AI, recherche d'organisation, API (OpenAPI) access, intégration theHarvester, toutes les fonctionnalités dont un pentester a besoin.\
**HackTricks continue d'être une excellente plateforme d'apprentissage pour nous tous et nous sommes fiers d'en être sponsor !**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) conçoit et délivre des formations en cybersécurité efficaces, construites et dirigées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour équiper les équipes d'une compréhension approfondie et de compétences actionnables, en utilisant des environnements personnalisés reflétant des menaces réelles. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leurs formations :**
* Custom-built content and labs
* Backed by top-tier tools and platforms
* Designed and taught by practitioners

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services de cybersécurité spécialisés pour les institutions de **l'Education** et de la **FinTech**, avec un focus sur **penetration testing, cloud security assessments**, et **compliance readiness** (SOC 2, PCI-DSS, NIST). Notre équipe inclut des professionnels **certifiés OSCP et CISSP**, apportant une expertise technique approfondie et un aperçu conforme aux standards de l'industrie pour chaque mission.

Nous allons au-delà des scans automatisés avec des **tests manuels, intelligence-driven** adaptés aux environnements à enjeux élevés. De la protection des dossiers étudiants à la sécurisation des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Restez informés et à jour avec les dernières actualités en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.jpg" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux DevOps, DevSecOps et développeurs de gérer, monitorer et sécuriser les clusters Kubernetes efficacement. Profitez de nos insights AI-driven, d'un cadre de sécurité avancé, et d'une GUI CloudMaps intuitive pour visualiser vos clusters, comprendre leur état, et agir en toute confiance.

De plus, K8Studio est **compatible with all major kubernetes distributions** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## License & Disclaimer

Consultez-les dans :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
