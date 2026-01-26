# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos & motion design par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Lancer HackTricks localement
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
Votre copie locale de HackTricks sera **available at [http://localhost:3337](http://localhost:3337)** après <5 minutes (il doit construire le livre, soyez patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils effectuent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services de cybersécurité précieux** comme pentesting, Red teams et formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) est l'événement de cybersécurité le plus important en **Spain** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir le savoir technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la plateforme d'ethical hacking et de bug bounty n°1 en Europe.

**Bug bounty tip** : inscrivez-vous sur **Intigriti**, une plateforme de bug bounty premium créée par des hackers, pour des hackers ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des récompenses jusqu'à **$100,000** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire facilement et **automatiser des workflows** propulsés par les outils communautaires les **plus avancés** au monde.

Get Access Today:

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bug bounty !

- **Hacking Insights:** Consultez du contenu qui explore le frisson et les défis du hacking
- **Real-Time Hack News:** Restez à jour avec l'actualité du monde du hacking en temps réel
- **Latest Announcements:** Soyez informé des nouveaux bug bounties lancés et des mises à jour cruciales de la plateforme

**Join us on** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une formation pratique en AI Security avec une approche lab axée sur l'ingénierie et hands-on. Nos cours sont conçus pour les security engineers, AppSec professionals et développeurs qui veulent **construire, casser et sécuriser des applications réelles propulsées par AI/LLM**.

The **AI Security Certification** focuses on real-world skills, including:
- Sécurisation des applications LLM et AI-powered
- Modélisation des menaces pour les systèmes AI
- Embeddings, vector databases et sécurité RAG
- Attaques LLM, scénarios d'abus et défenses pratiques
- Patrons de conception sécurisés et considérations de déploiement

Tous les cours sont **on-demand**, **lab-driven**, et conçus autour des compromis de sécurité du monde réel, pas seulement de la théorie.

👉 More details on the AI Security course:
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs rapides et faciles en temps réel pour **accéder aux search engine results**. Ils scrappent les moteurs de recherche, gèrent les proxies, résolvent les captchas et parsèment toutes les données structurées riches pour vous.

Un abonnement à l'un des plans de SerpApi inclut l'accès à plus de 50 APIs différentes pour scraper différents moteurs de recherche, y compris Google, Bing, Baidu, Yahoo, Yandex, et plus.\
Contrairement à d'autres fournisseurs, **SerpApi ne se contente pas de scraper les résultats organiques**. Les réponses SerpApi incluent systématiquement toutes les publicités, images et vidéos inline, knowledge graphs, et autres éléments présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify, and GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences nécessaires pour effectuer de la vulnerability research, penetration testing, et reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours on-demand et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à protéger les entreprises **all over the world** contre les dernières menaces de cybersécurité en fournissant des **offensive-security services** avec une approche **moderne**.

WebSec est une société de sécurité internationale avec des bureaux à Amsterdam et Wyoming. Ils offrent des **all-in-one security services** ce qui signifie qu'ils couvrent tout ; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing et bien plus encore.

Une autre chose intéressante à propos de WebSec est que contrairement à la moyenne de l'industrie, WebSec a **beaucoup de confiance en ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats**, il est indiqué sur leur site "**If we can't hack it, You don't pay it!**". Pour plus d'infos, consultez leur [**website**](https://websec.net/en/) et leur [**blog**](https://websec.net/blog/)!

En plus de ce qui précède, WebSec est aussi un **supporter engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


Built for the field. Built around you.\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et propose des formations en cybersécurité efficaces, construites et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour fournir aux équipes une compréhension approfondie et des compétences actionnables, en utilisant des environnements personnalisés qui reflètent les menaces du monde réel. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**What sets their training apart:**
* Contenu et labs sur mesure
* Soutenu par des outils et plateformes de premier ordre
* Conçu et enseigné par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services de cybersécurité spécialisés pour les institutions **Education** et **FinTech**, en se concentrant sur penetration testing, cloud security assessments, et la préparation à la conformité (SOC 2, PCI-DSS, NIST). Notre équipe comprend des professionnels certifiés **OSCP and CISSP**, apportant une expertise technique approfondie et une vision conforme aux standards du secteur à chaque mission.

Nous allons au-delà des scans automatisés avec des tests manuels, basés sur le renseignement, adaptés aux environnements à enjeux élevés. De la sécurisation des dossiers étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Restez informé et à jour avec les dernières actualités en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux DevOps, DevSecOps et développeurs de gérer, surveiller et sécuriser efficacement des clusters Kubernetes. Profitez de nos insights pilotés par l'IA, d'un cadre de sécurité avancé et d'une interface CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

## License & Disclaimer

Consultez-les ici :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
