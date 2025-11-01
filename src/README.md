# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos et design animé de Hacktricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (le livre doit se construire, soyez patient).

## Sponsors Corporatifs

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils réalisent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services de cybersécurité précieux** tels que pentesting, Red teams et formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient aussi des projets open source de cybersécurité comme HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir le savoir technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans toutes les disciplines.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme n°1 en Europe** d'ethical hacking et **bug bounty platform.**

**Astuce bug bounty** : **inscrivez-vous** sur **Intigriti**, une plateforme premium **bug bounty créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) dès aujourd'hui, et commencez à gagner des bounties jusqu'à **$100,000** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires les plus **avancés** au monde.

Obtenez l'accès aujourd'hui :

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des bug bounty hunters !

- **Hacking Insights :** Accédez à du contenu qui explore le frisson et les défis du hacking
- **Real-Time Hack News :** Restez à jour sur le monde du hacking en rythme rapide grâce à des news et analyses en temps réel
- **Latest Announcements :** Restez informé des nouveaux bug bounties lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers dès aujourd'hui !

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables avec un véritable impact business.** Utilisez nos 20+ outils personnalisés pour cartographier l'attack surface, trouver des problèmes de sécurité permettant d'escalate privileges, et utiliser des automated exploits pour collecter des preuves essentielles, transformant votre travail en rapports convaincants.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs en temps réel, rapides et faciles pour **accéder aux résultats des moteurs de recherche**. Ils scrapent les moteurs de recherche, gèrent les proxies, résolvent les captchas et parsèment toutes les données structurées riches pour vous.

Un abonnement à l'un des plans de SerpApi inclut l'accès à plus de 50 APIs différentes pour scraper différents moteurs de recherche, y compris Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d'autres fournisseurs, **SerpApi ne se contente pas de scraper les résultats organiques**. Les réponses SerpApi incluent systématiquement toutes les annonces, les images et vidéos inline, les knowledge graphs et autres éléments et fonctionnalités présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify, et GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences nécessaires pour effectuer de la vulnerability research, du penetration testing, et du reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à protéger des entreprises **dans le monde entier** contre les dernières menaces en fournissant des **offensive-security services** avec une approche **moderne**.

WebSec est une entreprise de sécurité internationale avec des bureaux à Amsterdam et Wyoming. Ils offrent des **all-in-one security services**, ce qui signifie qu'ils font tout ; Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing et bien plus encore.

Une autre chose intéressante à propos de WebSec est qu'à la différence de la moyenne de l'industrie, WebSec est **très confiant dans ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats**, comme indiqué sur leur site : "**If we can't hack it, You don't pay it!**". Pour plus d'infos, jetez un œil à leur [**site web**](https://websec.net/en/) et à leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) conçoit et délivre des formations en cybersécurité efficaces, construites et dirigées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour fournir aux équipes une compréhension approfondie et des compétences opérationnelles, en utilisant des environnements personnalisés reflétant des menaces réelles. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leurs formations :**
* Contenu et labs sur mesure
* Soutenu par des outils et plateformes de premier ordre
* Conçu et enseigné par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services de cybersécurité spécialisés pour les institutions de **Education** et **FinTech**, avec un focus sur les **penetration testing, cloud security assessments**, et la **compliance readiness** (SOC 2, PCI-DSS, NIST). Notre équipe inclut des professionnels certifiés **OSCP et CISSP**, apportant une expertise technique approfondie et une vision conforme aux standards de l'industrie à chaque intervention.

Nous allons au-delà des scans automatisés avec des **tests manuels, basés sur le renseignement**, adaptés aux environnements à enjeux élevés. De la sécurisation des dossiers étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_“A quality defense requires knowing the offense, we provide security through understanding.”_

Restez informé des dernières actualités en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement des clusters Kubernetes. Profitez de nos insights AI-driven, d'un cadre de sécurité avancé et d'une interface CloudMaps GUI intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift et plus).

{{#ref}}
https://k8studio.io/
{{#endref}}


---

## Licence & Avertissement

Consultez-les dans :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiques Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
