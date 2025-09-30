# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Hacktricks logos et motion design par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)._ 

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
Votre copie locale de HackTricks sera **available at [http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (il doit construire le livre, soyez patient).

## Sponsors Corporatifs

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils réalisent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services cybersécurité de grande valeur** tels que pentesting, Red teams et formations.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient aussi des projets open source en cybersécurité comme HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) est l'événement de cybersécurité le plus important en **Espagne** et l'un des plus influents en **Europe**. Avec **la mission de promouvoir le savoir-faire technique**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité de toutes disciplines.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la plateforme de bug bounty n°1 en Europe et dédiée à l'ethical hacking.

**Bug bounty tip** : **inscrivez-vous** sur **Intigriti**, une plateforme premium de bug bounty créée par des hackers, pour des hackers ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) dès aujourd'hui, et commencez à gagner des primes jusqu'à **$100,000** !

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

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour échanger avec des hackers expérimentés et des chasseurs de bug bounty !

- **Hacking Insights :** Participez à du contenu qui explore l'excitation et les défis du hacking
- **Real-Time Hack News :** Restez à jour avec l'actualité du monde du hacking en temps réel
- **Latest Announcements :** Soyez informé des derniers bug bounties lancés et des mises à jour cruciales des plateformes

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec des hackers de haut niveau dès aujourd'hui !

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - The essential penetration testing toolkit

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez le point de vue d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact réel sur l'entreprise.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, détecter des problèmes de sécurité permettant une escalation de privilèges, et utiliser des exploits automatisés pour collecter des preuves essentielles, transformant votre travail en rapports convaincants.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs rapides et faciles en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils scrappent les moteurs de recherche, gèrent les proxies, résolvent les captchas et parsèment toutes les données structurées riches pour vous.

Un abonnement à l'un des plans de SerpApi inclut l'accès à plus de 50 APIs différentes pour scraper différents moteurs de recherche, y compris Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d'autres fournisseurs, **SerpApi ne scrappe pas seulement les résultats organiques**. Les réponses SerpApi incluent systématiquement toutes les publicités, images et vidéos en ligne, knowledge graphs et autres éléments présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify, et GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences requises pour mener des recherches de vulnérabilités, du penetration testing et du reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une société professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** des entreprises **dans le monde entier** contre les menaces de cybersécurité les plus récentes en fournissant des **offensive-security services** avec une approche **moderne**.

WebSec est une société de sécurité internationale avec des bureaux à Amsterdam et Wyoming. Ils offrent des **all-in-one security services**, ce qui signifie qu'ils couvrent tout : Pentesting, **Security** Audits, Awareness Trainings, Phishing Campagnes, Code Review, Exploit Development, Security Experts Outsourcing et bien plus.

Autre point positif concernant WebSec : contrairement à la moyenne du secteur, WebSec a **une grande confiance en ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats**, comme indiqué sur leur site : "**If we can't hack it, You don't pay it!**". Pour plus d'infos, consultez leur [**website**](https://websec.net/en/) et leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est également un **sponsor engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [Venacus](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons)

<figure><img src="images/venacus-logo.svg" alt="venacus logo"><figcaption></figcaption></figure>

[**Venacus**](https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons) est un moteur de recherche de data breach (leak). \
Nous offrons une recherche par chaîne aléatoire (comme google) sur tous types de data leaks, grands et petits --pas seulement les gros-- sur des données issues de multiples sources. \
Recherche de personnes, recherche AI, recherche d'organisations, API (OpenAPI) access, intégration theHarvester, toutes les fonctionnalités dont un pentester a besoin.\
**HackTricks reste une excellente plateforme d'apprentissage pour nous tous et nous sommes fiers de la sponsoriser !**

{{#ref}}
https://venacus.com/?utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Built for the field. Built around you.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) conçoit et délivre des formations en cybersécurité efficaces, construites et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour doter les équipes d'une compréhension approfondie et de compétences opérationnelles, en utilisant des environnements personnalisés reflétant des menaces réelles. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leurs formations :**
* Contenu et labs personnalisés
* Soutenu par des outils et plateformes de premier plan
* Conçu et enseigné par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services cybersécurité spécialisés pour les institutions de **Education** et **FinTech**, avec un focus sur le **penetration testing, cloud security assessments**, et la **préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe inclut des professionnels certifiés **OSCP et CISSP**, apportant une expertise technique approfondie et des connaissances conformes aux standards du secteur à chaque mission.

Nous allons au-delà des scans automatisés avec des **tests manuels, basés sur le renseignement**, adaptés à des environnements à enjeux élevés. De la sécurisation des dossiers étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_« Une défense de qualité nécessite de connaître l'offensive, nous apportons la sécurité par la compréhension. »_

Restez informé des dernières actualités en cybersécurité en visitant leur [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux DevOps, DevSecOps et développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Profitez de nos insights pilotés par l'IA, d'un framework de sécurité avancé et de l'interface CloudMaps GUI pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les distributions kubernetes majeures** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift and more).

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
