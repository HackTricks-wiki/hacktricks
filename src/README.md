# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo Hacktricks et motion design par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Exécuter HackTricks en local
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
Your local copy of HackTricks will be **disponible sur [http://localhost:3337](http://localhost:3337)** after <5 minutes (it needs to build the book, be patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente société de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils réalisent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services de cybersécurité de grande valeur** comme pentesting, Red teams et formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme de bug bounty et de hacking éthique n°1 en Europe.**

**Astuce bug bounty** : **inscrivez-vous** sur **Intigriti**, une plateforme premium de **bug bounty créée par des hackers, pour des hackers** ! Rejoignez-nous dès aujourd'hui sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et commencez à gagner des récompenses pouvant aller jusqu'à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bug bounty !

- **Hacking Insights:** Interagissez avec du contenu qui explore le frisson et les défis du hacking
- **Actualités de hacking en temps réel:** Restez à jour dans le monde du hacking au rythme rapide grâce à des actualités et des analyses en temps réel
- **Dernières annonces:** Restez informé des nouveaux bug bounties lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez dès aujourd'hui à collaborer avec les meilleurs hackers !

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une **formation pratique à la sécurité de l’IA** avec une approche **d’ingénierie d’abord, axée sur des labs pratiques**. Nos cours sont conçus pour les ingénieurs sécurité, les professionnels AppSec et les développeurs qui veulent **construire, casser et sécuriser de vraies applications alimentées par l’IA/LLM**.

La **AI Security Certification** se concentre sur des compétences concrètes, notamment :
- Sécuriser les applications LLM et alimentées par l’IA
- Modélisation des menaces pour les systèmes d’IA
- Embeddings, bases de données vectorielles et sécurité RAG
- Attaques LLM, scénarios d’abus et défenses pratiques
- Schémas de conception sécurisés et considérations de déploiement

Tous les cours sont **à la demande**, **centrés sur des labs**, et conçus autour de **compromis de sécurité réels**, pas seulement de la théorie.

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des API rapides et simples en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils collectent les moteurs de recherche, gèrent les proxies, résolvent les captchas et analysent toutes les données enrichies structurées pour vous.

Un abonnement à l’un des plans SerpApi inclut l’accès à plus de 50 API différentes pour collecter différents moteurs de recherche, notamment Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d’autres fournisseurs, **SerpApi ne se contente pas de collecter les résultats organiques**. Les réponses de SerpApi incluent systématiquement toutes les annonces, les images et vidéos intégrées, les knowledge graphs et les autres éléments et fonctionnalités présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify et GrubHub**.\
Pour plus d’informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences nécessaires pour effectuer de la recherche de vulnérabilités, du pentesting et de la rétro-ingénierie afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** est une plateforme de sécurité alimentée par l’IA pour trouver des vulnérabilités exploitables avant les attaquants.

**Conseil sécurité du code** : inscrivez-vous à NaxusAI, une plateforme intelligente de surveillance des vulnérabilités conçue pour les développeurs et les équipes sécurité ! Rejoignez-nous aujourd’hui et commencez à utiliser l’IA pour **détecter, valider et corriger de vrais risques de sécurité avant qu’ils n’atteignent la production** !

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une société professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** les entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **services de sécurité offensive** avec une approche **moderne**.

WebSec est une société de sécurité internationale avec des bureaux à Amsterdam et au Wyoming. Ils proposent des **services de sécurité tout-en-un**, ce qui signifie qu’ils font tout ; Pentesting, audits de **sécurité**, formations de sensibilisation, campagnes de phishing, revue de code, développement d’exploits, externalisation d’experts sécurité et bien plus encore.

Une autre chose sympa à propos de WebSec est que, contrairement à la moyenne du secteur, WebSec est **très confiant dans ses compétences**, à tel point qu’ils **garantissent des résultats de la meilleure qualité** ; leur site indique "**Si nous ne pouvons pas le hacker, vous ne payez pas !**". Pour plus d’infos, jetez un œil à leur [**site web**](https://websec.net/en/) et à leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçu pour le terrain. Conçu autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et propose des formations efficaces en cybersécurité, conçues et animées par
des experts du secteur. Leurs programmes vont au-delà de la théorie pour doter les équipes d’une compréhension approfondie et de compétences actionnables, en utilisant des environnements personnalisés qui reflètent les
menaces du monde réel. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leur formation :**
* Contenu et labs conçus sur mesure
* Appuyés par des outils et plateformes de premier plan
* Conçus et enseignés par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services spécialisés de cybersécurité pour les institutions **d’éducation** et **FinTech**,
avec un focus sur le **pentesting, les évaluations de sécurité cloud**, et la
**préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe comprend des **professionnels certifiés OSCP et CISSP**,
apportant une expertise technique approfondie et une vision conforme aux standards du secteur à
chaque mission.

Nous allons au-delà des analyses automatisées avec des tests **manuels et guidés par le renseignement**, adaptés aux
environnements à enjeux élevés. De la sécurisation des dossiers étudiants à la protection des transactions financières,
nous aidons les organisations à défendre ce qui compte le plus.

_“Une défense de qualité exige de connaître l’offensive ; nous fournissons la sécurité par la compréhension.”_

Restez informé et à jour avec les dernières nouveautés en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Exploitez nos analyses pilotées par l’IA, notre cadre de sécurité avancé et notre interface graphique CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift et plus).

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
