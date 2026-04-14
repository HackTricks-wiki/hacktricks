# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos et design animé de HackTricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (il faut construire le livre, soyez patient).

## Corporate Sponsors

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils mènent leurs propres recherches et développent leurs propres outils de hacking afin d’**offrir plusieurs services de cybersécurité de grande valeur** comme le pentesting, les Red teams et la formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme de ethical hacking et de bug bounty n°1 en Europe.**

**Conseil bug bounty** : **inscrivez-vous** sur **Intigriti**, une plateforme premium de **bug bounty créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) dès aujourd’hui, et commencez à gagner des récompenses allant jusqu’à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour संवादer avec des hackers expérimentés et des bug bounty hunters !

- **Hacking Insights:** Interagissez avec du contenu qui explore l’excitation et les défis du hacking
- **Real-Time Hack News:** Restez à jour sur le monde du hacking qui évolue rapidement grâce à des actualités et des analyses en temps réel
- **Latest Announcements:** Tenez-vous informé des nouveaux bug bounties lancés et des mises à jour essentielles de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez dès aujourd’hui à collaborer avec les meilleurs hackers !

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une **formation pratique en AI Security** avec une **approche laboratoire, axée sur l’ingénierie et très concrète**. Nos cours sont conçus pour les ingénieurs sécurité, les professionnels AppSec et les développeurs qui veulent **construire, casser et sécuriser de vraies applications alimentées par l’AI/LLM**.

La **certification AI Security** se concentre sur des compétences réelles, notamment :
- Sécuriser les applications LLM et alimentées par l’AI
- Threat modeling pour les systèmes AI
- Embeddings, bases de données vectorielles et sécurité RAG
- Attaques LLM, scénarios d’abus et défenses pratiques
- Modèles de conception sécurisés et considérations de déploiement

Tous les cours sont **à la demande**, **orientés laboratoire**, et conçus autour de **compromis de sécurité réels**, pas seulement de la théorie.

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des API rapides et faciles en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils scrappent les moteurs de recherche, gèrent les proxies, résolvent les captchas et analysent pour vous toutes les données structurées enrichies.

Un abonnement à l’un des plans de SerpApi donne accès à plus de 50 API différentes pour scraper divers moteurs de recherche, notamment Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d’autres fournisseurs, **SerpApi ne se contente pas de scraper les résultats organiques**. Les réponses de SerpApi incluent systématiquement toutes les publicités, images et vidéos intégrées, knowledge graphs, ainsi que d’autres éléments et fonctionnalités présents dans les résultats de recherche.

Les clients actuels de SerpApi incluent **Apple, Shopify et GrubHub**.\
Pour plus d’informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et les compétences nécessaires pour effectuer de la recherche de vulnérabilités, du penetration testing et du reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** les entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **services d’offensive-security** avec une approche **moderne**.

WebSec est une société de sécurité internationale avec des bureaux à Amsterdam et dans le Wyoming. Ils proposent des **services de sécurité tout-en-un**, ce qui signifie qu’ils font tout ; Pentesting, audits de **Security**, formations de sensibilisation, campagnes de phishing, revue de code, développement d’exploits, externalisation d’experts sécurité et bien plus encore.

Autre point intéressant à propos de WebSec : contrairement à la moyenne du secteur, WebSec est **très confiant dans ses compétences**, au point de **garantir les meilleurs résultats de qualité** ; il est indiqué sur leur site web : "**If we can't hack it, You don't pay it!**". Pour plus d’informations, consultez leur [**website**](https://websec.net/en/) et leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçus pour le terrain. Conçus autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et dispense des formations efficaces en cybersécurité, conçues et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour doter les équipes d’une compréhension approfondie et de compétences applicables, en utilisant des environnements personnalisés qui reflètent les menaces du monde réel. Pour toute demande de formation personnalisée, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leur formation :**
* Contenu et laboratoires conçus sur mesure
* Soutenu par des outils et plateformes de premier plan
* Conçu et enseigné par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services spécialisés de cybersécurité pour les institutions **d’Éducation** et **FinTech**, avec un accent sur le **penetration testing, cloud security assessments**, et la **préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe comprend des professionnels certifiés **OSCP et CISSP**, apportant une expertise technique approfondie et une vision conforme aux standards du secteur à chaque mission.

Nous allons au-delà des analyses automatisées avec des tests **manuels, guidés par le renseignement**, adaptés aux environnements à enjeux élevés. De la sécurisation des dossiers étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_“Une défense de qualité exige de connaître l’offensive, nous assurons la sécurité par la compréhension.”_

Restez informé et à jour sur les dernières actualités de la cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Exploitez nos analyses pilotées par l’AI, notre framework de sécurité avancé et notre interface CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

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
