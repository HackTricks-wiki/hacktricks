# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos et motion design de Hacktricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Votre copie locale de HackTricks sera **disponible à l'adresse [http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (le livre doit être généré, soyez patient).

Si vous disposez de Docker Compose, vous pouvez également exécuter la commande suivante depuis la racine du dépôt :
```bash
docker compose up
```
Ce service utilise le fichier `docker-compose.yml` inclus pour servir votre copie locale à l’adresse [http://localhost:3337](http://localhost:3337) avec rechargement en direct.

## Partenaires HackTricks

---

## Amis de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Elle effectue ses propres recherches et développe ses propres hacking tools afin d’**offrir plusieurs services de cybersécurité précieux**, tels que le pentesting, les Red teams et la formation.

Vous pouvez consulter leur **blog** à l’adresse [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme de ethical hacking et de bug bounty n° 1 en Europe.**

**Conseil bug bounty** : **inscrivez-vous** sur **Intigriti**, une **bug bounty platform premium créée par des hackers, pour des hackers** ! Rejoignez-nous dès aujourd’hui à l’adresse [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et commencez à gagner des bounties allant jusqu’à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une **formation pratique en AI Security** avec une **approche de laboratoire pratique axée sur l’ingénierie**. Nos cours sont conçus pour les security engineers, les professionnels de l’AppSec et les développeurs qui souhaitent **construire, casser et sécuriser de véritables applications propulsées par l’AI/LLM**.

La **certification AI Security** se concentre sur les compétences du monde réel, notamment :
- Sécurisation des applications propulsées par les LLM et l’AI
- Threat modeling pour les systèmes AI
- Embeddings, bases de données vectorielles et sécurité de RAG
- Attaques contre les LLM, scénarios d’abus et défenses pratiques
- Modèles de conception sécurisés et considérations liées au déploiement

Tous les cours sont **à la demande**, **axés sur les labs** et conçus autour des **compromis de sécurité du monde réel**, et pas uniquement de la théorie.

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs rapides et simples en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils scrappent les moteurs de recherche, gèrent les proxies, résolvent les captchas et analysent toutes les données structurées enrichies pour vous.

Un abonnement à l’un des forfaits de SerpApi comprend l’accès à plus de 50 APIs différentes pour scraper différents moteurs de recherche, notamment Google, Bing, Baidu, Yahoo, Yandex et bien d’autres.\
Contrairement aux autres fournisseurs, **SerpApi ne se contente pas de scraper les résultats organiques**. Les réponses de SerpApi incluent systématiquement toutes les publicités, images et vidéos intégrées, knowledge graphs ainsi que les autres éléments et fonctionnalités présents dans les résultats de recherche.

Les clients actuels de SerpApi comprennent **Apple, Shopify et GrubHub**.\
Pour plus d’informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** vous forme à la sécurité offensive mobile et AI, avec des cours dispensés par des chercheurs actifs – la même équipe que celle à l’origine des rapports de CVE et des conférences à Black Hat, HITB et Zer0con. Les cours sont à votre rythme, s’appuient sur des labs ciblant des systèmes réels et sont accompagnés d’une certification pratique.

Le catalogue comprend deux parcours :

**Mobile Security** – iOS et Android, de la couche applicative aux couches les plus basses : reverse engineering avec Ghidra et LLDB, exploitation ARM64, fonctionnement interne des kernels et mitigations modernes (PAC, MTE, SELinux), mécanismes de jailbreak et de rooting.

**AI Security** – deux cours complets couvrant le domaine. Practical AI Security explique le fonctionnement des LLM, des pipelines RAG, des AI agents et de MCP, ainsi que la manière de les attaquer et de les défendre. Advanced AI Security adopte une approche intensive de construction à la frontière du domaine : red teaming de systèmes AI à grande échelle avec Garak et PyRIT, exploitation de serveurs MCP, implantation et détection de backdoors de modèles, ainsi que fine-tuning des attaques et des défenses sur Apple Silicon.

Cours et certifications :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** est une plateforme de sécurité propulsée par l’AI qui permet de trouver les vulnérabilités exploitables avant les attaquants.

**Conseil de sécurité du code** : inscrivez-vous sur NaxusAI, une plateforme intelligente de surveillance des vulnérabilités conçue pour les développeurs et les équipes de sécurité ! Rejoignez-nous dès aujourd’hui et commencez à utiliser l’AI pour **détecter, valider et corriger les risques de sécurité réels avant leur mise en production** !

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam**, qui aide à **protéger** les entreprises **partout dans le monde** contre les dernières menaces de cybersécurité en fournissant des **services de sécurité offensive** avec une approche **moderne**.

WebSec est une entreprise internationale de sécurité possédant des bureaux à Amsterdam et dans le Wyoming. Elle propose des **services de sécurité tout-en-un**, ce qui signifie qu’elle prend tout en charge : Pentesting, audits de **Security**, formations de sensibilisation, campagnes de phishing, revue de code, développement d’exploits, externalisation d’experts en sécurité et bien plus encore.

Un autre aspect intéressant de WebSec est que, contrairement à la moyenne du secteur, WebSec est **très confiante dans ses compétences**, au point de **garantir des résultats de la meilleure qualité**. Son site indique : "**If we can't hack it, You don't pay it!**". Pour plus d’informations, consultez leur [**site web**](https://websec.net/en/) et leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçue pour le terrain. Conçue autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et dispense des formations efficaces en cybersécurité, conçues et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie afin de doter les équipes d’une compréhension approfondie et de compétences directement applicables, grâce à des environnements personnalisés qui reflètent les menaces du monde réel. Pour toute demande de formation personnalisée, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leurs formations :**
* Contenu et labs créés sur mesure
* Soutenus par des outils et plateformes de premier plan
* Conçus et enseignés par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services spécialisés de cybersécurité aux institutions de l’**Education** et de la **FinTech**, avec un accent sur le **penetration testing, les évaluations de cloud security** et la **préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe comprend des **professionnels certifiés OSCP et CISSP**, qui apportent une expertise technique approfondie et une connaissance conforme aux normes du secteur à chaque mission.

Nous allons au-delà des scans automatisés grâce à des **tests manuels fondés sur le renseignement**, adaptés aux environnements à forts enjeux. De la sécurisation des dossiers des étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_« Une défense de qualité nécessite de connaître l’offensive ; nous assurons la sécurité par la compréhension. »_

Restez informé et à jour des dernières évolutions en cybersécurité en consultant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

L’IDE K8Studio permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Exploitez nos informations fournies par l’AI, notre framework de sécurité avancé et notre interface graphique CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift et bien d’autres).

{{#ref}}
https://k8studio.io/
{{#endref}}

---
## Licence et avertissement

Consultez-les ici :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiques Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)
