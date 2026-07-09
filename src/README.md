# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos & design animé Hacktricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (il faut construire le livre, soyez patient).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils mènent leurs propres recherches et développent leurs propres outils de hacking pour **proposer plusieurs services de cybersécurité de grande valeur** comme pentesting, Red teams et formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme de bug bounty et de hacking éthique n°1 en Europe.**

**Conseil bug bounty** : **inscrivez-vous** à **Intigriti**, une plateforme premium de **bug bounty créée par des hackers, pour des hackers** ! Rejoignez-nous dès aujourd’hui sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et commencez à gagner des récompenses allant jusqu’à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une **formation pratique à la sécurité IA** avec une **approche en laboratoire, axée sur l’ingénierie**. Nos cours sont conçus pour les ingénieurs sécurité, les professionnels AppSec et les développeurs qui veulent **construire, casser et sécuriser de vraies applications basées sur l’IA/LLM**.

La **certification AI Security** se concentre sur des compétences concrètes, notamment :
- Sécuriser les applications basées sur LLM et IA
- Modélisation des menaces pour les systèmes IA
- Embeddings, bases de données vectorielles et sécurité RAG
- Attaques LLM, scénarios d’abus et défenses pratiques
- Modèles de conception sécurisés et considérations de déploiement

Tous les cours sont **à la demande**, **orientés labo**, et conçus autour de **compromis de sécurité réels**, pas seulement de la théorie.

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des API rapides et simples en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils extraient les moteurs de recherche, gèrent les proxys, résolvent les captchas et analysent toutes les données structurées enrichies pour vous.

Un abonnement à l’un des plans de SerpApi donne accès à plus de 50 API différentes pour extraire différents moteurs de recherche, notamment Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d’autres fournisseurs, **SerpApi ne se contente pas d’extraire les résultats organiques**. Les réponses SerpApi incluent systématiquement toutes les annonces, les images et vidéos intégrées, les knowledge graphs et les autres éléments et fonctionnalités présents dans les résultats de recherche.

Parmi les clients actuels de SerpApi figurent **Apple, Shopify et GrubHub**.\
Pour plus d’informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** vous forme à la sécurité offensive mobile et IA, avec des chercheurs actifs comme formateurs — la même équipe derrière les writeups CVE et les conférences à Black Hat, HITB et Zer0con. Les cours sont à votre rythme, construits autour de labos sur des cibles réelles, et accompagnés d’une certification pratique.

Le catalogue comprend deux parcours :

**Mobile Security** – iOS et Android depuis la couche application jusqu’au bas niveau : reverse engineering avec Ghidra et LLDB, exploitation ARM64, internals du kernel et mitigations modernes (PAC, MTE, SELinux), mécanismes de jailbreak et de rooting.

**AI Security** – deux cours complets couvrant le domaine. Practical AI Security explique comment fonctionnent les LLM, les pipelines RAG, les agents IA et MCP, et comment les attaquer et les défendre. Advanced AI Security va plus loin, côté build : red teaming de systèmes IA à grande échelle avec Garak et PyRIT, exploitation de serveurs MCP, implantation et détection de backdoors de modèles, et attaques et défenses de fine-tuning sur Apple Silicon.

Cours et certifications :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** est une plateforme de sécurité propulsée par l’IA pour trouver des vulnérabilités exploitables avant que les attaquants ne le fassent.

**Conseil sécurité du code** : inscrivez-vous à NaxusAI, une plateforme intelligente de surveillance des vulnérabilités conçue pour les développeurs et les équipes sécurité ! Rejoignez-nous dès aujourd’hui et commencez à utiliser l’IA pour **détecter, valider et corriger de vrais risques de sécurité avant qu’ils n’atteignent la production** !

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** des entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **services de sécurité offensive** avec une approche **moderne**.

WebSec est une entreprise internationale de sécurité avec des bureaux à Amsterdam et au Wyoming. Elle propose des **services de sécurité tout-en-un**, ce qui signifie qu’elle fait tout : Pentesting, audits de **Security**, formations de sensibilisation, campagnes de phishing, revue de code, développement d’exploits, externalisation d’experts en sécurité et bien plus encore.

Autre point sympa à propos de WebSec : contrairement à la moyenne du secteur, WebSec a **une grande confiance en ses compétences**, au point de **garantir des résultats de la meilleure qualité** ; il est indiqué sur leur site web : "**If we can't hack it, You don't pay it!**". Pour plus d’infos, jetez un œil à leur [**website**](https://websec.net/en/) et à leur [**blog**](https://websec.net/blog/) !

En plus de ce qui précède, WebSec est aussi un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçu pour le terrain. Conçu autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et propose des formations efficaces en cybersécurité, conçues et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour donner aux équipes une compréhension approfondie et des compétences actionnables, en utilisant des environnements personnalisés qui reflètent les menaces réelles. Pour des demandes de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leur formation :**
* Contenu et labos sur mesure
* Appuyés par des outils et plateformes de premier plan
* Conçus et enseignés par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions fournit des services spécialisés de cybersécurité pour les institutions d’**Education** et de **FinTech**, avec un focus sur les **tests d’intrusion, les évaluations de sécurité cloud**, et
la **préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe comprend des professionnels **certifiés OSCP et CISSP**, apportant une expertise technique approfondie et un niveau de compréhension conforme aux standards du secteur à
chaque mission.

Nous allons au-delà des scans automatisés avec des **tests manuels, guidés par le renseignement**, adaptés aux environnements à forts enjeux. De la sécurisation des dossiers étudiants à la protection des transactions financières,
nous aidons les organisations à défendre ce qui compte le plus.

_« Une défense de qualité exige de connaître l’attaque ; nous assurons la sécurité par la compréhension. »_

Restez informé et à jour sur les dernières nouveautés en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Exploitez nos analyses pilotées par l’IA, notre cadre de sécurité avancé et notre interface CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift et plus encore).

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
