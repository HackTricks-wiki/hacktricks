# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo et design animé de Hacktricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** après <5 minutes (il faut compiler le livre, soyez patient).

## HackTricks Partners

---

## HackTricks Friends

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils réalisent leurs propres recherches et développent leurs propres outils de hacking pour **proposer plusieurs services de cybersécurité de grande valeur** comme pentesting, Red teams et formation.

Vous pouvez consulter leur **blog** sur [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **plateforme de ethical hacking et de bug bounty n°1 en Europe.**

**Conseil bug bounty** : **inscrivez-vous** à **Intigriti**, une plateforme premium de **bug bounty créée par des hackers, pour des hackers** ! Rejoignez-nous sur [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des récompenses allant jusqu'à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure class="sponsor-logo"><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bug bounty !

- **Hacking Insights:** Interagissez avec du contenu qui explore le frisson et les défis du hacking
- **Real-Time Hack News:** Restez à jour sur le monde rapide du hacking grâce à des actualités et analyses en temps réel
- **Latest Announcements:** Tenez-vous informé des nouveaux bug bounties lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez dès aujourd'hui à collaborer avec les meilleurs hackers !

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose une **formation pratique à la sécurité IA** avec une approche **ingénierie d'abord, orientée laboratoire**. Nos cours sont conçus pour les ingénieurs sécurité, les professionnels AppSec et les développeurs qui veulent **concevoir, casser et sécuriser de vraies applications alimentées par IA/LLM**.

La **certification AI Security** se concentre sur des compétences concrètes, notamment :
- Sécuriser des applications LLM et alimentées par IA
- Threat modeling pour les systèmes IA
- Embeddings, bases de données vectorielles et sécurité RAG
- Attaques LLM, scénarios d'abus et défenses pratiques
- Design patterns sécurisés et considérations de déploiement

Tous les cours sont **à la demande**, **basés sur des laboratoires**, et conçus autour de **compromis de sécurité réels**, pas seulement de la théorie.

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

{{#ref}}
https://modernsecurity.io/
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des APIs rapides et faciles en temps réel pour **accéder aux résultats des moteurs de recherche**. Ils extraient les moteurs de recherche, gèrent les proxies, résolvent les captchas et analysent toutes les données structurées enrichies pour vous.

Un abonnement à l'un des forfaits SerpApi inclut l'accès à plus de 50 APIs différentes pour extraire différents moteurs de recherche, notamment Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d'autres fournisseurs, **SerpApi ne se contente pas d'extraire les résultats organiques**. Les réponses de SerpApi incluent systématiquement toutes les annonces, les images et vidéos intégrées, les knowledge graphs, ainsi que d'autres éléments et fonctionnalités présents dans les résultats de recherche.

Les clients actuels de SerpApi incluent **Apple, Shopify et GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – In-Depth Mobile Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences nécessaires pour effectuer de la recherche de vulnérabilités, du penetration testing et du reverse engineering afin de protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [NaxusAI – AI Powered Security Scanner](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**NaxusAI** est une plateforme de sécurité alimentée par IA pour trouver des vulnérabilités exploitables avant les attaquants.

**Conseil de sécurité du code** : inscrivez-vous à NaxusAI, une plateforme intelligente de surveillance des vulnérabilités conçue pour les développeurs et les équipes sécurité ! Rejoignez-nous aujourd'hui et commencez à utiliser l'IA pour **détecter, valider et corriger de vrais risques de sécurité avant qu'ils n'atteignent la production** !

{{#ref}}
https://naxusai.com
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** des entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **services d'offensive-security** avec une approche **moderne**.

WebSec est une entreprise internationale de sécurité avec des bureaux à Amsterdam et dans le Wyoming. Ils proposent des **services de sécurité tout-en-un**, ce qui signifie qu'ils font tout ; Pentesting, audits de **Security**, formations de sensibilisation, campagnes de phishing, Code Review, développement d'exploits, externalisation d'experts sécurité et bien plus encore.

Autre chose intéressante à propos de WebSec : contrairement à la moyenne du secteur, WebSec est **très confiant dans ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats de qualité** ; leur site indique : "**If we can't hack it, You don't pay it!**". Pour plus d'informations, consultez leur [**website**](https://websec.net/en/) et leur [**blog**](https://websec.net/blog/) !

En plus de cela, WebSec est aussi un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçu pour le terrain. Conçu autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) développe et propose des formations efficaces en cybersécurité, conçues et animées par des experts du secteur. Leurs programmes vont au-delà de la théorie pour doter les équipes d'une compréhension approfondie et de compétences concrètes, en utilisant des environnements personnalisés qui reflètent les menaces du monde réel. Pour toute demande de formation sur mesure, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leur formation :**
* Contenu et laboratoires conçus sur mesure
* Soutenu par des outils et des plateformes de premier plan
* Conçu et enseigné par des praticiens

{{#ref}}
https://cyberhelmets.com/courses/?ref=hacktricks
{{#endref}}

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions propose des services de cybersécurité spécialisés pour les institutions d'**Éducation** et de **FinTech**, avec un accent sur les **penetration testing, cloud security assessments**, et la **préparation à la conformité** (SOC 2, PCI-DSS, NIST). Notre équipe comprend des professionnels certifiés **OSCP et CISSP**, apportant une expertise technique approfondie et une vision conforme aux standards du secteur à chaque mission.

Nous allons au-delà des analyses automatisées avec des **tests manuels, guidés par le renseignement**, adaptés aux environnements à forts enjeux. De la sécurisation des dossiers étudiants à la protection des transactions financières, nous aidons les organisations à défendre ce qui compte le plus.

_“Une défense de qualité exige de connaître l'offensive, nous fournissons la sécurité par la compréhension.”_

Restez informé et à jour des dernières actualités en cybersécurité en visitant notre [**blog**](https://www.lasttowersolutions.com/blog).

{{#ref}}
https://www.lasttowersolutions.com/
{{#endref}}

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio IDE permet aux équipes DevOps, DevSecOps et aux développeurs de gérer, surveiller et sécuriser efficacement les clusters Kubernetes. Exploitez nos analyses pilotées par IA, notre cadre de sécurité avancé et notre interface CloudMaps intuitive pour visualiser vos clusters, comprendre leur état et agir en toute confiance.

De plus, K8Studio est **compatible avec toutes les principales distributions kubernetes** (AWS, GCP, Azure, DO, Rancher, K3s, Openshift et plus).

{{#ref}}
https://k8studio.io/
{{#endref}}

---

<!-- hacktricks-friends:friend:friend-carlospolop:start -->
### [HackTricks Books](https://book.hacktricks.wiki/)

<figure class="sponsor-logo"><img src="https://friends.hacktricks.wiki/assets/17181413/5e15e93e6b8523dac2ad.png" alt="HackTricks Books logo"><figcaption></figcaption></figure>

Ceci est un texte pour présenter le wiki gratuit de cybersécurité : <b>Hacktricks Book </b>. Apprenez dès maintenant gratuitement toutes sortes d'astuces de hacking grâce à lui !

{{#ref}}
https://book.hacktricks.wiki/
{{#endref}}

---
<!-- hacktricks-friends:friend:friend-carlospolop:end -->

## License & Disclaimer

Consultez-les dans :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Github Stats

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
