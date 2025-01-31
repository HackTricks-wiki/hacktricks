# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logo et design animé de Hacktricks par_ [_@ppiernacho_](https://www.instagram.com/ppieranacho/)_._

### Exécuter HackTricks Localement
```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks
# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "cd /app && git config --global --add safe.directory /app && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** après <5 minutes (elle doit construire le livre, soyez patient).

## Sponsors d'entreprise

### [STM Cyber](https://www.stmcyber.com)

<figure><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

[**STM Cyber**](https://www.stmcyber.com) est une excellente entreprise de cybersécurité dont le slogan est **HACK THE UNHACKABLE**. Ils effectuent leurs propres recherches et développent leurs propres outils de hacking pour **offrir plusieurs services de cybersécurité précieux** comme le pentesting, les équipes rouges et la formation.

Vous pouvez consulter leur **blog** à [**https://blog.stmcyber.com**](https://blog.stmcyber.com)

**STM Cyber** soutient également des projets open source en cybersécurité comme HackTricks :)

---

### [RootedCON](https://www.rootedcon.com/)

<figure><img src="images/image (45).png" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com) est l'événement de cybersécurité le plus pertinent en **Espagne** et l'un des plus importants en **Europe**. Avec **la mission de promouvoir les connaissances techniques**, ce congrès est un point de rencontre bouillonnant pour les professionnels de la technologie et de la cybersécurité dans chaque discipline.

{{#ref}}
https://www.rootedcon.com/
{{#endref}}

---

### [Intigriti](https://www.intigriti.com)

<figure><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

**Intigriti** est la **première plateforme** de hacking éthique et de **bug bounty en Europe.**

**Conseil sur les bug bounties** : **inscrivez-vous** sur **Intigriti**, une plateforme de **bug bounty premium créée par des hackers, pour des hackers** ! Rejoignez-nous à [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) aujourd'hui, et commencez à gagner des récompenses allant jusqu'à **100 000 $** !

{{#ref}}
https://go.intigriti.com/hacktricks
{{#endref}}

---

### [Trickest](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)

<figure><img src="images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Utilisez [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) pour construire et **automatiser facilement des workflows** alimentés par les outils communautaires **les plus avancés** au monde.

Accédez dès aujourd'hui :

{{#ref}}
https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks
{{#endref}}

---

### [HACKENPROOF](https://bit.ly/3xrrDrL)

<figure><img src="images/image (3).png" alt=""><figcaption></figcaption></figure>

Rejoignez le serveur [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) pour communiquer avec des hackers expérimentés et des chasseurs de bugs !

- **Aperçus sur le hacking :** Engagez-vous avec du contenu qui explore le frisson et les défis du hacking
- **Actualités de hacking en temps réel :** Restez à jour avec le monde du hacking en rapide évolution grâce à des nouvelles et des aperçus en temps réel
- **Dernières annonces :** Restez informé des nouveaux bug bounties lancés et des mises à jour cruciales de la plateforme

**Rejoignez-nous sur** [**Discord**](https://discord.com/invite/N3FrSbmwdy) et commencez à collaborer avec les meilleurs hackers aujourd'hui !

---

### [Pentest-Tools.com](https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons) - L'outil essentiel de test de pénétration

<figure><img src="images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Obtenez la perspective d'un hacker sur vos applications web, votre réseau et votre cloud**

**Trouvez et signalez des vulnérabilités critiques et exploitables ayant un impact commercial réel.** Utilisez nos 20+ outils personnalisés pour cartographier la surface d'attaque, trouver des problèmes de sécurité qui vous permettent d'escalader les privilèges, et utilisez des exploits automatisés pour collecter des preuves essentielles, transformant votre travail acharné en rapports convaincants.

{{#ref}}
https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons
{{#endref}}

---

### [SerpApi](https://serpapi.com/)

<figure><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** propose des API en temps réel rapides et faciles pour **accéder aux résultats des moteurs de recherche**. Ils extraient des moteurs de recherche, gèrent des proxies, résolvent des captchas et analysent toutes les données structurées riches pour vous.

Un abonnement à l'un des plans de SerpApi inclut l'accès à plus de 50 API différentes pour extraire différents moteurs de recherche, y compris Google, Bing, Baidu, Yahoo, Yandex, et plus encore.\
Contrairement à d'autres fournisseurs, **SerpApi ne se contente pas d'extraire des résultats organiques**. Les réponses de SerpApi incluent systématiquement toutes les annonces, images et vidéos en ligne, graphiques de connaissances, et d'autres éléments et fonctionnalités présents dans les résultats de recherche.

Les clients actuels de SerpApi incluent **Apple, Shopify, et GrubHub**.\
Pour plus d'informations, consultez leur [**blog**](https://serpapi.com/blog/)**,** ou essayez un exemple dans leur [**playground**](https://serpapi.com/playground)**.**\
Vous pouvez **créer un compte gratuit** [**ici**](https://serpapi.com/users/sign_up)**.**

---

### [8kSec Academy – Cours de sécurité mobile approfondis](https://academy.8ksec.io/)

<figure><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

Apprenez les technologies et compétences nécessaires pour effectuer des recherches sur les vulnérabilités, des tests de pénétration et de l'ingénierie inverse pour protéger les applications et appareils mobiles. **Maîtrisez la sécurité iOS et Android** grâce à nos cours à la demande et **obtenez une certification** :

{{#ref}}
https://academy.8ksec.io/
{{#endref}}

---

### [WebSec](https://websec.net/)

<figure><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

[**WebSec**](https://websec.net) est une entreprise professionnelle de cybersécurité basée à **Amsterdam** qui aide à **protéger** les entreprises **dans le monde entier** contre les dernières menaces de cybersécurité en fournissant des **services de sécurité offensive** avec une approche **moderne**.

WebSec est une entreprise de sécurité internationale avec des bureaux à Amsterdam et Wyoming. Ils offrent des **services de sécurité tout-en-un**, ce qui signifie qu'ils font tout ; Pentesting, **Audits** de sécurité, Formations de sensibilisation, Campagnes de phishing, Revue de code, Développement d'exploits, Externalisation d'experts en sécurité et bien plus encore.

Une autre chose intéressante à propos de WebSec est qu'à la différence de la moyenne de l'industrie, WebSec est **très confiant dans ses compétences**, à tel point qu'ils **garantissent les meilleurs résultats de qualité**, comme indiqué sur leur site web "**Si nous ne pouvons pas le hacker, vous ne le payez pas !**". Pour plus d'infos, jetez un œil à leur [**site web**](https://websec.net/en/) et [**blog**](https://websec.net/blog/) !

En plus de cela, WebSec est également un **soutien engagé de HackTricks.**

{{#ref}}
https://www.youtube.com/watch?v=Zq2JycGDCPM
{{#endref}}

## Licence & Avertissement

Vérifiez-les dans :

{{#ref}}
welcome/hacktricks-values-and-faq.md
{{#endref}}

## Statistiques Github

![Statistiques Github de HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

{{#include ./banners/hacktricks-training.md}}
