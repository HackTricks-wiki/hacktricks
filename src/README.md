# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos et motion design de Hacktricks par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

### Exécuter HackTricks localement

```bash
# Download latest version of hacktricks
git clone https://github.com/HackTricks-wiki/hacktricks

# Select the language you want to use
export HT_LANG="master" # Leave master for English
# "af" for Afrikaans
# "de" for German
# "el" for Greek
# "es" for Spanish
# "fr" for French
# "hi" for Hindi
# "it" for Italian
# "ja" for Japanese
# "ko" for Korean
# "pl" for Polish
# "pt" for Portuguese
# "sr" for Serbian
# "sw" for Swahili
# "tr" for Turkish
# "uk" for Ukrainian
# "vi" for Vietnamese
# "zh" for Chinese

# Run the docker container indicating the path to the hacktricks folder
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```

Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** dans moins de 5 minutes (le livre doit être compilé, soyez patient).

Sinon, si vous avez Docker Compose, vous pouvez simplement exécuter la commande suivante depuis la racine du dépôt :

```bash
docker compose up
```

This utilise le fichier `docker-compose.yml` fourni pour servir la branche actuellement extraite sur l’hôte à l’adresse [http://localhost:3337](http://localhost:3337), avec rechargement à chaud. Pour changer de langue avec Compose, extrayez la branche de la langue souhaitée avant de démarrer le service.

## Partenaires HackTricks

---

## Amis HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber propose des tests d’intrusion, des audits de sécurité, des travaux de recherche et d’exploitation, des outils et des services de sensibilisation à la sécurité. Son site présente une équipe de pentesters, de programmeurs et de chercheurs en sécurité comptant plus de dix ans d’expérience.<sup>[[1]](#references)</sup>

Vous pouvez consulter leur **blog** à l’adresse [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti est un fournisseur de sécurité participative qui propose des services de bug bounty et de tests d’intrusion grâce à une communauté mondiale de chercheurs. Sa plateforme associe une couverture continue en bug bounty à des services PTaaS à la demande et à des programmes gérés de divulgation des vulnérabilités.<sup>[[2]](#references)</sup>

**Conseil bug bounty** : Rejoignez Intigriti via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et découvrez ses programmes de bug bounty.

---

### [Modern Security – Plateforme de formation à la sécurité de l’IA et des applications](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose des formations pratiques à son rythme sur la sécurité de l’IA, destinées aux ingénieurs en sécurité, aux professionnels AppSec et aux développeurs. Sa certification en sécurité de l’IA couvre les fondamentaux des LLM et des agents, RAG et les bases de données vectorielles, la modélisation des menaces, les attaques par prompt injection et MCP, ainsi que l’architecture défensive.<sup>[[3]](#references)</sup>

👉 Plus de détails sur le cours de sécurité de l’IA :  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fournit des API pour Google et d’autres moteurs de recherche, qui renvoient des données SERP structurées avec des fonctionnalités comme les résultats géolocalisés, Maps, Shopping et Knowledge Graph.<sup>[[4]](#references)</sup>

Pour en savoir plus, consultez leur [**blog**](https://serpapi.com/blog/), essayez un exemple dans leur [**environnement de test**](https://serpapi.com/playground) ou [**créez un compte gratuit**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Formations approfondies en sécurité mobile et IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** propose des formations à son rythme en sécurité mobile et en sécurité de l’IA. Son catalogue couvre l’audit et la rétro-ingénierie d’applications mobiles à l’aide d’outils tels que Ghidra, Frida et LLDB, ainsi que des ateliers pratiques sur les attaques et les défenses liées à l’IA et aux LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Parcourez le [catalogue de formations de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Sécurité offensive autonome](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt="NaxusAI logo"><figcaption></figcaption></figure>

**Naxus** est une plateforme de sécurité offensive basée sur l’IA qui réalise des analyses complètes de la surface d’attaque externe, des audits d’applications mobiles, des tests web en boîte noire et des revues de code source. Ses agents valident les vulnérabilités exploitables et fournissent des preuves traçables, des exploits de preuve de concept et des mesures correctives concrètes.<sup>[[7]](#references)</sup>

**Conseil d’audit de sécurité** : Utilisez Naxus pour effectuer des audits autonomes de bout en bout des actifs externes, des applications mobiles et web, ainsi que du code source.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec propose des tests d’intrusion, des abonnements de sécurité, des services de recrutement et des évaluations de vulnérabilité. Son site indique que l’entreprise exerce ses activités à l’international et couvre la sécurité offensive, la sécurité défensive ainsi que la gouvernance, la gestion des risques et la conformité.<sup>[[8]](#references)</sup>

Pour en savoir plus, consultez leur [**site web**](https://websec.net/en/) ou leur [**blog**](https://websec.net/blog/).

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçue pour le terrain. Conçue autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) propose des formations en cybersécurité dirigées par des experts, avec des contenus et des ateliers pratiques conçus sur mesure et fondés sur des infrastructures réelles. Ses programmes sont adaptés aux besoins des organisations et couvrent toutes les étapes, de l’évaluation à la mise en œuvre.<sup>[[9]](#references)</sup> Pour toute demande de formation personnalisée, contactez-les [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Les atouts de leurs formations :**
* Contenus et ateliers pratiques conçus sur mesure
* S’appuient sur des outils et des plateformes de premier plan
* Conçus et enseignés par des praticiens

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se spécialise dans le conseil en cybersécurité pour les secteurs de l’**éducation** et de la **FinTech**, notamment les évaluations cloud, les tests d’intrusion internes et externes, les évaluations de vulnérabilité et l’accompagnement en matière de conformité.<sup>[[10]](#references)</sup>

Restez informé des dernières actualités en cybersécurité en consultant notre [**blog**](https://www.lasttowersolutions.com/blog).

---

### [Beaki — Une alimentation adaptée à vos besoins](https://www.beaki.app/)

<figure class="sponsor-logo"><img src="images/beaki-logo.png" alt="Beaki logo"><figcaption></figcaption></figure>

**Beaki** est une application personnalisée de scan alimentaire, de comptage des calories et de suivi nutritionnel. Scannez les codes-barres et les rayons des supermarchés, photographiez ou décrivez des repas et des menus de restaurant, et obtenez des scores explicables adaptés à vos objectifs, à votre régime alimentaire, à vos allergies et à votre profil de santé. Beaki suit également les calories et les macronutriments et crée des menus personnalisés avec des listes de courses.<sup>[[11]](#references)</sup>

[**Téléchargez Beaki gratuitement**](https://www.beaki.app/?utm_source=hacktricks&utm_medium=partner&utm_campaign=hacktricks) sur Android ou iPhone.

---

## Licence et avertissement

Consultez l’entrée « Valeurs et FAQ de HackTricks » dans les références ci-dessous.

## Statistiques GitHub de HackTricks

![Statistiques GitHub de HackTricks](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certification en sécurité de l’IA – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Sécurité pratique de l’IA : attaques, défenses et applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [Beaki](https://www.beaki.app/)
- [12] [Parrainage HackTricks Intigriti](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vidéo de sponsoring WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Formations Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valeurs et FAQ de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
