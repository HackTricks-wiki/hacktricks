# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos et motion design de_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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

Votre copie locale de HackTricks sera **disponible à [http://localhost:3337](http://localhost:3337)** dans < 5 minutes (la compilation du livre prend un peu de temps, veuillez patienter).

Sinon, si vous disposez de Docker Compose, vous pouvez simplement exécuter la commande suivante depuis la racine du dépôt :

```bash
docker compose up
```

Ce service utilise le fichier `docker-compose.yml` fourni pour servir la branche actuellement extraite sur l’hôte à l’adresse [http://localhost:3337](http://localhost:3337), avec rechargement à chaud. Pour changer de langue avec Compose, extrayez la branche de la langue souhaitée avant de démarrer le service.

## Partenaires HackTricks

---

## Amis de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber fournit des services de tests d’intrusion, d’audits de sécurité, d’exploits et de recherche, des outils ainsi que des services de sensibilisation à la sécurité. Son site présente une équipe de testeurs d’intrusion, de programmeurs et de chercheurs en sécurité qui cumule plus de dix ans d’expérience.<sup>[[1]](#references)</sup>

Vous pouvez consulter leur **blog** à l’adresse [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti est un fournisseur de sécurité participative qui propose des services de bug bounty et de tests d’intrusion grâce à une communauté mondiale de chercheurs. Sa plateforme associe une couverture continue de bug bounty à des services PTaaS à la demande et à des programmes gérés de divulgation des vulnérabilités.<sup>[[2]](#references)</sup>

**Conseil bug bounty** : Rejoignez Intigriti via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et découvrez ses programmes de bug bounty.

---

### [Modern Security – Plateforme de formation à la sécurité de l’IA et des applications](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose des formations pratiques en sécurité de l’IA, à suivre à votre rythme, destinées aux ingénieurs en sécurité, aux professionnels AppSec et aux développeurs. Sa certification en sécurité de l’IA couvre les fondamentaux des LLM et des agents, le RAG et les bases de données vectorielles, la modélisation des menaces, les attaques par prompt injection et MCP, ainsi que l’architecture défensive.<sup>[[3]](#references)</sup>

👉 Plus d’informations sur la formation en sécurité de l’IA :  
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fournit des API pour Google et d’autres moteurs de recherche, qui renvoient des données SERP structurées avec des fonctionnalités telles que les résultats géolocalisés, Maps, Shopping et le Knowledge Graph.<sup>[[4]](#references)</sup>

Pour en savoir plus, consultez leur [**blog**](https://serpapi.com/blog/), essayez un exemple dans leur [**environnement de test**](https://serpapi.com/playground) ou [**créez un compte gratuit**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – Formations approfondies en sécurité mobile et IA](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** propose des formations en sécurité mobile et IA, à suivre à votre rythme. Son catalogue couvre l’audit et le reverse engineering d’applications mobiles avec des outils comme Ghidra, Frida et LLDB, ainsi que des laboratoires d’attaque et de défense de l’IA et des LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consultez le [catalogue des formations de 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – Scanner de sécurité propulsé par l’IA](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** présente une plateforme d’IA offensive qui cartographie le code et l’infrastructure, puis utilise des agents statiques et dynamiques pour trouver et valider des faiblesses exploitables, avec des preuves de concept et des conseils de remédiation.<sup>[[7]](#references)</sup>

**Conseil en sécurité du code** : Découvrez Naxus pour rechercher des vulnérabilités dans le code et l’infrastructure.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec fournit des services de tests d’intrusion, des abonnements de sécurité, des services de recrutement et des évaluations de vulnérabilités. Son site indique que l’entreprise exerce ses activités à l’international et couvre la sécurité offensive, la sécurité défensive ainsi que la gouvernance, la gestion des risques et la conformité.<sup>[[8]](#references)</sup>

Pour en savoir plus, consultez leur [**site web**](https://websec.net/en/) ou leur [**blog**](https://websec.net/blog/).

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçues pour le terrain. Conçues pour vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) propose des formations en cybersécurité animées par des experts, avec des contenus et des laboratoires conçus sur mesure et fondés sur des infrastructures réelles. Ses programmes sont adaptés aux besoins des organisations et couvrent toutes les étapes, de l’évaluation à la mise en œuvre.<sup>[[9]](#references)</sup> Pour toute demande de formation personnalisée, contactez-les [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Les atouts de leurs formations :**
* Contenus et laboratoires conçus sur mesure
* S’appuient sur des outils et plateformes de premier ordre
* Conçues et enseignées par des praticiens

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se spécialise dans le conseil en cybersécurité pour les secteurs de l’**éducation** et de la **FinTech**, notamment les évaluations cloud, les tests d’intrusion internes et externes, les évaluations de vulnérabilités et l’accompagnement en matière de conformité.<sup>[[10]](#references)</sup>

Restez informé des dernières actualités en cybersécurité en consultant notre [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - L’interface graphique plus intelligente pour gérer Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio est un IDE Kubernetes pour ordinateur de bureau offrant la visualisation CloudMaps, la navigation multi-cluster, RBAC, Helm, ainsi que des vues pour les journaux, YAML et le terminal. Le fournisseur indique que l’outil se connecte via kubeconfig sans installer d’agents et prend en charge macOS, Windows, Linux et les clusters isolés d’Internet.<sup>[[11]](#references)</sup>

---

## Licence et avertissement

Consultez l’entrée HackTricks Values & FAQ dans les références ci-dessous.

## Statistiques GitHub

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
- [11] [K8Studio](https://k8studio.io/)
- [12] [Parrainage HackTricks Intigriti](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vidéo de parrainage WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Formations Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [Valeurs et FAQ de HackTricks](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
