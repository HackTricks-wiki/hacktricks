# HackTricks

<figure><img src="images/hacktricks.gif" alt=""><figcaption></figcaption></figure>

_Logos Hacktricks et motion design par_ [_@ppieranacho_](https://www.instagram.com/ppieranacho/)_._

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
docker run -d --rm --platform linux/amd64 -p 3337:3000 --name hacktricks -v $(pwd)/hacktricks:/app ghcr.io/hacktricks-wiki/hacktricks-cloud/translator-image bash -c "mkdir -p ~/.ssh && ssh-keyscan -H github.com >> ~/.ssh/known_hosts && cd /app && git config --global --add safe.directory /app && git checkout $HT_LANG && git pull && MDBOOK_PREPROCESSOR__HACKTRICKS__ENV=dev mdbook serve --hostname 0.0.0.0"
```
Votre copie locale de HackTricks sera disponible à **[http://localhost:3337](http://localhost:3337)** après moins de 5 minutes (le livre doit être compilé, veuillez patienter).

Si vous disposez de Docker Compose, vous pouvez également exécuter la commande suivante depuis la racine du repo :
```bash
docker compose up
```
Ce service utilise le fichier `docker-compose.yml` inclus pour servir la branche actuellement sélectionnée sur l’hôte à l’adresse [http://localhost:3337](http://localhost:3337), avec rechargement automatique. Pour changer de langue avec Compose, sélectionnez la branche correspondant à la langue souhaitée avant de démarrer le service.

## Partenaires HackTricks

---

## Amis de HackTricks

### [STM Cyber](https://www.stmcyber.com)

<figure class="sponsor-logo"><img src="images/stm (1).png" alt=""><figcaption></figcaption></figure>

STM Cyber fournit des services de penetration testing, d’audits de sécurité, d’exploitation et de recherche, ainsi que des outils et des services de sensibilisation à la sécurité. Son site décrit une équipe de penetration testers, de programmeurs et de chercheurs en sécurité disposant de plus de dix ans d’expérience.<sup>[[1]](#references)</sup>

Vous pouvez consulter leur **blog** à l’adresse [**https://blog.stmcyber.com**](https://blog.stmcyber.com).

**STM Cyber** soutient également des projets open source de cybersécurité comme HackTricks :)

---

### [Intigriti](https://www.intigriti.com)

<figure class="sponsor-logo"><img src="images/image (47).png" alt=""><figcaption></figcaption></figure>

Intigriti est un fournisseur de sécurité participative proposant des services de bug bounty et de penetration testing grâce à une communauté mondiale de chercheurs. Sa plateforme combine une couverture bug bounty continue avec des services PTaaS à la demande et des programmes de divulgation de vulnérabilités gérés.<sup>[[2]](#references)</sup>

**Conseil bug bounty** : Rejoignez Intigriti via [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) et explorez ses programmes bug bounty.

---

### [Modern Security – AI & Application Security Training Platform](https://modernsecurity.io/)

<figure class="sponsor-logo"><img src="images/modern_security_logo.png" alt="Modern Security"><figcaption></figcaption></figure>

Modern Security propose des formations pratiques en sécurité de l’AI, à rythme libre, destinées aux security engineers, aux professionnels de l’AppSec et aux développeurs. Sa certification AI Security couvre les fondamentaux des LLM et des agents, le RAG et les bases de données vectorielles, la modélisation des menaces, les attaques par prompt injection et MCP, ainsi que l’architecture défensive.<sup>[[3]](#references)</sup>

👉 Plus de détails sur le cours AI Security :
https://www.modernsecurity.io/courses/ai-security-certification

---

### [SerpApi](https://serpapi.com/)

<figure class="sponsor-logo"><img src="images/image (1254).png" alt=""><figcaption></figcaption></figure>

**SerpApi** fournit des APIs pour Google et d’autres moteurs de recherche, en renvoyant des données SERP structurées avec des fonctionnalités telles que les résultats selon la localisation, Maps, Shopping et Knowledge Graph.<sup>[[4]](#references)</sup>

Pour plus d’informations, consultez leur [**blog**](https://serpapi.com/blog/), essayez un exemple dans leur [**playground**](https://serpapi.com/playground) ou [**créez un compte gratuit**](https://serpapi.com/users/sign_up).

---

### [8kSec Academy – In-Depth Mobile & AI Security Courses](https://academy.8ksec.io/)

<figure class="sponsor-logo"><img src="images/image (2).png" alt=""><figcaption></figcaption></figure>

**8kSec Academy** propose des formations à rythme libre sur la sécurité mobile et l’AI. Son catalogue couvre l’audit et le reversing d’applications mobiles avec des outils tels que Ghidra, Frida et LLDB, ainsi que des labs d’attaque et de défense liés à l’AI/LLM.<sup>[[5]](#references)[[6]](#references)</sup>

Consultez le [catalogue de formations 8kSec Academy](https://academy.8ksec.io/).

---

### [NaxusAI – AI Powered Security Scanner](https://www.naxusai.com/)

<figure class="sponsor-logo"><img src="images/logo-naxus.png" alt=""><figcaption></figcaption></figure>

**Naxus** commercialise une plateforme offensive basée sur l’AI qui cartographie le code et l’infrastructure, puis utilise des agents statiques et dynamiques pour trouver et valider les faiblesses exploitables, avec des preuves de concept et des conseils de remédiation.<sup>[[7]](#references)</sup>

**Conseil de sécurité du code** : Découvrez Naxus pour la détection de vulnérabilités centrée sur le code et l’infrastructure.

---

### [WebSec](https://websec.net/)

<figure class="sponsor-logo"><img src="images/websec (1).svg" alt=""><figcaption></figcaption></figure>

WebSec fournit des services de penetration testing, des abonnements de sécurité, de staffing et d’évaluation des vulnérabilités. Son site indique que l’entreprise opère à l’international et couvre la sécurité offensive, la sécurité défensive, ainsi que les activités de gouvernance, de gestion des risques et de conformité.<sup>[[8]](#references)</sup>

Pour plus d’informations, consultez leur [**site web**](https://websec.net/en/) ou leur [**blog**](https://websec.net/blog/).

En plus de ce qui précède, WebSec est également un **soutien engagé de HackTricks.**

---

### [CyberHelmets](https://cyberhelmets.com/courses/?ref=hacktricks)

<figure class="sponsor-logo"><img src="images/cyberhelmets-logo.png" alt="cyberhelmets logo"><figcaption></figcaption></figure>


**Conçu pour le terrain. Conçu autour de vous.**\
[**Cyber Helmets**](https://cyberhelmets.com/?ref=hacktricks) fournit des formations en cybersécurité dirigées par des experts, avec du contenu et des labs conçus sur mesure et basés sur des infrastructures réelles. Ses programmes sont adaptés aux besoins des organisations et couvrent les phases d’évaluation et de mise en œuvre.<sup>[[9]](#references)</sup> Pour toute demande de formation personnalisée, contactez-nous [**ici**](https://cyberhelmets.com/tailor-made-training/?ref=hacktricks).

**Ce qui distingue leurs formations :**
* Contenu et labs conçus sur mesure
* Soutenus par des outils et plateformes de premier plan
* Conçus et enseignés par des professionnels de terrain

---

### [Last Tower Solutions](https://www.lasttowersolutions.com/)

<figure class="sponsor-logo"><img src="images/lasttower.png" alt="lasttower logo"><figcaption></figcaption></figure>

Last Tower Solutions se concentre sur le conseil en cybersécurité pour l’**Education** et la **FinTech**, notamment les évaluations cloud, les tests de pénétration internes et externes, les évaluations des vulnérabilités et l’accompagnement en matière de conformité.<sup>[[10]](#references)</sup>

Restez informé et à jour des dernières actualités en cybersécurité en consultant notre [**blog**](https://www.lasttowersolutions.com/blog).

---

### [K8Studio - The Smarter GUI to Manage Kubernetes.](https://k8studio.io/)

<figure class="sponsor-logo"><img src="images/k8studio.png" alt="k8studio logo"><figcaption></figcaption></figure>

K8Studio est un IDE Kubernetes de bureau doté de la visualisation CloudMaps, de la navigation multi-cluster, de RBAC, de Helm et de vues pour les logs, YAML et le terminal. Le fournisseur indique qu’il se connecte via kubeconfig sans installer d’agents et qu’il prend en charge macOS, Windows, Linux et les clusters air-gapped.<sup>[[11]](#references)</sup>

---

## Licence et clause de non-responsabilité

Consultez l’entrée HackTricks Values & FAQ dans les References ci-dessous.

## Statistiques Github

![HackTricks Github Stats](https://repobeats.axiom.co/api/embed/68f8746802bcf1c8462e889e6e9302d4384f164b.svg)

## References

- [1] [STM Cyber](https://www.stmcyber.com/)
- [2] [Intigriti](https://www.intigriti.com/)
- [3] [Certification AI Security – Modern Security](https://www.modernsecurity.io/courses/ai-security-certification)
- [4] [SerpApi](https://serpapi.com/)
- [5] [8kSec Academy](https://academy.8ksec.io/)
- [6] [Sécurité pratique de l’AI : attaques, défenses et applications](https://academy.8ksec.io/course/practical-ai-security)
- [7] [Naxus](https://www.naxusai.com/)
- [8] [WebSec](https://websec.net/)
- [9] [Cyber Helmets](https://cyberhelmets.com/)
- [10] [Last Tower Solutions](https://www.lasttowersolutions.com/)
- [11] [K8Studio](https://k8studio.io/)
- [12] [Parrainage Intigriti HackTricks](https://go.intigriti.com/hacktricks)
- [13] [Modern Security](https://modernsecurity.io/)
- [14] [Vidéo de sponsoring WebSec](https://www.youtube.com/watch?v=Zq2JycGDCPM)
- [15] [Formations Cyber Helmets](https://cyberhelmets.com/courses/?ref=hacktricks)
- [16] [HackTricks Values & FAQ](welcome/hacktricks-values-and-faq.md)
{{#include banners/hacktricks-training.md}}
