# Risques liés à l'IA

{{#include ../banners/hacktricks-training.md}}

## Top 10 des vulnérabilités du Machine Learning selon l'OWASP

L'OWASP a identifié les 10 principales vulnérabilités du Machine Learning susceptibles d'affecter les systèmes d'IA. Ces vulnérabilités peuvent entraîner divers problèmes de sécurité, notamment l'empoisonnement des données, l'inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est essentiel pour concevoir des systèmes d'IA sécurisés.

Pour consulter une liste mise à jour et détaillée des 10 principales vulnérabilités du Machine Learning, reportez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Attaque par manipulation des entrées** : Un attaquant ajoute de minuscules modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne une mauvaise décision.\
*Exemple* : Quelques taches de peinture sur un panneau stop trompent une voiture autonome, qui le "voit" comme un panneau de limitation de vitesse.

- **Attaque par empoisonnement des données** : Le **jeu de données d'entraînement** est délibérément contaminé par de mauvais échantillons, ce qui apprend au modèle des règles nuisibles.\
*Exemple* : Des binaires malveillants sont étiquetés à tort comme "bénins" dans un corpus d'entraînement antivirus, permettant à des malwares similaires de passer inaperçus par la suite.

- **Attaque par inversion de modèle** : En sondant les sorties, un attaquant construit un **modèle inverse** qui reconstitue des caractéristiques sensibles des entrées originales.\
*Exemple* : Recréer l'image IRM d'un patient à partir des prédictions d'un modèle de détection du cancer.

- **Attaque par inférence d'appartenance** : L'adversaire vérifie si un **enregistrement spécifique** a été utilisé pendant l'entraînement en repérant des différences de confiance.\
*Exemple* : Confirmer qu'une transaction bancaire d'une personne apparaît dans les données d'entraînement d'un modèle de détection de la fraude.

- **Vol de modèle** : Des requêtes répétées permettent à un attaquant d'apprendre les frontières de décision et de **cloner le comportement du modèle** (ainsi que sa propriété intellectuelle).\
*Exemple* : Collecter suffisamment de paires Q/R auprès d'une API ML-as-a-Service pour créer un modèle local presque équivalent.

- **Attaque de la supply chain de l'IA** : Compromettre n'importe quel composant (données, bibliothèques, poids pré-entraînés, CI/CD) du **pipeline ML** afin de corrompre les modèles en aval.\
*Exemple* : Une dépendance empoisonnée provenant d'un model hub installe un modèle d'analyse des sentiments doté d'une backdoor dans de nombreuses applications.

- **Attaque par Transfer Learning** : Une logique malveillante est implantée dans un **modèle pré-entraîné** et survit au fine-tuning effectué sur la tâche de la victime.\
*Exemple* : Un backbone de vision doté d'un trigger caché continue d'inverser les labels après son adaptation à l'imagerie médicale.

- **Biaisage du modèle** : Des données subtilement biaisées ou mal étiquetées **déplacent les sorties du modèle** afin de favoriser les objectifs de l'attaquant.\
*Exemple* : Injecter des e-mails de spam "propres" étiquetés comme ham afin qu'un filtre anti-spam laisse passer des e-mails futurs similaires.

- **Attaque contre l'intégrité des sorties** : L'attaquant **modifie les prédictions du modèle en transit**, et non le modèle lui-même, afin de tromper les systèmes en aval.\
*Exemple* : Modifier la verdict d'un classificateur de malwares, de "malveillant" à "bénin", avant que l'étape de mise en quarantaine du fichier ne le reçoive.

- **Empoisonnement du modèle** --- Modifications directes et ciblées des **paramètres du modèle** lui-même, souvent après l'obtention d'un accès en écriture, afin d'en modifier le comportement.\
*Exemple* : Modifier les poids d'un modèle de détection de fraude en production afin que les transactions effectuées avec certaines cartes soient toujours approuvées.


## Risques Google SAIF

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google présente différents risques associés aux systèmes d'IA :<sup>[[2]](#references)</sup>

- **Empoisonnement des données** : Des acteurs malveillants modifient ou injectent des données d'entraînement ou de tuning afin de dégrader la précision, d'implanter des backdoors ou de fausser les résultats, compromettant l'intégrité du modèle sur l'ensemble du cycle de vie des données.

- **Données d'entraînement non autorisées** : L'ingestion de jeux de données protégés par le droit d'auteur, sensibles ou non autorisés crée des risques juridiques, éthiques et de performance, car le modèle apprend à partir de données qu'il n'était pas autorisé à utiliser.

- **Altération de la source du modèle** : Une manipulation de la supply chain ou par un initié du code du modèle, des dépendances ou des poids avant ou pendant l'entraînement peut intégrer une logique cachée qui persiste même après un nouvel entraînement.

- **Gestion excessive des données** : Des contrôles faibles de conservation et de gouvernance des données amènent les systèmes à stocker ou traiter davantage de données personnelles que nécessaire, augmentant les risques d'exposition et de non-conformité.

- **Exfiltration du modèle** : Des attaquants volent des fichiers ou poids de modèle, entraînant une perte de propriété intellectuelle et permettant la création de services copies ou de nouvelles attaques.

- **Altération du déploiement du modèle** : Des adversaires modifient les artefacts du modèle ou l'infrastructure de serving afin que le modèle en cours d'exécution diffère de la version validée, ce qui peut en modifier le comportement.

- **Déni de service ML** : Inonder les API ou envoyer des entrées "sponge" peut épuiser les ressources de calcul ou l'énergie et mettre le modèle hors ligne, comme dans les attaques DoS classiques.

- **Reverse engineering du modèle** : En collectant un grand nombre de paires entrée-sortie, les attaquants peuvent cloner ou distiller le modèle, favorisant les produits d'imitation et les attaques adversariales personnalisées.

- **Composant intégré non sécurisé** : Des plugins, agents ou services en amont vulnérables permettent aux attaquants d'injecter du code ou d'escalader leurs privilèges au sein du pipeline d'IA.

- **Prompt Injection** : Concevoir des prompts, directement ou indirectement, afin d'y dissimuler des instructions qui remplacent l'intention du système et amènent le modèle à exécuter des commandes non prévues.

- **Évasion de modèle** : Des entrées soigneusement conçues amènent le modèle à mal classifier, à halluciner ou à produire du contenu interdit, ce qui érode la sécurité et la confiance.

- **Divulgation de données sensibles** : Le modèle révèle des informations privées ou confidentielles issues de ses données d'entraînement ou du contexte utilisateur, en violation de la vie privée et de la réglementation.

- **Données sensibles inférées** : Le modèle déduit des attributs personnels qui n'ont jamais été fournis, créant de nouveaux préjudices pour la vie privée par inférence.

- **Sortie de modèle non sécurisée** : Des réponses non nettoyées transmettent du code dangereux, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Actions malveillantes** : Des agents intégrés de manière autonome exécutent des opérations réelles non prévues (écritures de fichiers, appels API, achats, etc.) sans supervision suffisante de l'utilisateur.

## Matrice Mitre AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d'IA. Elle classe différentes techniques et tactiques d'attaque que les adversaires peuvent utiliser contre les modèles d'IA, ainsi que les façons d'utiliser les systèmes d'IA pour effectuer différentes attaques.<sup>[[3]](#references)</sup>

## LLMJacking (Vol et revente de tokens d'accès à des LLM hébergés dans le cloud)

Les attaquants volent des tokens de session actifs ou des identifiants API cloud et invoquent sans autorisation des LLM payants hébergés dans le cloud. L'accès est souvent revendu via des reverse proxies qui utilisent le compte de la victime, par exemple des déploiements "oai-reverse-proxy". Les conséquences comprennent des pertes financières, une utilisation du modèle en dehors des politiques et une attribution au tenant de la victime.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs :
- Récupérer des tokens sur les machines de développeurs ou les navigateurs infectés ; voler des secrets CI/CD ; acheter des cookies ayant fait l'objet d'un leak.<sup>[[5]](#references)</sup>
- Mettre en place un reverse proxy qui transmet les requêtes au véritable fournisseur, dissimule la clé upstream et multiplexe de nombreux clients.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuser des endpoints de modèles de base directs pour contourner les guardrails d'entreprise et les limites de débit.<sup>[[4]](#references)</sup>

Mesures d'atténuation :
- Lier les tokens à l'empreinte de l'appareil, aux plages d'adresses IP et à l'attestation du client ; imposer des expirations courtes et effectuer le refresh avec MFA.
- Limiter au minimum la portée des clés (aucun accès aux outils, lecture seule le cas échéant) ; effectuer une rotation en cas d'anomalie.
- Faire transiter tout le trafic côté serveur derrière une policy gateway qui applique des filtres de sécurité, des quotas par route et l'isolation des tenants.
- Surveiller les schémas d'utilisation inhabituels (pics soudains de dépenses, régions atypiques, chaînes UA) et révoquer automatiquement les sessions suspectes.
- Préférer mTLS ou des JWT signés émis par votre IdP aux clés API statiques à longue durée de vie.

## Renforcement de la sécurité de l'inférence LLM auto-hébergée

L'exécution d'un serveur LLM local pour des données confidentielles crée une surface d'attaque différente de celle des API hébergées dans le cloud : les endpoints d'inférence et de debug peuvent provoquer un leak de prompts, la stack de serving expose généralement un reverse proxy et les nœuds de périphériques GPU donnent accès à de grandes surfaces `ioctl()`. Si vous évaluez ou déployez un service d'inférence on-premise, examinez au minimum les points suivants.<sup>[[8]](#references)</sup>

### Leak de prompts via les endpoints de debug et de monitoring

Traitez l'API d'inférence comme un **service sensible multi-utilisateur**. Les routes de debug ou de monitoring peuvent exposer le contenu des prompts, l'état des slots, les métadonnées du modèle ou les informations de file d'attente interne. Dans `llama.cpp`, l'endpoint `/slots` est particulièrement sensible, car il expose l'état de chaque slot et est uniquement destiné à l'inspection ou à la gestion des slots.<sup>[[8]](#references)</sup>

- Placer un reverse proxy devant le serveur d'inférence et **refuser par défaut**.
- N'autoriser que les combinaisons exactes méthode HTTP + chemin nécessaires au client ou à l'UI.
- Désactiver les endpoints d'introspection dans le backend lui-même chaque fois que possible, par exemple `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Lier le reverse proxy à `127.0.0.1` et l'exposer via un transport authentifié tel que la redirection de port locale SSH, plutôt que de le publier sur le LAN.

Exemple d'allowlist avec nginx :
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Conteneurs rootless sans réseau et sockets UNIX

Si le daemon d'inférence prend en charge l'écoute sur un socket UNIX, préférez cette option à TCP et exécutez le conteneur avec **aucune pile réseau** :<sup>[[8]](#references)</sup>
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Avantages :
- `--network none` supprime l’exposition TCP/IP entrante/sortante et évite les helpers en mode utilisateur dont les conteneurs rootless auraient autrement besoin.
- Un socket UNIX permet d’utiliser les permissions/ACL POSIX sur le chemin du socket comme première couche de contrôle d’accès.
- `--userns=keep-id` et Podman rootless réduisent l’impact d’une breakout de conteneur, car le root du conteneur n’est pas le root de l’hôte.
- Les montages de modèles en lecture seule réduisent le risque de tampering des modèles depuis l’intérieur du conteneur.

Pour les déploiements persistants, les mêmes restrictions peuvent être exprimées sous forme d’unités Podman Quadlet. Si l’accès au GPU est délégué via le Container Device Interface, gardez la spécification du périphérique CDI aussi limitée que possible au lieu d’exposer chaque nœud d’accélérateur.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Minimisation des nœuds de périphériques GPU

Pour l’inférence utilisant un GPU, les fichiers `/dev/nvidia*` constituent des surfaces d’attaque locales à haute valeur, car ils exposent de grands gestionnaires `ioctl()` du pilote ainsi que des chemins potentiellement partagés de gestion de la mémoire GPU.<sup>[[8]](#references)</sup>

- Ne laissez pas `/dev/nvidia*` accessibles en écriture à tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACL afin que seul l’UID mappé du conteneur puisse les ouvrir.
- Mettez sur liste noire les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d’inférence headless.
- Préchargez uniquement les modules requis au démarrage au lieu de laisser le runtime exécuter opportunément `modprobe` pendant le démarrage de l’inférence.

Exemple :
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un point important à vérifier est **`/dev/nvidia-uvm`**. Même si la workload n'utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent toujours nécessiter `nvidia-uvm`. Comme ce device est partagé et gère la mémoire virtuelle du GPU, considérez-le comme une surface d'exposition de données cross-tenant. Si l'inference backend le prend en charge, un backend Vulkan peut constituer un compromis intéressant, car il peut éviter d'exposer `nvidia-uvm` au container.<sup>[[8]](#references)</sup>

### Confinement LSM pour les workers d'inférence

AppArmor/SELinux/seccomp doivent être utilisés comme défense en profondeur autour du processus d'inférence :<sup>[[8]](#references)</sup>

- N'autorisez que les shared libraries, les chemins des modèles, le répertoire des sockets et les device nodes GPU réellement nécessaires.
- Refusez explicitement les capabilities à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Conservez le répertoire des modèles en lecture seule et limitez les chemins accessibles en écriture aux seuls répertoires des sockets/cache du runtime.
- Surveillez les logs de refus, car ils fournissent une télémétrie de détection utile lorsque le model server ou un payload de post-exploitation tente de s'échapper de son comportement attendu.

Exemple de règles AppArmor pour un worker utilisant un GPU :
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting : les domaines hallucinés par les LLM comme vecteur de supply chain IA

Le phantom squatting est l’**équivalent domaine/URL du slopsquatting**. Au lieu d’halluciner un nom de package inexistant, le LLM hallucine un **domaine de portail, d’API, de webhook, de facturation, de SSO, de téléchargement ou de support** plausible pour une marque réelle, puis un attaquant enregistre cet espace de noms avant qu’un humain ou un agent ne l’utilise.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Cela est important, car dans de nombreux workflows assistés par IA, la sortie du modèle est traitée comme une **dépendance de confiance** :
- Les développeurs copient l’endpoint suggéré dans le code ou les intégrations CI/CD.
- Les agents IA récupèrent automatiquement de la documentation, des schémas, des APK, des ZIP ou des cibles de webhook.
- Les runbooks ou documents générés peuvent intégrer la fausse URL comme si elle faisait autorité.

### Workflow offensif

1. **Sonder la surface d’hallucination** : poser des questions spécifiques à une marque sur des workflows réalistes tels que `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou des portails d’`application mobile`.<sup>[[12]](#references)</sup>
2. **Normaliser les candidats** : résoudre les URLs générées, réduire les réponses NXDOMAIN au domaine parent enregistrable et dédupliquer les familles de prompts. Les corpus de prompts doivent rester diversifiés, par exemple en supprimant les quasi-doublons avec la **similarité de Jaccard**.
3. **Prioriser les hallucinations prévisibles** :
- **Thermal Hallucination Persistence (THP)** : le même faux domaine apparaît à différentes températures, y compris à basse température comme `T=0.1`.
- **Consensus inter-modèles** : plusieurs familles de LLM génèrent le même faux domaine.
4. **Enregistrer et weaponize** le domaine parent, puis héberger du phishing, de faux téléchargements d’APK/ZIP, des voleurs d’identifiants, des documents malveillants ou des endpoints d’API qui collectent des secrets/des payloads de webhook. Les **hallucinations au niveau du domaine uniquement** sont les plus faciles à monétiser, car l’attaquant contrôle tout l’espace de noms ; les hallucinations de sous-domaines/chemins peuvent néanmoins être exploitées lorsque le parent normalisé n’est pas enregistré.
5. **Exploiter la fenêtre de réputation nulle** : les domaines nouvellement enregistrés ne disposent souvent d’aucun historique de blocklist, d’aucune réputation d’URL ni d’une télémétrie mature ; ils peuvent donc contourner les contrôles jusqu’à ce que les détections rattrapent leur retard. Les attaquants peuvent prolonger cette fenêtre avec des réponses bénignes réservées aux crawlers, du redirect cloaking, des barrières CAPTCHA ou une mise en staging différée du payload.

### Pourquoi cela est dangereux pour les agents

Pour une victime humaine, le faux domaine nécessite généralement encore un clic et une autre action. Dans un **workflow agentique**, le LLM peut être à la fois le **leurre** et l’**exécuteur** : l’agent reçoit l’URL hallucinée, la récupère, analyse la réponse et peut ensuite leaker des tokens, exécuter des instructions, télécharger une dépendance ou injecter des données empoisonnées dans le CI/CD sans aucune vérification humaine.<sup>[[12]](#references)</sup>

### Prompts offensifs pratiques

Les prompts à haut rendement ressemblent généralement à des tâches d’entreprise normales plutôt qu’à des leurres de phishing explicites :<sup>[[12]](#references)</sup>
- « Quelle est l’URL du payment sandbox pour les intégrations `<brand>` ? »
- « Quel endpoint de webhook dois-je utiliser pour les notifications de build de `<brand>` ? »
- « Où se trouve le portail employee benefits / billing / SSO de `<brand>` ? »
- « Donne-moi le téléchargement direct de l’APK Android ou du client desktop de `<brand>`. »

### Inversion défensive

Traitez cela comme un problème proactif de surveillance des domaines, et pas seulement comme un problème de prompt injection :<sup>[[12]](#references)</sup>
- Constituer un **corpus de prompts de marques** et sonder périodiquement les LLM sur lesquels vos utilisateurs/agents s’appuient.
- Stocker les URLs hallucinées et suivre celles qui restent stables selon les températures/modèles.
- Suivre l’**Adversarial Exploitation Window (AEW)** : le délai entre la première hallucination et l’enregistrement par l’attaquant. Un AEW positif signifie que les défenseurs peuvent pré-enregistrer, sinkhole ou bloquer préventivement le domaine avant son weaponization.
- Surveiller les transitions **NXDOMAIN → enregistré** pour les domaines parents.
- Lors de l’enregistrement, analyser le registrar, la date de création, les nameservers, la protection de la confidentialité, le contenu de la page, les captures d’écran, le statut de page parquée et la similarité des assets de marque.
- Ajouter des policy gates afin que les agents/développeurs ne **fassent pas confiance par défaut aux domaines générés par les LLM** : exiger des allowlists, une validation de propriété, des contrôles CT/RDAP ou une approbation humaine avant la première utilisation.

Cela relève simultanément de plusieurs catégories de risques IA : **attaque de supply chain IA**, **sortie de modèle non sécurisée** et **actions rogue** lorsque les agents consomment automatiquement l’URL hallucinée.

## References

- [1] [Top 10 des vulnérabilités du Machine Learning selon OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risques](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice des menaces MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Les risques des LLM Code Assistant : contenu nuisible, misuse et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking : des identifiants Cloud volés utilisés dans une nouvelle attaque IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Présentation du schéma LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revente d’accès LLM volé)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analyse approfondie du déploiement d’un serveur LLM on-premise à faibles privilèges](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets Podman : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Spécification CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting : les domaines hallucinés par l’IA comme vecteur de supply chain logicielle](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting : comment les hallucinations IA alimentent une nouvelle catégorie d’attaques de supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
