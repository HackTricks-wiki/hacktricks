# Risques liés à l'IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp a identifié les top 10 des vulnérabilités du machine learning qui peuvent affecter les systèmes IA. Ces vulnérabilités peuvent conduire à divers problèmes de sécurité, notamment le data poisoning, le model inversion et les adversarial attacks. Comprendre ces vulnérabilités est crucial pour construire des systèmes IA sécurisés.

Pour une liste mise à jour et détaillée des top 10, référez‑vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaquant ajoute de minuscules modifications, souvent invisibles, aux données entrantes (**incoming data**) afin que le modèle prenne la mauvaise décision.\
*Example*: Quelques éclaboussures de peinture sur un panneau stop trompent une voiture autonome en lui faisant "voir" un panneau de limitation de vitesse.

- **Data Poisoning Attack**: L’ensemble d’entraînement (**training set**) est délibérément pollué avec des échantillons corrompus, apprenant au modèle des règles nuisibles.\
*Example*: Des binaires malware sont étiquetés à tort comme "benign" dans un corpus d'entraînement d'un antivirus, permettant à des malwares similaires de passer inaperçus plus tard.

- **Model Inversion Attack**: En sondant les sorties, un attaquant construit un modèle inverse capable de reconstruire des caractéristiques sensibles des entrées d’origine.\
*Example*: Recréer l’image IRM d’un patient à partir des prédictions d’un modèle de détection du cancer.

- **Membership Inference Attack**: L’adversaire teste si un enregistrement spécifique (**specific record**) a été utilisé durant l’entraînement en repérant des différences de confiance.\
*Example*: Confirmer qu’une transaction bancaire d’une personne apparaît dans les données d’entraînement d’un modèle de détection de fraude.

- **Model Theft**: Des requêtes répétées permettent à un attaquant d’apprendre les frontières de décision et de **cloner le comportement du modèle** (et la propriété intellectuelle).\
*Example*: Récupérer suffisamment de paires Q&A depuis une API ML‑as‑a‑Service pour construire un modèle local quasi‑équivalent.

- **AI Supply‑Chain Attack**: Compromettre n’importe quel composant (données, librairies, poids pré‑entraînés, CI/CD) dans la pipeline ML pour corrompre les modèles en aval.\
*Example*: Une dépendance empoisonnée sur un model‑hub installe un modèle backdoorisé d’analyse de sentiment dans de nombreuses applications.

- **Transfer Learning Attack**: Une logique malveillante est implantée dans un modèle pré‑entraîné (**pre‑trained model**) et survit au fine‑tuning sur la tâche de la victime.\
*Example*: Un backbone vision avec un trigger caché continue d’inverser les labels après adaptation pour l’imagerie médicale.

- **Model Skewing**: Des données subtilement biaisées ou mal étiquetées déplacent les sorties du modèle (**shifts the model's outputs**) pour favoriser l’agenda de l’attaquant.\
*Example*: Injecter des emails spam "propres" étiquetés comme ham pour qu’un filtre anti‑spam laisse passer des emails similaires à l’avenir.

- **Output Integrity Attack**: L’attaquant **altère les prédictions du modèle en transit**, pas le modèle lui‑même, trompant ainsi les systèmes en aval.\
*Example*: Transformer le verdict "malicious" d’un classifieur malware en "benign" avant que l’étape de quarantaine ne voie le fichier.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle** eux‑mêmes, souvent après avoir obtenu un accès en écriture, pour altérer le comportement.\
*Example*: Ajuster des poids sur un modèle de détection de fraude en production pour que les transactions de certaines cartes soient toujours approuvées.


## Google SAIF Risks

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google décrit divers risques associés aux systèmes IA :

- **Data Poisoning**: Des acteurs malveillants modifient ou injectent des données d’entraînement/tuning pour dégrader la précision, implanter des backdoors ou biaiser les résultats, sapant l’intégrité du modèle à travers tout le cycle de vie des données.

- **Unauthorized Training Data**: Ingestion de jeux de données sous copyright, sensibles ou non autorisés créant des responsabilités légales, éthiques et de performance parce que le modèle apprend à partir de données qu’il n’était pas autorisé à utiliser.

- **Model Source Tampering**: Manipulation de la supply‑chain ou par un insider du code du modèle, des dépendances ou des poids avant ou pendant l’entraînement pouvant intégrer une logique cachée qui persiste même après retraining.

- **Excessive Data Handling**: Des contrôles faibles de rétention et de gouvernance des données poussent les systèmes à stocker ou traiter plus de données personnelles que nécessaire, augmentant l’exposition et le risque de conformité.

- **Model Exfiltration**: Des attaquants volent des fichiers/poids du modèle, causant une perte de propriété intellectuelle et permettant des services imitateurs ou des attaques ultérieures.

- **Model Deployment Tampering**: Des adversaires modifient les artefacts du modèle ou l’infrastructure de serving pour que le modèle en exécution diffère de la version validée, modifiant potentiellement le comportement.

- **Denial of ML Service**: Submerger les APIs ou envoyer des entrées « sponge » peut épuiser le compute/l’énergie et mettre le modèle hors ligne, reproduisant des attaques DoS classiques.

- **Model Reverse Engineering**: En récoltant un très grand nombre de paires entrée‑sortie, les attaquants peuvent cloner ou distiller le modèle, alimentant des produits d’imitation et des attaques adversariales personnalisées.

- **Insecure Integrated Component**: Des plugins vulnérables, agents ou services en amont permettent aux attaquants d’injecter du code ou d’escalader des privilèges dans la pipeline IA.

- **Prompt Injection**: Construire des prompts (directement ou indirectement) pour faire passer des instructions qui remplacent l’intention système, forçant le modèle à exécuter des commandes non prévues.

- **Model Evasion**: Des entrées soigneusement conçues déclenchent une mauvaise classification, des hallucinations ou la sortie de contenus interdits, érodant la sécurité et la confiance.

- **Sensitive Data Disclosure**: Le modèle révèle des informations privées ou confidentielles issues de ses données d’entraînement ou du contexte utilisateur, violant la vie privée et les régulations.

- **Inferred Sensitive Data**: Le modèle déduit des attributs personnels jamais fournis, créant de nouveaux préjudices de confidentialité par inférence.

- **Insecure Model Output**: Des réponses non filtrées transmettent du code dangereux, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions**: Des agents intégrés de façon autonome exécutent des opérations réelles non souhaitées (écritures de fichiers, appels API, achats, etc.) sans supervision utilisateur adéquate.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes IA. Elle catégorise diverses techniques d’attaque et tactiques que les adversaires peuvent utiliser contre des modèles IA et aussi comment utiliser des systèmes IA pour réaliser différentes attaques.


## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Des attaquants volent des jetons de session actifs ou des credentials d’API cloud et invoquent des LLM payants hébergés dans le cloud sans autorisation. L’accès est souvent revendu via des reverse proxies qui font front pour le compte du locataire victime, par ex. des déploiements "oai-reverse-proxy". Les conséquences incluent perte financière, usage abusif du modèle hors des politiques, et attribution au tenant victime.

TTPs:
- Harvest tokens depuis des machines de développeurs infectées ou des navigateurs ; voler des secrets CI/CD ; acheter des cookies leakés.
- Déployer un reverse proxy qui forwarde les requêtes vers le provider légitime, masquant la clé upstream et multiplexant de nombreux clients.
- Abuser des base‑model endpoints directs pour bypasser les enterprise guardrails et les quotas.

Mitigations:
- Lier les tokens au fingerprint device, aux plages IP et à l’attestation client ; imposer des expirations courtes et refreshs avec MFA.
- Scoper les clés au minimum nécessaire (pas d’accès outils, read‑only quand applicable) ; rotate en cas d’anomalie.
- Terminer tout le trafic côté serveur derrière une policy gateway qui applique des filtres de sécurité, des quotas par route et l’isolation des tenants.
- Monitorer les patterns d’usage inhabituels (pics de dépense soudains, régions atypiques, UA strings) et auto‑révoquer les sessions suspectes.
- Préférer mTLS ou des JWT signés émis par votre IdP plutôt que des API keys statiques long‑lived.

## Self-hosted LLM inference hardening

Exploiter un serveur LLM local pour des données confidentielles crée une surface d’attaque différente des APIs cloud : les endpoints d’inference/debug peuvent leak des prompts, la stack de serving expose souvent un reverse proxy, et les nœuds GPU donnent accès à de larges surfaces `ioctl()`. Si vous évaluez ou déployez un service d’inférence on‑prem, passez au moins en revue les points suivants.

### Prompt leakage via debug and monitoring endpoints

Considérez l’API d’inférence comme un **service sensible multi‑utilisateur**. Les routes de debug ou de monitoring peuvent exposer le contenu des prompts, l’état des slots, les métadonnées du modèle ou des informations sur les queues internes. Dans `llama.cpp`, l’endpoint `/slots` est particulièrement sensible parce qu’il expose l’état par slot et n’est destiné qu’à l’inspection/gestion des slots.

- Placez un reverse proxy devant le serveur d’inférence et **deny by default**.
- N’autorisez en allowlist que les combinaisons exactes méthode HTTP + path nécessaires au client/UI.
- Désactivez les endpoints d’introspection dans le backend lui‑même autant que possible, par exemple `llama-server --no-slots`.
- Liezz le reverse proxy à `127.0.0.1` et exposez‑le via un transport authentifié comme le SSH local port forwarding au lieu de le publier sur le LAN.

Exemple d'allowlist avec nginx:
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

Si le daemon d'inférence prend en charge l'écoute sur un socket UNIX, privilégiez cela plutôt que TCP et lancez le conteneur avec **aucune pile réseau** :
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
Avantages:
- `--network none` supprime l'exposition TCP/IP entrante/sortante et évite les user-mode helpers dont les rootless containers auraient autrement besoin.
- Un socket UNIX vous permet d'utiliser les permissions/ACLs POSIX sur le chemin du socket comme première couche de contrôle d'accès.
- `--userns=keep-id` et rootless Podman réduisent l'impact d'un container breakout parce que container root n'est pas host root.
- Les montages de modèle en lecture seule réduisent le risque d'altération du modèle depuis l'intérieur du conteneur.

### Minimisation des nœuds de périphérique GPU

Pour l'inférence reposant sur GPU, les fichiers `/dev/nvidia*` sont des surfaces d'attaque locales de grande valeur car ils exposent de larges gestionnaires `ioctl()` du driver et potentiellement des chemins partagés de gestion de mémoire GPU.

- Ne laissez pas `/dev/nvidia*` accessible en écriture par tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACLs afin que seul l'UID mappé du conteneur puisse les ouvrir.
- Mettez en liste noire les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d'inférence headless.
- Préchargez uniquement les modules requis au démarrage au lieu de laisser le runtime les `modprobe` opportunément lors du démarrage de l'inférence.

Exemple:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un point important à vérifier est **`/dev/nvidia-uvm`**. Même si la charge de travail n'utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent quand même exiger `nvidia-uvm`. Parce que ce périphérique est partagé et gère la gestion de la mémoire virtuelle GPU, considérez-le comme une surface d'exposition des données entre locataires. Si le backend d'inférence le supporte, un backend Vulkan peut être un compromis intéressant car il peut éviter d'exposer `nvidia-uvm` au conteneur.

### Confinement LSM pour les workers d'inférence

AppArmor/SELinux/seccomp should be used as defense in depth around the inference process:

- Autoriser uniquement les bibliothèques partagées, les chemins des modèles, le répertoire des sockets, et les nœuds de périphérique GPU qui sont réellement requis.
- Refuser explicitement les capacités à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio`, et `sys_ptrace`.
- Garder le répertoire des modèles en lecture seule et limiter les chemins inscriptibles aux seuls répertoires de socket/cache d'exécution.
- Surveiller les journaux de refus car ils fournissent une télémétrie de détection utile lorsque le model server ou une charge utile post-exploitation tente d'échapper à son comportement attendu.

Exemple de règles AppArmor pour un worker supporté par GPU:
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
## Références
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Deep-dive into the deployment of an on-premise low-privileged LLM server](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets: podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [CNCF Container Device Interface (CDI) specification](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
