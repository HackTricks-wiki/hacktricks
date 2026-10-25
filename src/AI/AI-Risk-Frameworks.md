# Risques liés à l’IA

{{#include ../banners/hacktricks-training.md}}

## Top 10 des vulnérabilités du machine learning selon OWASP

OWASP a identifié les 10 principales vulnérabilités du machine learning susceptibles d’affecter les systèmes d’IA. Elles peuvent entraîner divers problèmes de sécurité, notamment l’empoisonnement des données, l’inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est essentiel pour concevoir des systèmes d’IA sécurisés.

Pour consulter la liste détaillée et à jour des 10 principales vulnérabilités du machine learning, reportez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack** : un attaquant apporte de petites modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne une mauvaise décision.\
    *Exemple* : quelques taches de peinture sur un panneau stop trompent une voiture autonome, qui le « voit » comme un panneau de limitation de vitesse.

- **Data Poisoning Attack** : le **jeu d’entraînement** est délibérément contaminé par des exemples malveillants, ce qui apprend au modèle des règles nuisibles.\
*Exemple* : des fichiers binaires de malware sont étiquetés à tort comme « bénins » dans un corpus d’entraînement antivirus, permettant à des malwares similaires de passer inaperçus par la suite.

- **Model Inversion Attack** : en sondant les sorties, un attaquant crée un **modèle inverse** qui reconstitue des caractéristiques sensibles des entrées d’origine.\
*Exemple* : recréer l’image IRM d’un patient à partir des prédictions d’un modèle de détection du cancer.

- **Membership Inference Attack** : l’adversaire cherche à déterminer si un **enregistrement précis** a été utilisé pendant l’entraînement en repérant des différences de confiance.\
*Exemple* : confirmer que les transactions bancaires d’une personne figurent dans les données d’entraînement d’un modèle de détection de fraude.

- **Model Theft** : en interrogeant le modèle à plusieurs reprises, un attaquant peut apprendre ses limites de décision et **cloner son comportement** (ainsi que sa propriété intellectuelle).\
*Exemple* : récupérer suffisamment de paires de questions-réponses auprès d’une API de ML-as-a-Service pour créer un modèle local presque équivalent.

- **AI Supply-Chain Attack** : compromettre un composant quelconque (données, bibliothèques, poids pré-entraînés, CI/CD) du **pipeline ML** pour corrompre les modèles en aval.\
*Exemple* : une dépendance empoisonnée sur un hub de modèles installe un modèle d’analyse des sentiments piégé dans de nombreuses applications.

- **Transfer Learning Attack** : une logique malveillante est intégrée à un **modèle pré-entraîné** et subsiste après son fine-tuning pour la tâche de la victime.\
*Exemple* : un backbone de vision doté d’un déclencheur caché continue de modifier les étiquettes après son adaptation à l’imagerie médicale.

- **Model Skewing** : des données subtilement biaisées ou mal étiquetées **orientent les sorties du modèle** en faveur des objectifs de l’attaquant.\
*Exemple* : injecter des e-mails de spam « propres » étiquetés comme ham afin qu’un filtre anti-spam laisse passer des e-mails similaires par la suite.

- **Output Integrity Attack** : l’attaquant **modifie les prédictions du modèle pendant leur transmission**, sans modifier le modèle lui-même, pour tromper les systèmes en aval.\
*Exemple* : remplacer le verdict « malveillant » d’un classificateur de malware par « bénin » avant que le système de mise en quarantaine du fichier ne le reçoive.

- **Model Poisoning** --- modifications directes et ciblées des **paramètres du modèle**, souvent après l’obtention d’un accès en écriture, afin d’en altérer le comportement.\
*Exemple* : modifier les poids d’un modèle de détection de fraude en production pour que les transactions provenant de certaines cartes soient toujours approuvées.


## Risques du Google SAIF

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google décrit divers risques associés aux systèmes d’IA :<sup>[[2]](#references)</sup>

- **Data Poisoning** : des acteurs malveillants modifient ou injectent des données d’entraînement ou de réglage afin de réduire la précision, d’implanter des backdoors ou de fausser les résultats, compromettant ainsi l’intégrité du modèle tout au long du cycle de vie des données.

- **Données d’entraînement non autorisées** : l’ingestion de jeux de données protégés par le droit d’auteur, sensibles ou utilisés sans autorisation crée des risques juridiques, éthiques et de performance, car le modèle apprend à partir de données qu’il n’était pas autorisé à utiliser.

- **Altération du code source du modèle** : la manipulation du code, des dépendances ou des poids du modèle par un acteur de la chaîne d’approvisionnement ou un initié, avant ou pendant l’entraînement, peut intégrer une logique cachée qui persiste même après le réentraînement.

- **Gestion excessive des données** : des contrôles insuffisants de conservation et de gouvernance des données conduisent les systèmes à stocker ou traiter plus de données personnelles que nécessaire, augmentant les risques d’exposition et de non-conformité.

- **Exfiltration de modèle** : des attaquants dérobent les fichiers ou les poids du modèle, entraînant une perte de propriété intellectuelle et permettant de créer des services similaires ou de mener des attaques ultérieures.

- **Altération du déploiement du modèle** : des adversaires modifient les artefacts du modèle ou l’infrastructure de service, de sorte que le modèle en cours d’exécution diffère de la version validée, ce qui peut en changer le comportement.

- **Déni de service ML** : saturer les API ou envoyer des entrées « sponge » peut épuiser les ressources de calcul et l’énergie, et mettre le modèle hors service, comme dans les attaques DoS classiques.

- **Rétro-ingénierie du modèle** : en récupérant un grand nombre de paires entrée-sortie, les attaquants peuvent cloner ou distiller le modèle, favorisant la création de produits d’imitation et d’attaques adversariales personnalisées.

- **Composant intégré non sécurisé** : des plugins, agents ou services en amont vulnérables permettent aux attaquants d’injecter du code ou d’élever leurs privilèges au sein du pipeline d’IA.

- **Prompt Injection** : concevoir des prompts, directement ou indirectement, pour y dissimuler des instructions qui supplantent l’intention du système et amènent le modèle à exécuter des commandes non prévues.

- **Model Evasion** : des entrées soigneusement conçues poussent le modèle à mal classifier, à halluciner ou à produire du contenu interdit, ce qui nuit à la sécurité et à la confiance.

- **Divulgation de données sensibles** : le modèle révèle des informations privées ou confidentielles provenant de ses données d’entraînement ou du contexte utilisateur, en violation de la vie privée et des réglementations.

- **Inférence de données sensibles** : le modèle déduit des attributs personnels qui ne lui ont jamais été communiqués, créant de nouveaux préjudices pour la vie privée par inférence.

- **Sortie de modèle non sécurisée** : des réponses non nettoyées transmettent du code malveillant, des informations erronées ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Actions incontrôlées** : des agents intégrés de manière autonome exécutent des opérations réelles non prévues (écriture de fichiers, appels API, achats, etc.) sans supervision adéquate de l’utilisateur.

## Matrice MITRE AI ATLAS

La [matrice MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d’IA. Elle classe diverses techniques et tactiques d’attaque que les adversaires peuvent utiliser contre les modèles d’IA, ainsi que les façons d’utiliser les systèmes d’IA pour mener différentes attaques.<sup>[[3]](#references)</sup>

## LLMJacking (vol de tokens et revente d’accès à des LLM hébergés dans le cloud)

Des attaquants volent des tokens de session actifs ou des identifiants d’API cloud et invoquent sans autorisation des LLM payants hébergés dans le cloud. L’accès est souvent revendu au moyen de reverse proxies qui utilisent le compte de la victime, par exemple des déploiements « oai-reverse-proxy ». Les conséquences incluent des pertes financières, une utilisation du modèle contraire aux règles et l’attribution des activités au tenant de la victime.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP :
- Récupérer des tokens sur des machines de développeurs ou des navigateurs infectés ; voler des secrets CI/CD ; acheter des cookies divulgués.<sup>[[5]](#references)</sup>
- Mettre en place un reverse proxy qui transmet les requêtes au fournisseur légitime, masquant la clé en amont et multiplexant les requêtes de nombreux clients.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuser des endpoints directs des modèles de base pour contourner les garde-fous d’entreprise et les limites de débit.<sup>[[4]](#references)</sup>

Mesures d’atténuation :
- Lier les tokens à l’empreinte de l’appareil, aux plages d’adresses IP et à l’attestation du client ; imposer des expirations courtes et renouveler les tokens avec MFA.
- Limiter au minimum la portée des clés (aucun accès aux outils, lecture seule le cas échéant) ; les renouveler en cas d’anomalie.
- Faire passer tout le trafic par un gateway de politiques côté serveur qui applique des filtres de sécurité, des quotas par route et l’isolation des tenants.
- Surveiller les habitudes d’utilisation inhabituelles (pics soudains de dépenses, régions atypiques, chaînes UA) et révoquer automatiquement les sessions suspectes.
- Privilégier mTLS ou des JWT signés émis par votre IdP plutôt que des clés API statiques à longue durée de vie.

## Renforcement de l’inférence LLM auto-hébergée

L’exécution d’un serveur LLM local pour traiter des données confidentielles présente une surface d’attaque différente de celle des API hébergées dans le cloud : les endpoints d’inférence ou de débogage peuvent divulguer des prompts, la pile de service expose généralement un reverse proxy et les nœuds de périphériques GPU donnent accès à de vastes surfaces `ioctl()`. Si vous évaluez ou déployez un service d’inférence sur site, examinez au minimum les points suivants.<sup>[[8]](#references)</sup>

### Fuite de prompts via les endpoints de débogage et de surveillance

Traitez l’API d’inférence comme un **service sensible multi-utilisateur**. Les routes de débogage ou de surveillance peuvent exposer le contenu des prompts, l’état des slots, les métadonnées du modèle ou des informations sur la file d’attente interne. Dans `llama.cpp`, l’endpoint `/slots` est particulièrement sensible, car il expose l’état de chaque slot et est uniquement destiné à l’inspection ou à la gestion des slots.<sup>[[8]](#references)</sup>

Pour l’empreinte et le test en boîte noire des runners de modèles exposés et des services d’IA associés, consultez [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Placez un reverse proxy devant le serveur d’inférence et **refusez tout accès par défaut**.
- N’autorisez que les combinaisons exactes de méthodes HTTP et de chemins requises par le client ou l’interface utilisateur.
- Désactivez autant que possible les endpoints d’introspection directement dans le backend, par exemple avec `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reliez le reverse proxy à `127.0.0.1` et exposez-le via un transport authentifié, comme la redirection de port locale SSH, plutôt que de le publier sur le LAN.

Exemple de liste d’autorisations avec nginx :

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

### Conteneurs sans privilèges avec aucun réseau et sockets UNIX

Si le démon d’inférence prend en charge l’écoute sur un socket UNIX, préférez cette option à TCP et lancez le conteneur **sans pile réseau** :<sup>[[8]](#references)</sup>

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
- `--network none` supprime l’exposition TCP/IP entrante et sortante et évite les aides en espace utilisateur dont les conteneurs rootless auraient autrement besoin.
- Un socket UNIX permet d’utiliser les permissions/ACL POSIX sur son chemin comme première couche de contrôle d’accès.
- `--userns=keep-id` et Podman rootless réduisent l’impact d’une évasion de conteneur, car le root du conteneur n’est pas le root de l’hôte.
- Les montages de modèles en lecture seule réduisent le risque de falsification des modèles depuis le conteneur.

Pour les déploiements persistants, les mêmes restrictions peuvent être exprimées sous forme d’unités Podman Quadlet. Si l’accès au GPU est délégué via le Container Device Interface, limitez autant que possible la spécification du périphérique CDI au lieu d’exposer tous les nœuds d’accélérateur.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Réduction au minimum des nœuds de périphériques GPU

Pour l’inférence utilisant un GPU, les fichiers `/dev/nvidia*` constituent des surfaces d’attaque locales à forte valeur, car ils exposent de grands gestionnaires de `ioctl()` et potentiellement des chemins partagés de gestion de la mémoire GPU.<sup>[[8]](#references)</sup>

- Ne laissez pas `/dev/nvidia*` accessibles en écriture à tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACL afin que seul l’UID mappé du conteneur puisse les ouvrir.
- Blacklistez les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d’inférence sans interface graphique.
- Préchargez uniquement les modules requis au démarrage au lieu de laisser le runtime lancer opportunément `modprobe` au démarrage de l’inférence.

Exemple :

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un point important à examiner est **`/dev/nvidia-uvm`**. Même si la charge de travail n’utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent tout de même nécessiter `nvidia-uvm`. Comme ce périphérique est partagé et gère la mémoire virtuelle du GPU, considérez-le comme une surface d’exposition de données entre tenants. Si le backend d’inférence le prend en charge, un backend Vulkan peut constituer un compromis intéressant, car il peut éviter d’exposer `nvidia-uvm` au conteneur.<sup>[[8]](#references)</sup>

### Confinement LSM pour les workers d’inférence

AppArmor/SELinux/seccomp doivent être utilisés comme défense en profondeur autour du processus d’inférence :<sup>[[8]](#references)</sup>

- N’autorisez que les bibliothèques partagées, les chemins des modèles, le répertoire des sockets et les nœuds de périphérique GPU réellement nécessaires.
- Refusez explicitement les capacités à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Gardez le répertoire des modèles en lecture seule et limitez les chemins accessibles en écriture aux seuls répertoires des sockets et du cache du runtime.
- Surveillez les journaux de refus, car ils fournissent des données de télémétrie utiles pour la détection lorsque le serveur de modèles ou un payload de post-exploitation tente de s’échapper du comportement attendu.

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

## Phantom Squatting : les domaines hallucinés par les LLM comme vecteur de la chaîne d’approvisionnement de l’IA

Le Phantom Squatting est l’équivalent **domaine/URL du slopsquatting**. Au lieu d’halluciner un nom de package inexistant, le LLM hallucine un **domaine de portail, d’API, de webhook, de facturation, de SSO, de téléchargement ou de support** plausible pour une marque réelle, puis un attaquant enregistre cet espace de noms avant qu’un humain ou un agent ne l’utilise.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

C’est important, car dans de nombreux workflows assistés par l’IA, la sortie du modèle est traitée comme une **dépendance de confiance** :
- Les développeurs collent le endpoint suggéré dans du code ou des intégrations CI/CD.
- Les agents IA récupèrent automatiquement de la documentation, des schémas, des APK, des ZIP ou des cibles de webhook.
- Des runbooks ou documents générés peuvent intégrer la fausse URL comme si elle faisait autorité.

### Workflow offensif

1. **Sonder la surface d’hallucination** : poser des questions spécifiques à une marque sur des workflows réalistes, comme les portails `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou d’application mobile.<sup>[[12]](#references)</sup>
2. **Normaliser les candidats** : résoudre les URL générées, ramener les réponses NXDOMAIN au domaine parent enregistrable et dédupliquer les familles de prompts. Les corpus de prompts doivent rester diversifiés, par exemple en supprimant les quasi-doublons avec la **similarité de Jaccard**.
3. **Prioriser les hallucinations prévisibles** :
   - **Thermal Hallucination Persistence (THP)** : le même faux domaine apparaît à différentes températures, y compris à basse température, par exemple `T=0.1`.
   - **Consensus entre modèles** : plusieurs familles de LLM génèrent le même faux domaine.
4. **Enregistrer et armer** le domaine parent, puis héberger des pages de phishing, de faux téléchargements d’APK/ZIP, des collecteurs d’identifiants, des documents malveillants ou des endpoints d’API qui collectent des secrets ou des charges utiles de webhook. Les **hallucinations limitées au domaine** sont les plus faciles à monétiser, car l’attaquant contrôle tout l’espace de noms ; les hallucinations de sous-domaines/chemins peuvent néanmoins être exploitées si le domaine parent normalisé n’est pas enregistré.
5. **Exploiter la fenêtre sans réputation** : les domaines nouvellement enregistrés n’ont souvent aucun historique dans les listes de blocage, aucune réputation d’URL ni télémétrie mature ; ils peuvent donc contourner les contrôles jusqu’à ce que les systèmes de détection rattrapent leur retard. Les attaquants peuvent prolonger cette fenêtre avec des réponses bénignes réservées aux crawlers, du cloaking par redirection, des CAPTCHA ou une mise en place différée de la charge utile.

### Pourquoi c’est dangereux pour les agents

Pour une victime humaine, le faux domaine nécessite généralement un clic et une autre action. Dans un **workflow agentique**, le LLM peut être à la fois le **leurre** et l’**exécutant** : l’agent reçoit l’URL hallucinée, la récupère, analyse la réponse, puis peut leak des tokens, exécuter des instructions, télécharger une dépendance ou injecter des données empoisonnées dans la CI/CD sans aucune vérification humaine.<sup>[[12]](#references)</sup>

### Prompts pratiques pour les attaquants

Les prompts les plus efficaces ressemblent généralement à des tâches d’entreprise ordinaires plutôt qu’à des leurres de phishing explicites :<sup>[[12]](#references)</sup>
- « Quelle est l’URL du sandbox de paiement pour les intégrations de `<brand>` ? »
- « Quel endpoint de webhook dois-je utiliser pour les notifications de build de `<brand>` ? »
- « Où se trouve le portail des avantages sociaux / de facturation / SSO de `<brand>` ? »
- « Donne-moi le lien direct de téléchargement de l’APK Android ou du client desktop de `<brand>`. »

### Inversion défensive

Traitez cela comme un problème de surveillance proactive des domaines, et pas seulement comme un problème de prompt-injection :<sup>[[12]](#references)</sup>
- Constituez un **corpus de prompts sur les marques** et sondez périodiquement les LLM utilisés par vos utilisateurs et agents.
- Stockez les URL hallucinées et suivez celles qui restent stables selon les températures et les modèles.
- Suivez l’**Adversarial Exploitation Window (AEW)** : le délai entre la première hallucination et l’enregistrement par un attaquant. Une AEW positive signifie que les défenseurs peuvent préenregistrer, sinkhole ou bloquer le domaine avant son armement.
- Surveillez les transitions **NXDOMAIN → enregistré** pour les domaines parents.
- Lorsqu’un domaine est enregistré, examinez le bureau d’enregistrement, la date de création, les serveurs de noms, le masquage de la confidentialité, le contenu de la page, les captures d’écran, le statut de page parking et la similarité des éléments graphiques de la marque.
- Ajoutez des contrôles de politique afin que les agents et les développeurs **ne fassent pas confiance par défaut aux domaines générés par un LLM** : exigez des listes d’autorisation, la validation de la propriété, des vérifications CT/RDAP ou une approbation humaine avant toute première utilisation.

Cela relève simultanément de plusieurs catégories de risques liés à l’IA : **attaque de la chaîne d’approvisionnement de l’IA**, **sortie de modèle non sécurisée** et **actions malveillantes** lorsque des agents utilisent de manière autonome l’URL hallucinée.

## References

- [1] [Top 10 des vulnérabilités du machine learning selon OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risques](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice des menaces MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Les risques des LLM assistants de code : contenu nuisible, détournement et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking : des identifiants cloud volés utilisés dans une nouvelle attaque par IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Présentation du système LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revente d’accès LLM volé)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analyse approfondie du déploiement d’un serveur LLM sur site à privilèges limités](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets Podman : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Spécification CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting : les domaines hallucinés par l’IA comme vecteur de la chaîne d’approvisionnement logicielle](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting : comment les hallucinations de l’IA alimentent une nouvelle catégorie d’attaques de la chaîne d’approvisionnement](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
