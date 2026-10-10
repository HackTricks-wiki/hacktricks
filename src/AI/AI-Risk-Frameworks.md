# Risques liés à l’IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

OWASP a identifié les 10 principales vulnérabilités du machine learning susceptibles d’affecter les systèmes d’IA. Elles peuvent entraîner divers problèmes de sécurité, notamment l’empoisonnement des données, l’inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est essentiel pour créer des systèmes d’IA sécurisés.

Pour consulter la liste détaillée et à jour des 10 principales vulnérabilités du machine learning, reportez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack**: Un attaquant apporte de minuscules modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne la mauvaise décision.\
    *Exemple* : Quelques taches de peinture sur un panneau stop trompent une voiture autonome, qui le « voit » comme un panneau de limitation de vitesse.

- **Data Poisoning Attack**: L’**ensemble d’entraînement** est délibérément contaminé par des échantillons erronés, ce qui apprend au modèle des règles nuisibles.\
*Exemple* : Des exécutables malveillants sont étiquetés à tort comme « inoffensifs » dans un corpus d’entraînement antivirus, ce qui permet ensuite à des malwares similaires de passer inaperçus.

- **Model Inversion Attack**: En sondant les résultats, un attaquant construit un **modèle inversé** qui reconstitue des caractéristiques sensibles des entrées originales.\
*Exemple* : Recréer l’image IRM d’un patient à partir des prédictions d’un modèle de détection du cancer.

- **Membership Inference Attack**: L’adversaire vérifie si un **enregistrement spécifique** a été utilisé pendant l’entraînement en repérant les différences de confiance.\
*Exemple* : Confirmer que les transactions bancaires d’une personne figurent dans les données d’entraînement d’un modèle de détection des fraudes.

- **Model Theft**: Des requêtes répétées permettent à un attaquant d’apprendre les frontières de décision et de **cloner le comportement du modèle** (ainsi que sa propriété intellectuelle).\
*Exemple* : Collecter suffisamment de paires de questions-réponses depuis une API de ML-as-a-Service pour créer un modèle local presque équivalent.

- **AI Supply‑Chain Attack**: Compromettre un composant quelconque (données, bibliothèques, poids pré-entraînés, CI/CD) du **pipeline ML** afin de corrompre les modèles en aval.\
*Exemple* : Une dépendance empoisonnée sur un model hub installe un modèle d’analyse des sentiments doté d’une backdoor dans de nombreuses applications.

- **Transfer Learning Attack**: Une logique malveillante est intégrée à un **modèle pré-entraîné** et résiste au fine-tuning pour la tâche de la victime.\
*Exemple* : Un backbone de vision contenant un trigger caché continue d’inverser les étiquettes après son adaptation à l’imagerie médicale.

- **Model Skewing**: Des données subtilement biaisées ou mal étiquetées **déplacent les résultats du modèle** au profit des objectifs de l’attaquant.\
*Exemple* : Injecter des e-mails de spam « propres » étiquetés comme ham afin qu’un filtre antispam laisse passer des e-mails similaires à l’avenir.

- **Output Integrity Attack**: L’attaquant **modifie les prédictions du modèle pendant leur transmission**, sans toucher au modèle lui-même, afin de tromper les systèmes en aval.\
*Exemple* : Modifier le verdict « malveillant » d’un classificateur de malware en « inoffensif » avant que l’étape de mise en quarantaine du fichier ne le reçoive.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle**, souvent après l’obtention d’un accès en écriture, afin d’en altérer le comportement.\
*Exemple* : Ajuster les poids d’un modèle de détection des fraudes en production pour que les transactions de certaines cartes soient toujours approuvées.


## Risques Google SAIF

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google présente divers risques associés aux systèmes d’IA :<sup>[[2]](#references)</sup>

- **Data Poisoning**: Des acteurs malveillants altèrent ou injectent des données d’entraînement ou d’ajustement afin de réduire la précision, d’implanter des backdoors ou de fausser les résultats, compromettant ainsi l’intégrité du modèle tout au long du cycle de vie des données. 

- **Unauthorized Training Data**: L’ingestion de jeux de données protégés par le droit d’auteur, sensibles ou dont l’utilisation n’est pas autorisée crée des risques juridiques, éthiques et de performance, car le modèle apprend à partir de données qu’il n’était pas autorisé à utiliser. 

- **Model Source Tampering**: La manipulation du code du modèle, de ses dépendances ou de ses poids avant ou pendant l’entraînement, par un acteur de la chaîne d’approvisionnement ou un initié, peut intégrer une logique cachée qui persiste même après un nouvel entraînement. 

- **Excessive Data Handling**: Des contrôles insuffisants en matière de conservation et de gouvernance des données conduisent les systèmes à stocker ou traiter plus de données personnelles que nécessaire, ce qui accroît les risques d’exposition et de non-conformité. 

- **Model Exfiltration**: Des attaquants volent les fichiers ou les poids du modèle, entraînant une perte de propriété intellectuelle et facilitant la création de services imitateurs ou de nouvelles attaques. 

- **Model Deployment Tampering**: Des adversaires modifient les artefacts du modèle ou l’infrastructure de service, de sorte que le modèle en production diffère de la version validée et que son comportement puisse changer. 

- **Denial of ML Service**: Inonder les API de requêtes ou envoyer des entrées « sponge » peut épuiser les ressources de calcul ou l’énergie, et mettre le modèle hors ligne, comme dans les attaques DoS classiques. 

- **Model Reverse Engineering**: En collectant un grand nombre de paires entrée-sortie, des attaquants peuvent cloner ou distiller le modèle, ce qui alimente la création de produits d’imitation et d’attaques adversariales personnalisées. 

- **Insecure Integrated Component**: Des plugins, agents ou services en amont vulnérables permettent aux attaquants d’injecter du code ou d’élever leurs privilèges au sein du pipeline d’IA. 

- **Prompt Injection**: Concevoir des prompts, directement ou indirectement, pour y dissimuler des instructions qui supplantent l’intention du système et amènent le modèle à exécuter des commandes non prévues. 

- **Model Evasion**: Des entrées soigneusement conçues poussent le modèle à mal classifier, à halluciner ou à produire du contenu interdit, ce qui nuit à sa sécurité et à la confiance qu’il inspire. 

- **Sensitive Data Disclosure**: Le modèle révèle des informations privées ou confidentielles issues de ses données d’entraînement ou du contexte utilisateur, en violation de la vie privée et de la réglementation. 

- **Inferred Sensitive Data**: Le modèle déduit des attributs personnels qui ne lui ont jamais été fournis, créant de nouveaux préjudices pour la vie privée par inférence. 

- **Insecure Model Output**: Des réponses non assainies transmettent du code malveillant, des informations erronées ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval. 

- **Rogue Actions**: Des agents intégrés de manière autonome exécutent des opérations réelles non prévues (écriture de fichiers, appels API, achats, etc.) sans supervision adéquate de l’utilisateur.

## Matrice MITRE AI ATLAS

La [matrice MITRE AI ATLAS](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d’IA. Elle catégorise différentes techniques et tactiques d’attaque que les adversaires peuvent utiliser contre les modèles d’IA, ainsi que les façons d’utiliser les systèmes d’IA pour mener diverses attaques.<sup>[[3]](#references)</sup>

## LLMJacking (vol de tokens et revente d’accès à des LLM hébergés dans le cloud)

Les attaquants volent des tokens de session actifs ou des identifiants d’API cloud, puis invoquent sans autorisation des LLM payants hébergés dans le cloud. L’accès est souvent revendu via des reverse proxies qui utilisent le compte de la victime, par exemple des déploiements « oai-reverse-proxy ». Les conséquences incluent des pertes financières, une utilisation du modèle contraire aux règles et l’attribution des activités au tenant de la victime.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTPs :
- Récupérer des tokens sur des machines de développeurs ou des navigateurs infectés ; voler des secrets CI/CD ; acheter des cookies ayant fait l’objet d’un leak.<sup>[[5]](#references)</sup>
- Mettre en place un reverse proxy qui transmet les requêtes au fournisseur légitime, masque la clé en amont et répartit les requêtes entre de nombreux clients.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuser des endpoints directs des modèles de base pour contourner les garde-fous d’entreprise et les limites de débit.<sup>[[4]](#references)</sup>

Mesures d’atténuation :
- Lier les tokens à l’empreinte de l’appareil, aux plages d’adresses IP et à l’attestation du client ; imposer des expirations courtes et renouveler les tokens avec MFA.
- Limiter les clés au minimum nécessaire (aucun accès aux outils, lecture seule le cas échéant) ; les renouveler en cas d’anomalie.
- Faire passer tout le trafic côté serveur par une passerelle de règles qui applique des filtres de sécurité, des quotas par route et l’isolation des tenants.
- Surveiller les comportements d’utilisation inhabituels (hausses soudaines des dépenses, régions atypiques, chaînes UA) et révoquer automatiquement les sessions suspectes.
- Préférer mTLS ou des JWT signés émis par votre IdP à des clés API statiques de longue durée.

## Renforcement de l’inférence de LLM auto-hébergés

L’exécution d’un serveur LLM local pour traiter des données confidentielles crée une surface d’attaque différente de celle des API hébergées dans le cloud : les endpoints d’inférence ou de débogage peuvent divulguer des prompts, la pile de service expose généralement un reverse proxy et les nœuds de périphériques GPU donnent accès à de vastes surfaces `ioctl()`. Si vous évaluez ou déployez un service d’inférence sur site, examinez au minimum les points suivants.<sup>[[8]](#references)</sup>

### Fuite de prompts via les endpoints de débogage et de surveillance

Traitez l’API d’inférence comme un **service sensible multi-utilisateur**. Les routes de débogage ou de surveillance peuvent exposer le contenu des prompts, l’état des slots, les métadonnées du modèle ou les informations sur la file d’attente interne. Dans `llama.cpp`, l’endpoint `/slots` est particulièrement sensible, car il expose l’état de chaque slot et est uniquement destiné à l’inspection ou à la gestion des slots.<sup>[[8]](#references)</sup>

- Placez un reverse proxy devant le serveur d’inférence et **refusez tout par défaut**.
- N’autorisez que les combinaisons exactes de méthodes HTTP et de chemins nécessaires au client ou à l’interface utilisateur.
- Désactivez les endpoints d’introspection dans le backend lui-même lorsque c’est possible, par exemple avec `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Reliez le reverse proxy à `127.0.0.1` et exposez-le via un transport authentifié, par exemple la redirection de port local SSH, plutôt que de le publier sur le LAN.

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

### Conteneurs rootless sans réseau et sockets UNIX

Si le daemon d’inférence peut écouter sur un socket UNIX, préférez cette option à TCP et exécutez le conteneur **sans pile réseau** :<sup>[[8]](#references)</sup>

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
- `--network none` supprime l’exposition TCP/IP entrante/sortante et évite les aides en espace utilisateur dont les conteneurs rootless auraient autrement besoin.
- Un socket UNIX permet d’utiliser les permissions/ACL POSIX sur le chemin du socket comme première couche de contrôle d’accès.
- `--userns=keep-id` et Podman rootless réduisent l’impact d’un container breakout, car le root du conteneur n’est pas le root de l’hôte.
- Les montages de modèles en lecture seule réduisent le risque d’altération des modèles depuis l’intérieur du conteneur.

Pour les déploiements persistants, les mêmes restrictions peuvent être exprimées sous forme d’unités Podman Quadlet. Si l’accès au GPU est délégué via le Container Device Interface, limitez autant que possible la spécification du périphérique CDI au lieu d’exposer chaque nœud d’accélérateur.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Réduction au minimum des nœuds de périphérique GPU

Pour l’inférence reposant sur un GPU, les fichiers `/dev/nvidia*` constituent des surfaces d’attaque locales de grande valeur, car ils exposent de vastes gestionnaires `ioctl()` du pilote et potentiellement des chemins partagés de gestion de la mémoire GPU.<sup>[[8]](#references)</sup>

- Ne laissez pas `/dev/nvidia*` accessible en écriture à tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` à l’aide de `NVreg_DeviceFileUID/GID/Mode`, de règles udev et d’ACL afin que seul l’UID de conteneur mappé puisse les ouvrir.
- Placez sur liste noire les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d’inférence sans interface graphique.
- Préchargez uniquement les modules nécessaires au démarrage au lieu de laisser le runtime les charger opportunément avec `modprobe` lors du lancement de l’inférence.

Exemple :

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un point important à vérifier est **`/dev/nvidia-uvm`**. Même si la charge de travail n’utilise pas explicitement `cudaMallocManaged()`, les versions récentes du runtime CUDA peuvent tout de même nécessiter `nvidia-uvm`. Comme ce périphérique est partagé et gère la mémoire virtuelle du GPU, considérez-le comme une surface d’exposition des données entre tenants. Si le backend d’inférence le prend en charge, un backend Vulkan peut constituer un compromis intéressant, car il peut éviter d’exposer `nvidia-uvm` au conteneur.<sup>[[8]](#references)</sup>

### Confinement LSM des workers d’inférence

AppArmor/SELinux/seccomp devraient être utilisés comme défense en profondeur autour du processus d’inférence :<sup>[[8]](#references)</sup>

- N’autorisez que les bibliothèques partagées, les chemins des modèles, le répertoire des sockets et les nœuds de périphériques GPU réellement nécessaires.
- Refusez explicitement les capacités à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Gardez le répertoire des modèles en lecture seule et limitez les chemins accessibles en écriture aux seuls répertoires des sockets et du cache d’exécution.
- Surveillez les journaux de refus, car ils fournissent des données de télémétrie utiles pour la détection lorsque le serveur de modèles ou un payload de post-exploitation tente de sortir du comportement attendu.

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

## Phantom Squatting : les domaines hallucinés par les LLM comme vecteur d’attaque de la chaîne d’approvisionnement de l’IA

Phantom squatting est l’**équivalent domaine/URL du slopsquatting**. Au lieu d’halluciner un nom de package inexistant, le LLM hallucine un **domaine plausible de portail, d’API, de webhook, de facturation, de SSO, de téléchargement ou de support** pour une marque réelle, et un attaquant enregistre cet espace de noms avant qu’un humain ou un agent ne l’utilise.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

C’est important, car dans de nombreux workflows assistés par l’IA, la sortie du modèle est considérée comme une **dépendance de confiance** :
- Les développeurs collent l’endpoint suggéré dans du code ou des intégrations CI/CD.
- Les agents IA récupèrent automatiquement de la documentation, des schémas, des APK, des ZIP ou des cibles de webhook.
- Les runbooks ou la documentation générés peuvent intégrer la fausse URL comme si elle faisait autorité.

### Workflow offensif

1. **Sonder la surface d’hallucination** : poser des questions spécifiques à une marque sur des workflows réalistes tels que les portails `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normaliser les candidats** : résoudre les URL générées, ramener les réponses NXDOMAIN au domaine parent enregistrable et dédupliquer les familles de prompts. Les corpus de prompts doivent rester variés, par exemple en éliminant les quasi-doublons à l’aide de la **similarité de Jaccard**.
3. **Prioriser les hallucinations prévisibles** :
   - **Thermal Hallucination Persistence (THP)** : le même faux domaine apparaît à différentes températures, y compris à basse température, comme `T=0.1`.
   - **Consensus entre modèles** : plusieurs familles de LLM génèrent le même faux domaine.
4. **Enregistrer le domaine parent et l’armer**, puis héberger des pages de phishing, de faux téléchargements d’APK/ZIP, des collecteurs d’identifiants, des documents malveillants ou des endpoints d’API qui collectent des secrets/charges utiles de webhook. Les **hallucinations portant uniquement sur le domaine** sont les plus faciles à monétiser, car l’attaquant contrôle tout l’espace de noms ; les hallucinations de sous-domaines/chemins peuvent tout de même être exploitées si le domaine parent normalisé n’est pas enregistré.
5. **Exploiter la fenêtre de réputation nulle** : les domaines nouvellement enregistrés n’ont souvent aucun historique de listes de blocage, aucune réputation d’URL et peu de télémétrie, ce qui leur permet de contourner les contrôles jusqu’à ce que les détections rattrapent leur retard. Les attaquants peuvent prolonger cette fenêtre avec des réponses inoffensives réservées aux crawlers, du cloaking par redirection, des CAPTCHA ou un déploiement différé de la charge utile.

### Pourquoi les agents sont exposés

Pour une victime humaine, le faux domaine nécessite généralement un clic et une autre action. Dans un **workflow agentique**, le LLM peut être à la fois le **leurre** et l’**exécutant** : l’agent reçoit l’URL hallucinée, la récupère, analyse la réponse, puis peut divulguer des jetons, exécuter des instructions, télécharger une dépendance ou injecter des données empoisonnées dans CI/CD sans aucune vérification humaine.<sup>[[12]](#references)</sup>

### Prompts pratiques pour les attaquants

Les prompts les plus efficaces ressemblent généralement à des tâches d’entreprise ordinaires plutôt qu’à des leurres de phishing explicites :<sup>[[12]](#references)</sup>
- « Quelle est l’URL du sandbox de paiement pour les intégrations de `<brand>` ? »
- « Quel endpoint de webhook dois-je utiliser pour les notifications de build de `<brand>` ? »
- « Où se trouve le portail des avantages sociaux / de facturation / SSO de `<brand>` ? »
- « Donne-moi le lien direct de téléchargement de l’APK Android ou du client de bureau de `<brand>`. »

### Inversion défensive

Traitez ce problème comme une tâche proactive de surveillance des domaines, et pas seulement comme un problème d’injection de prompt :<sup>[[12]](#references)</sup>
- Constituez un **corpus de prompts de marques** et sondez périodiquement les LLM dont dépendent vos utilisateurs/agents.
- Stockez les URL hallucinées et suivez celles qui restent stables selon les températures/modèles.
- Suivez l’**Adversarial Exploitation Window (AEW)** : le délai entre la première hallucination et l’enregistrement par l’attaquant. Un AEW positif signifie que les défenseurs peuvent préenregistrer, mettre en sinkhole ou bloquer préventivement le domaine avant son armement.
- Surveillez les transitions **NXDOMAIN → enregistré** pour les domaines parents.
- Lors de l’enregistrement, examinez le registrar, la date de création, les serveurs de noms, le masquage de confidentialité, le contenu de la page, les captures d’écran, le statut de page par défaut et la similarité des éléments de marque.
- Ajoutez des contrôles de politique afin que les agents/développeurs **ne fassent pas confiance par défaut aux domaines générés par un LLM** : exigez des listes d’autorisation, une validation de propriété, des vérifications CT/RDAP ou une approbation humaine avant toute première utilisation.

Cela relève simultanément de plusieurs catégories de risques liés à l’IA : **attaque de la chaîne d’approvisionnement de l’IA**, **sortie de modèle non sécurisée** et **actions malveillantes** lorsque des agents consomment de façon autonome l’URL hallucinée.

## References

- [1] [Top 10 des vulnérabilités du machine learning selon OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risques](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice des menaces MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Les risques des LLM assistants de code : contenu nuisible, détournement et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking : des identifiants cloud volés utilisés dans une nouvelle attaque par IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Présentation du stratagème LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revente d’accès LLM volé)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analyse approfondie du déploiement d’un serveur LLM on-premise à faibles privilèges](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets Podman : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Spécification CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting : les domaines hallucinés par l’IA comme vecteur d’attaque de la chaîne d’approvisionnement logicielle](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting : comment les hallucinations de l’IA alimentent une nouvelle catégorie d’attaques de la chaîne d’approvisionnement](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
{{#include ../banners/hacktricks-training.md}}
