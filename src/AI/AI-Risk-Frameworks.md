# Risques liés à l’IA

{{#include ../banners/hacktricks-training.md}}

## Vulnérabilités OWASP Top 10 Machine Learning

Owasp a identifié les 10 principales vulnérabilités du machine learning susceptibles d’affecter les systèmes d’IA. Elles peuvent entraîner divers problèmes de sécurité, notamment l’empoisonnement des données, l’inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est essentiel pour créer des systèmes d’IA sécurisés.

Pour consulter la liste actualisée et détaillée des 10 principales vulnérabilités du machine learning, référez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).<sup>[[1]](#references)</sup>

- **Input Manipulation Attack** : Un attaquant apporte de légères modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne la mauvaise décision.\
    *Exemple* : Quelques taches de peinture sur un panneau Stop font qu’une voiture autonome le « voit » comme un panneau de limitation de vitesse.

- **Data Poisoning Attack** : Des échantillons malveillants sont délibérément introduits dans le **jeu d’entraînement**, ce qui enseigne au modèle des règles nuisibles.\
*Exemple* : Des binaires malveillants sont étiquetés « bénins » dans un corpus d’entraînement d’antivirus, permettant à des logiciels malveillants similaires de passer ensuite inaperçus.

- **Model Inversion Attack** : En sondant les sorties, un attaquant crée un **modèle inversé** qui reconstitue des caractéristiques sensibles des entrées d’origine.\
*Exemple* : Recréer l’IRM d’un patient à partir des prédictions d’un modèle de détection du cancer.

- **Membership Inference Attack** : L’adversaire vérifie si un **enregistrement précis** a été utilisé pendant l’entraînement en repérant des différences de confiance.\
*Exemple* : Confirmer qu’une transaction bancaire d’une personne figure dans les données d’entraînement d’un modèle de détection de fraude.

- **Model Theft** : Des requêtes répétées permettent à un attaquant d’apprendre les frontières de décision et de **cloner le comportement du modèle** (et sa propriété intellectuelle).\
*Exemple* : Collecter suffisamment de paires de questions-réponses auprès d’une API ML-as-a-Service pour créer un modèle local presque équivalent.

- **AI Supply-Chain Attack** : La compromission d’un composant quelconque (données, bibliothèques, poids pré-entraînés, CI/CD) du **pipeline ML** peut corrompre les modèles en aval.\
*Exemple* : Une dépendance empoisonnée sur un hub de modèles installe un modèle d’analyse de sentiments doté d’une porte dérobée dans de nombreuses applications.

- **Transfer Learning Attack** : Une logique malveillante est intégrée à un **modèle pré-entraîné** et survit au fine-tuning sur la tâche de la victime.\
*Exemple* : Un backbone de vision doté d’un déclencheur caché continue d’inverser les étiquettes après son adaptation à l’imagerie médicale.

- **Model Skewing** : Des données subtilement biaisées ou mal étiquetées **déplacent les sorties du modèle** pour servir les objectifs de l’attaquant.\
*Exemple* : Injecter des e-mails de spam « propres » étiquetés comme ham afin qu’un filtre anti-spam laisse passer des e-mails similaires par la suite.

- **Output Integrity Attack** : L’attaquant **modifie les prédictions du modèle en transit**, et non le modèle lui-même, trompant ainsi les systèmes en aval.\
*Exemple* : Inverser le verdict « malveillant » d’un classifieur de logiciels malveillants en « bénin » avant que le fichier n’atteigne l’étape de mise en quarantaine.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle**, souvent après l’obtention d’un accès en écriture, afin d’en altérer le comportement.\
*Exemple* : Modifier les poids d’un modèle de détection de fraude en production afin que les transactions de certaines cartes soient toujours approuvées.


## Risques Google SAIF

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google présente différents risques associés aux systèmes d’IA :<sup>[[2]](#references)</sup>

- **Data Poisoning** : Des acteurs malveillants altèrent ou injectent des données d’entraînement ou de réglage afin de réduire la précision, d’implanter des portes dérobées ou de biaiser les résultats, compromettant ainsi l’intégrité du modèle tout au long du cycle de vie des données.

- **Unauthorized Training Data** : L’ingestion de jeux de données protégés par le droit d’auteur, sensibles ou non autorisés crée des risques juridiques, éthiques et de performance, car le modèle apprend à partir de données qu’il n’était pas autorisé à utiliser.

- **Model Source Tampering** : La manipulation du code, des dépendances ou des poids du modèle par la chaîne d’approvisionnement ou un initié, avant ou pendant l’entraînement, peut intégrer une logique cachée qui persiste même après un nouvel entraînement.

- **Excessive Data Handling** : Des contrôles faibles de conservation et de gouvernance des données conduisent les systèmes à stocker ou traiter davantage de données personnelles que nécessaire, augmentant les risques d’exposition et de non-conformité.

- **Model Exfiltration** : Des attaquants dérobent des fichiers ou des poids de modèle, entraînant une perte de propriété intellectuelle et permettant la création de services imitateurs ou la conduite d’attaques ultérieures.

- **Model Deployment Tampering** : Des adversaires modifient les artefacts du modèle ou l’infrastructure de service, de sorte que le modèle en cours d’exécution diffère de la version validée, ce qui peut en changer le comportement.

- **Denial of ML Service** : Inonder les API ou envoyer des entrées « sponge » peut épuiser les ressources de calcul ou l’énergie et mettre le modèle hors ligne, à l’image des attaques DoS classiques.

- **Model Reverse Engineering** : En collectant un grand nombre de paires entrée-sortie, des attaquants peuvent cloner ou distiller le modèle, favorisant la création de produits imitateurs et d’attaques adversariales ciblées.

- **Insecure Integrated Component** : Des plugins, agents ou services en amont vulnérables permettent aux attaquants d’injecter du code ou d’élever leurs privilèges dans le pipeline d’IA.

- **Prompt Injection** : Des prompts conçus pour cela, directement ou indirectement, introduisent clandestinement des instructions qui remplacent l’intention du système et poussent le modèle à exécuter des commandes non prévues.

- **Model Evasion** : Des entrées conçues avec soin amènent le modèle à mal classifier, à halluciner ou à produire du contenu interdit, érodant la sécurité et la confiance.

- **Sensitive Data Disclosure** : Le modèle révèle des informations privées ou confidentielles issues de ses données d’entraînement ou du contexte de l’utilisateur, enfreignant les règles de confidentialité et la réglementation.

- **Inferred Sensitive Data** : Le modèle déduit des attributs personnels qui ne lui ont jamais été fournis, créant de nouveaux préjudices pour la vie privée par inférence.

- **Insecure Model Output** : Des réponses non assainies transmettent du code malveillant, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions** : Des agents intégrés de manière autonome exécutent des opérations non prévues dans le monde réel (écriture de fichiers, appels d’API, achats, etc.) sans supervision adéquate de l’utilisateur.

## Matrice MITRE AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d’IA. Elle classe différentes techniques d’attaque et tactiques que des adversaires peuvent utiliser contre les modèles d’IA, ainsi que les façons dont les systèmes d’IA peuvent servir à mener diverses attaques.<sup>[[3]](#references)</sup>

## LLMJacking (vol de jetons et revente d’accès à des LLM hébergés dans le cloud)

Les attaquants dérobent des jetons de session actifs ou des identifiants d’API cloud et invoquent sans autorisation des LLM payants hébergés dans le cloud. L’accès est souvent revendu par l’intermédiaire de reverse proxies qui utilisent le compte de la victime, par exemple des déploiements « oai-reverse-proxy ». Les conséquences incluent des pertes financières, une utilisation du modèle contraire aux règles et l’attribution de cette activité au tenant de la victime.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

TTP :
- Récupérer des jetons sur des machines de développeurs ou des navigateurs infectés ; dérober des secrets CI/CD ; acheter des cookies ayant fait l’objet d’un leak.<sup>[[5]](#references)</sup>
- Mettre en place un reverse proxy qui transmet les requêtes au fournisseur légitime, masquant la clé en amont et répartissant les requêtes entre de nombreux clients.<sup>[[5]](#references)</sup><sup>[[7]](#references)</sup>
- Abuser des endpoints directs du modèle de base pour contourner les garde-fous d’entreprise et les limites de débit.<sup>[[4]](#references)</sup>

**Réutilisation de clé API sur l’hôte :** Après la compromission d’un hôte, un implant peut envoyer des requêtes API au modèle directement depuis l’hôte de la victime et relayer les réponses via C2, sans exporter de clé API cloud ni lancer une CLI d’IA locale. Dans le handler observé, une clé fournie par C2 est prioritaire ; ce n’est que si elle est absente que l’implant lit `OPENAI_API_KEY` dans l’environnement de son propre processus. L’utilisation du compte de la victime nécessite donc une clé valide accessible à ce processus et un accès à l’API du modèle. Le prompt de l’opérateur est envoyé à l’API Chat Completions, tandis que la sortie du modèle et l’utilisation des jetons sont renvoyées via C2. Cela peut consommer l’accès payant de la victime au modèle sans exécuter les outils d’IA du développeur, contrairement à l’abus de [CLI d’IA locale ou de configuration MCP](../generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md).<sup>[[14]](#references)</sup>

Mesures d’atténuation :
- Associer les jetons à l’empreinte de l’appareil, aux plages d’adresses IP et à l’attestation du client ; imposer des durées d’expiration courtes et un renouvellement avec MFA.
- Limiter les clés au strict nécessaire (pas d’accès aux outils, lecture seule le cas échéant) ; les renouveler en cas d’anomalie.
- Faire passer tout le trafic côté serveur par une passerelle de politiques qui applique des filtres de sécurité, des quotas par route et l’isolation des tenants.
- Surveiller les comportements d’utilisation inhabituels (pics soudains de dépenses, régions atypiques, chaînes UA) et révoquer automatiquement les sessions suspectes.
- Privilégier mTLS ou les JWT signés émis par votre IdP plutôt que des clés API statiques à longue durée de vie.

## Renforcement de l’inférence de LLM auto-hébergés

L’exécution d’un serveur LLM local pour traiter des données confidentielles crée une surface d’attaque différente de celle des API hébergées dans le cloud : les endpoints d’inférence et de débogage peuvent révéler les prompts, la pile de service expose généralement un reverse proxy et les nœuds de périphériques GPU donnent accès à de grandes surfaces `ioctl()`. Si vous évaluez ou déployez un service d’inférence sur site, examinez au minimum les points suivants.<sup>[[8]](#references)</sup>

### Fuite de prompts via les endpoints de débogage et de surveillance

Traitez l’API d’inférence comme un **service sensible multi-utilisateur**. Les routes de débogage ou de surveillance peuvent exposer le contenu des prompts, l’état des slots, les métadonnées du modèle ou des informations internes sur les files d’attente. Dans `llama.cpp`, l’endpoint `/slots` est particulièrement sensible, car il expose l’état de chaque slot et est uniquement destiné à l’inspection et à la gestion des slots.<sup>[[8]](#references)</sup>

Pour l’empreinte et les tests en boîte noire des runners de modèles exposés et des services d’IA associés, consultez [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

- Placez un reverse proxy devant le serveur d’inférence et **refusez tout par défaut**.
- N’autorisez que les combinaisons exactes de méthode HTTP et de chemin nécessaires au client ou à l’interface utilisateur.
- Désactivez les endpoints d’introspection dans le backend même chaque fois que possible, par exemple avec `llama-server --no-slots`.<sup>[[9]](#references)</sup>
- Faites écouter le reverse proxy sur `127.0.0.1` et exposez-le via un transport authentifié, par exemple le transfert de port local SSH, plutôt que de le publier sur le LAN.

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

### Conteneurs sans privilèges, sans réseau et avec sockets UNIX

Si le démon d’inférence peut écouter sur un socket UNIX, privilégiez cette option plutôt que TCP et exécutez le conteneur **sans pile réseau** :<sup>[[8]](#references)</sup>

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
- Un socket UNIX permet d’utiliser les permissions POSIX/ACL sur le chemin du socket comme première couche de contrôle d’accès.
- `--userns=keep-id` et Podman rootless réduisent l’impact d’un breakout de conteneur, car root dans le conteneur n’est pas root sur l’hôte.
- Des montages de modèles en lecture seule réduisent le risque d’altération des modèles depuis l’intérieur du conteneur.

Pour les déploiements persistants, les mêmes restrictions peuvent être exprimées sous forme d’unités Podman Quadlet. Si l’accès au GPU est délégué via le Container Device Interface, limitez autant que possible la spécification de périphérique CDI au lieu d’exposer chaque nœud d’accélérateur.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>

### Réduction au minimum des nœuds de périphériques GPU

Pour l’inférence utilisant un GPU, les fichiers `/dev/nvidia*` constituent des surfaces d’attaque locales très sensibles, car ils exposent de grands gestionnaires de pilotes `ioctl()` et potentiellement des chemins de gestion de la mémoire GPU partagée.<sup>[[8]](#references)</sup>

- Ne laissez pas `/dev/nvidia*` accessible en écriture à tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACL, afin que seul l’UID de conteneur mappé puisse les ouvrir.
- Désactivez les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d’inférence sans interface graphique.
- Préchargez uniquement les modules nécessaires au démarrage au lieu de laisser le runtime exécuter opportunément `modprobe` lors du démarrage de l’inférence.

Exemple :

```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```

Un point important à vérifier est **`/dev/nvidia-uvm`**. Même si la charge de travail n’utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent tout de même nécessiter `nvidia-uvm`. Comme ce périphérique est partagé et gère la mémoire virtuelle du GPU, considérez-le comme une surface d’exposition des données entre tenants. Si le backend d’inférence le prend en charge, un backend Vulkan peut constituer un compromis intéressant, car il peut éviter d’exposer `nvidia-uvm` au conteneur.<sup>[[8]](#references)</sup>

### Confinement LSM des workers d’inférence

AppArmor/SELinux/seccomp devraient être utilisés comme défense en profondeur autour du processus d’inférence :<sup>[[8]](#references)</sup>

- N’autorisez que les bibliothèques partagées, les chemins des modèles, le répertoire des sockets et les nœuds de périphériques GPU réellement nécessaires.
- Refusez explicitement les capacités à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Gardez le répertoire des modèles en lecture seule et limitez les chemins accessibles en écriture aux seuls répertoires des sockets et du cache d’exécution.
- Surveillez les journaux de refus, car ils fournissent une télémétrie de détection utile lorsque le serveur de modèles ou un payload post-exploitation tente de s’écarter du comportement attendu.

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

Phantom squatting est l’**équivalent domaine/URL du slopsquatting**. Au lieu d’halluciner un nom de package inexistant, le LLM hallucine un **domaine de portail, d’API, de webhook, de facturation, de SSO, de téléchargement ou d’assistance** plausible pour une marque réelle, et un attaquant enregistre cet espace de noms avant qu’un humain ou un agent ne l’utilise.<sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

C’est important car, dans de nombreux workflows assistés par l’IA, la sortie du modèle est traitée comme une **dépendance de confiance** :
- Les développeurs collent l’endpoint suggéré dans du code ou des intégrations CI/CD.
- Les agents IA récupèrent automatiquement de la documentation, des schémas, des APK, des ZIP ou des cibles de webhook.
- Les runbooks ou la documentation générés peuvent intégrer la fausse URL comme si elle faisait autorité.

### Workflow offensif

1. **Sonder la surface d’hallucination** : poser des questions spécifiques à une marque sur des workflows réalistes tels que des portails `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.<sup>[[12]](#references)</sup>
2. **Normaliser les candidats** : résoudre les URL générées, ramener les réponses NXDOMAIN au domaine parent pouvant être enregistré, et dédupliquer les familles de prompts. Les corpus de prompts doivent rester diversifiés, par exemple en supprimant les quasi-doublons à l’aide de la **similarité de Jaccard**.
3. **Prioriser les hallucinations prévisibles** :
   - **Persistance thermique des hallucinations (THP)** : le même faux domaine apparaît à différentes températures, y compris à basse température, comme `T=0.1`.
   - **Consensus inter-modèles** : plusieurs familles de LLM génèrent le même faux domaine.
4. **Enregistrer et armer** le domaine parent, puis héberger du phishing, de faux téléchargements d’APK/ZIP, des collecteurs d’identifiants, des documents malveillants ou des endpoints d’API qui collectent des secrets/des payloads de webhook. Les **hallucinations limitées au domaine** sont les plus faciles à monétiser, car l’attaquant contrôle tout l’espace de noms ; les hallucinations de sous-domaines/chemins peuvent toujours être exploitées si le domaine parent normalisé n’est pas enregistré.
5. **Exploiter la fenêtre sans réputation** : les domaines nouvellement enregistrés n’ont souvent pas d’historique dans les listes de blocage, de réputation d’URL ni de télémétrie mature ; ils peuvent donc contourner les contrôles jusqu’à ce que les détections rattrapent leur retard. Les attaquants peuvent prolonger cette fenêtre avec des réponses bénignes réservées aux crawlers, du cloaking par redirection, des CAPTCHA ou un déploiement différé du payload.

### Pourquoi c’est dangereux pour les agents

Pour une victime humaine, le faux domaine nécessite généralement encore un clic et une autre action. Dans un **workflow agentique**, le LLM peut être à la fois le **leurre** et l’**exécutant** : l’agent reçoit l’URL halluciné, la récupère, analyse la réponse, puis peut divulguer des tokens, exécuter des instructions, télécharger une dépendance ou injecter des données compromises dans CI/CD sans aucune vérification humaine.<sup>[[12]](#references)</sup>

### Prompts pratiques pour les attaquants

Les prompts les plus efficaces ressemblent généralement à des tâches d’entreprise ordinaires plutôt qu’à des leurres de phishing explicites :<sup>[[12]](#references)</sup>
- « Quelle est l’URL du sandbox de paiement pour les intégrations de `<brand>` ? »
- « Quel endpoint de webhook dois-je utiliser pour les notifications de build de `<brand>` ? »
- « Où se trouve le portail des avantages sociaux / de facturation / SSO de `<brand>` ? »
- « Donne-moi le lien direct de téléchargement de l’APK Android ou du client de bureau de `<brand>`. »

### Inversion défensive

Considérez cela comme un problème de surveillance proactive des domaines, et pas seulement comme un problème d’injection de prompt :<sup>[[12]](#references)</sup>
- Constituez un **corpus de prompts sur les marques** et interrogez périodiquement les LLM sur lesquels vos utilisateurs/agents s’appuient.
- Stockez les URL hallucinées et suivez celles qui restent stables selon les températures/modèles.
- Suivez la **fenêtre d’exploitation adversariale (AEW)** : le temps entre la première hallucination et l’enregistrement par l’attaquant. Une AEW positive signifie que les défenseurs peuvent enregistrer le domaine à l’avance, le sinkhole ou le bloquer avant son armement.
- Surveillez les transitions **NXDOMAIN → enregistré** pour les domaines parents.
- Lors de l’enregistrement, analysez le bureau d’enregistrement, la date de création, les serveurs de noms, le masquage de confidentialité, le contenu de la page, les captures d’écran, l’état de la page parquée et la similarité avec les éléments de marque.
- Ajoutez des contrôles de politique afin que les agents/développeurs **ne fassent pas confiance par défaut aux domaines générés par un LLM** : exigez des listes d’autorisation, la validation de propriété, des vérifications CT/RDAP ou une approbation humaine avant toute première utilisation.

Cela relève simultanément de plusieurs catégories de risques liés à l’IA : **attaque de la chaîne d’approvisionnement de l’IA**, **sortie de modèle non sécurisée** et **actions malveillantes** lorsque des agents consomment de manière autonome l’URL halluciné.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Top 10 des vulnérabilités du machine learning selon OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google SAIF (Secure AI Framework) – Risques](https://saif.google/secure-ai-framework/risks)
- [3] [Matrice des menaces MITRE ATLAS](https://atlas.mitre.org/)
- [4] [Unit 42 – Les risques des LLM assistants de code : contenu nuisible, détournement et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [5] [Sysdig – LLMjacking : des identifiants cloud volés utilisés dans une nouvelle attaque IA](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)
- [6] [Présentation du stratagème LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [7] [oai-reverse-proxy (revente d’accès LLM volé)](https://gitgud.io/khanon/oai-reverse-proxy)
- [8] [Synacktiv - Analyse approfondie du déploiement d’un serveur LLM on-premise à privilèges limités](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [9] [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [10] [Quadlets Podman : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [11] [Spécification de l’interface de périphériques de conteneurs (CDI) de la CNCF](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [12] [Unit 42 – Phantom Squatting : les domaines hallucinés par l’IA comme vecteur de la chaîne d’approvisionnement logicielle](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [13] [Socket – Slopsquatting : comment les hallucinations de l’IA alimentent une nouvelle catégorie d’attaques de la chaîne d’approvisionnement](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)
- [14] [Cisco Talos – NIK C2 : le nouveau framework de commande et de contrôle basé sur l’IA](https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/)
