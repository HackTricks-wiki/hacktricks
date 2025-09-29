# Risques liés à l'IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp a identifié les 10 principales vulnérabilités du machine learning qui peuvent affecter les systèmes d'IA. Ces vulnérabilités peuvent mener à divers problèmes de sécurité, y compris le data poisoning, le model inversion, et les adversarial attacks. Comprendre ces vulnérabilités est crucial pour construire des systèmes d'IA sécurisés.

Pour une liste à jour et détaillée des top 10, référez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaquant ajoute de minuscules modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne une mauvaise décision.\
*Exemple*: Quelques éclaboussures de peinture sur un stop‑sign trompent une voiture autonome en lui faisant "voir" un panneau de limitation de vitesse.

- **Data Poisoning Attack**: Le **jeu de données d'entraînement** est délibérément pollué avec des échantillons malveillants, enseignant au modèle des règles nuisibles.\
*Exemple*: Des binaires malveillants sont étiquetés à tort comme "benign" dans un corpus d'entraînement d'antivirus, permettant à des malwares similaires de passer plus tard.

- **Model Inversion Attack**: En sondant les sorties, un attaquant construit un **modèle inverse** qui reconstruit des caractéristiques sensibles des entrées originales.\
*Exemple*: Re‑créer l'image IRM d'un patient à partir des prédictions d'un modèle de détection du cancer.

- **Membership Inference Attack**: L'adversaire teste si un **enregistrement spécifique** a été utilisé durant l'entraînement en repérant des différences de confiance.\
*Exemple*: Confirmer qu'une transaction bancaire d'une personne figure dans les données d'entraînement d'un modèle de détection de fraude.

- **Model Theft**: Des requêtes répétées permettent à un attaquant d'apprendre les frontières de décision et de **cloner le comportement du modèle** (et la propriété intellectuelle).\
*Exemple*: Récupérer suffisamment de paires Q&A depuis une API ML‑as‑a‑Service pour construire un modèle local quasi‑équivalent.

- **AI Supply‑Chain Attack**: Compromettre n'importe quel composant (données, bibliothèques, pre‑trained weights, CI/CD) dans le **ML pipeline** pour corrompre les modèles en aval.\
*Exemple*: Une dépendance empoisonnée sur un model‑hub installe un modèle de sentiment‑analysis backdoored dans de nombreuses applications.

- **Transfer Learning Attack**: Une logique malveillante est implantée dans un **pre‑trained model** et survit au fine‑tuning pour la tâche de la victime.\
*Exemple*: Un backbone de vision contenant un trigger caché continue d'inverser des labels après avoir été adapté pour l'imagerie médicale.

- **Model Skewing**: Des données subtilement biaisées ou mal étiquetées **décalent les sorties du modèle** pour favoriser l'agenda de l'attaquant.\
*Exemple*: Injecter des emails de spam "propres" étiquetés comme ham pour que un filtre antispam laisse passer des emails similaires à l'avenir.

- **Output Integrity Attack**: L'attaquant **altère les prédictions du modèle en transit**, pas le modèle lui‑même, trompant les systèmes en aval.\
*Exemple*: Basculer le verdict "malicious" d'un classifieur de malware en "benign" avant que l'étape de quarantaine de fichier ne l'analyse.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle** eux‑mêmes, souvent après avoir obtenu un accès en écriture, pour altérer le comportement.\
*Exemple*: Ajuster des poids sur un modèle de détection de fraude en production pour que les transactions provenant de certaines cartes soient toujours approuvées.


## Google SAIF Risks

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google décrit divers risques associés aux systèmes d'IA :

- **Data Poisoning**: Des acteurs malveillants modifient ou injectent des données d'entraînement/tuning pour dégrader la précision, implanter des backdoors, ou biaiser les résultats, sapant l'intégrité du modèle sur l'ensemble du cycle de vie des données.

- **Unauthorized Training Data**: L'ingestion de jeux de données protégés par copyright, sensibles, ou non autorisés crée des responsabilités légales, éthiques et de performance parce que le modèle apprend à partir de données qu'il n'était pas permis d'utiliser.

- **Model Source Tampering**: Une manipulation de la supply‑chain ou par un insider du code du modèle, des dépendances, ou des weights avant ou pendant l'entraînement peut intégrer une logique cachée qui persiste même après un retraining.

- **Excessive Data Handling**: Des contrôles faibles de rétention et de gouvernance des données poussent les systèmes à stocker ou traiter plus de données personnelles que nécessaire, augmentant l'exposition et le risque de conformité.

- **Model Exfiltration**: Des attaquants volent des fichiers/weights du modèle, entraînant une perte de propriété intellectuelle et permettant des services imitateurs ou des attaques ultérieures.

- **Model Deployment Tampering**: Des adversaires modifient des artefacts de modèle ou l'infrastructure de serving de sorte que le modèle en fonctionnement diffère de la version contrôlée, pouvant changer son comportement.

- **Denial of ML Service**: Inonder des APIs ou envoyer des inputs « sponge » peut épuiser le compute/énergie et mettre le modèle hors ligne, reproduisant des attaques classiques de DoS.

- **Model Reverse Engineering**: En récoltant un grand nombre de paires entrée‑sortie, des attaquants peuvent cloner ou distiller le modèle, alimentant des produits d'imitation et des attaques adversariales personnalisées.

- **Insecure Integrated Component**: Des plugins, agents, ou services amont vulnérables permettent aux attaquants d'injecter du code ou d'escalader des privilèges au sein du pipeline IA.

- **Prompt Injection**: Concevoir des prompts (directement ou indirectement) pour faire passer des instructions qui outrepassent l'intention du système, poussant le modèle à exécuter des commandes non prévues.

- **Model Evasion**: Des inputs soigneusement conçus déclenchent le modèle pour qu'il se trompe de classe, hallucine, ou produise du contenu interdit, érodant la sécurité et la confiance.

- **Sensitive Data Disclosure**: Le modèle révèle des informations privées ou confidentielles provenant de ses données d'entraînement ou du contexte utilisateur, violant la vie privée et les régulations.

- **Inferred Sensitive Data**: Le modèle déduit des attributs personnels jamais fournis, créant de nouveaux préjudices à la vie privée par inférence.

- **Insecure Model Output**: Des réponses non assainies transmettent du code dangereux, de la désinformation, ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions**: Des agents intégrés de façon autonome exécutent des opérations réelles non prévues (écritures de fichiers, appels API, achats, etc.) sans supervision utilisateur adéquate.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d'IA. Elle catégorise diverses techniques et tactiques d'attaque que les adversaires peuvent utiliser contre les modèles d'IA, et aussi comment utiliser des systèmes d'IA pour réaliser différentes attaques.


## LLMJacking (Vol de tokens et revente d'accès à des LLM hébergés dans le cloud)

Des attaquants volent des tokens de session actifs ou des credentials d'API cloud et invoquent des LLMs payants hébergés dans le cloud sans autorisation. L'accès est souvent revendu via des reverse proxies qui font front sur le compte de la victime, par ex. des déploiements "oai-reverse-proxy". Les conséquences incluent des pertes financières, un mauvais usage du modèle en dehors des politiques, et une attribution à la tenant victime.

TTPs:
- Harvest tokens from infected developer machines or browsers; steal CI/CD secrets; buy leaked cookies.
- Mettre en place un reverse proxy qui transmet les requêtes au provider légitime, cachant la clé upstream et multiplexant de nombreux clients.
- Abuser des endpoints base‑model directs pour contourner les guardrails d'entreprise et les limites de taux.

Mitigations:
- Lier les tokens au fingerprint device, aux plages IP, et à l'attestation client; imposer des expirations courtes et le rafraîchissement avec MFA.
- Scoper les keys au minimum (pas d'accès aux outils, read‑only quand applicable); faire une rotation en cas d'anomalie.
- Terminer tout le trafic côté serveur derrière une policy gateway qui applique des filtres de safety, des quotas par route, et l'isolation des tenants.
- Surveiller les patterns d'utilisation inhabituels (pics de dépense soudains, régions atypiques, UA strings) et révoquer automatiquement les sessions suspectes.
- Préférer mTLS ou des JWT signés émis par votre IdP plutôt que des API keys statiques longue durée.

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
