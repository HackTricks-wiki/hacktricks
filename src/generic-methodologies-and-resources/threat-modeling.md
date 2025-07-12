# Modélisation des Menaces

{{#include ../banners/hacktricks-training.md}}

## Modélisation des Menaces

Bienvenue dans le guide complet de HackTricks sur la Modélisation des Menaces ! Embarquez pour une exploration de cet aspect critique de la cybersécurité, où nous identifions, comprenons et élaborons des stratégies contre les vulnérabilités potentielles dans un système. Ce fil sert de guide étape par étape rempli d'exemples concrets, de logiciels utiles et d'explications faciles à comprendre. Idéal pour les novices comme pour les praticiens expérimentés cherchant à renforcer leurs défenses en cybersécurité.

### Scénarios Couramment Utilisés

1. **Développement de Logiciels** : Dans le cadre du Cycle de Vie de Développement de Logiciels Sécurisés (SSDLC), la modélisation des menaces aide à **identifier les sources potentielles de vulnérabilités** dès les premières étapes du développement.
2. **Tests de Pénétration** : Le cadre du Standard d'Exécution des Tests de Pénétration (PTES) exige **la modélisation des menaces pour comprendre les vulnérabilités du système** avant de réaliser le test.

### Modèle de Menace en Bref

Un Modèle de Menace est généralement représenté sous la forme d'un diagramme, d'une image ou d'une autre forme d'illustration visuelle qui décrit l'architecture prévue ou la construction existante d'une application. Il ressemble à un **diagramme de flux de données**, mais la distinction clé réside dans son design orienté sécurité.

Les modèles de menaces présentent souvent des éléments marqués en rouge, symbolisant des vulnérabilités, des risques ou des barrières potentielles. Pour rationaliser le processus d'identification des risques, le triade CIA (Confidentialité, Intégrité, Disponibilité) est utilisée, formant la base de nombreuses méthodologies de modélisation des menaces, STRIDE étant l'une des plus courantes. Cependant, la méthodologie choisie peut varier en fonction du contexte et des exigences spécifiques.

### La Triade CIA

La Triade CIA est un modèle largement reconnu dans le domaine de la sécurité de l'information, représentant la Confidentialité, l'Intégrité et la Disponibilité. Ces trois piliers forment la base sur laquelle de nombreuses mesures et politiques de sécurité sont construites, y compris les méthodologies de modélisation des menaces.

1. **Confidentialité** : Assurer que les données ou le système ne sont pas accessibles par des individus non autorisés. C'est un aspect central de la sécurité, nécessitant des contrôles d'accès appropriés, le chiffrement et d'autres mesures pour prévenir les violations de données.
2. **Intégrité** : L'exactitude, la cohérence et la fiabilité des données tout au long de leur cycle de vie. Ce principe garantit que les données ne sont pas modifiées ou altérées par des parties non autorisées. Il implique souvent des sommes de contrôle, du hachage et d'autres méthodes de vérification des données.
3. **Disponibilité** : Cela garantit que les données et les services sont accessibles aux utilisateurs autorisés lorsque cela est nécessaire. Cela implique souvent de la redondance, de la tolérance aux pannes et des configurations de haute disponibilité pour maintenir les systèmes en fonctionnement même en cas de perturbations.

### Méthodologies de Modélisation des Menaces

1. **STRIDE** : Développé par Microsoft, STRIDE est un acronyme pour **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**. Chaque catégorie représente un type de menace, et cette méthodologie est couramment utilisée lors de la phase de conception d'un programme ou d'un système pour identifier les menaces potentielles.
2. **DREAD** : C'est une autre méthodologie de Microsoft utilisée pour l'évaluation des risques des menaces identifiées. DREAD signifie **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**. Chacun de ces facteurs est noté, et le résultat est utilisé pour prioriser les menaces identifiées.
3. **PASTA** (Process for Attack Simulation and Threat Analysis) : C'est une méthodologie en sept étapes, **centrée sur le risque**. Elle inclut la définition et l'identification des objectifs de sécurité, la création d'un périmètre technique, la décomposition de l'application, l'analyse des menaces, l'analyse des vulnérabilités et l'évaluation des risques/triage.
4. **Trike** : C'est une méthodologie basée sur le risque qui se concentre sur la défense des actifs. Elle part d'une perspective de **gestion des risques** et examine les menaces et les vulnérabilités dans ce contexte.
5. **VAST** (Visual, Agile, and Simple Threat modeling) : Cette approche vise à être plus accessible et s'intègre dans des environnements de développement Agile. Elle combine des éléments des autres méthodologies et se concentre sur **les représentations visuelles des menaces**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation) : Développé par le CERT Coordination Center, ce cadre est orienté vers **l'évaluation des risques organisationnels plutôt que des systèmes ou logiciels spécifiques**.

## Outils

Il existe plusieurs outils et solutions logicielles disponibles qui peuvent **aider** à la création et à la gestion de modèles de menaces. Voici quelques-uns que vous pourriez envisager.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un outil GUI web spider/crawler multi-fonction et multiplateforme avancé pour les professionnels de la cybersécurité. Spider Suite peut être utilisé pour la cartographie et l'analyse de la surface d'attaque.

**Utilisation**

1. Choisissez une URL et explorez

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Voir le Graphique

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Un projet open-source d'OWASP, Threat Dragon est à la fois une application web et de bureau qui inclut le diagramme de système ainsi qu'un moteur de règles pour générer automatiquement des menaces/atténuations.

**Utilisation**

1. Créer un Nouveau Projet

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Parfois, cela pourrait ressembler à ceci :

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lancer un Nouveau Projet

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Enregistrer le Nouveau Projet

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Créer votre modèle

Vous pouvez utiliser des outils comme SpiderSuite Crawler pour vous inspirer, un modèle de base ressemblerait à quelque chose comme ceci

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Juste un peu d'explication sur les entités :

- Processus (L'entité elle-même comme un serveur web ou une fonctionnalité web)
- Acteur (Une personne comme un Visiteur de Site Web, un Utilisateur ou un Administrateur)
- Ligne de Flux de Données (Indicateur d'Interaction)
- Limite de Confiance (Différents segments ou portées de réseau.)
- Stocker (Choses où les données sont stockées comme des Bases de Données)

5. Créer une Menace (Étape 1)

Tout d'abord, vous devez choisir la couche à laquelle vous souhaitez ajouter une menace

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Maintenant, vous pouvez créer la menace

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Gardez à l'esprit qu'il y a une différence entre les Menaces d'Acteur et les Menaces de Processus. Si vous ajoutez une menace à un Acteur, vous ne pourrez choisir que "Spoofing" et "Repudiation". Cependant, dans notre exemple, nous ajoutons une menace à une entité de Processus, donc nous verrons cela dans la boîte de création de menace :

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Terminé

Maintenant, votre modèle terminé devrait ressembler à quelque chose comme ceci. Et c'est ainsi que vous créez un modèle de menace simple avec OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

C'est un outil gratuit de Microsoft qui aide à trouver des menaces dans la phase de conception des projets logiciels. Il utilise la méthodologie STRIDE et est particulièrement adapté à ceux qui développent sur la pile de Microsoft.


{{#include ../banners/hacktricks-training.md}}
