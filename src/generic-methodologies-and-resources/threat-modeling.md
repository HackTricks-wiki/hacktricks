# Modélisation des menaces

{{#include ../banners/hacktricks-training.md}}

## Modélisation des menaces

Bienvenue dans le guide complet de HackTricks sur la Threat Modeling ! Explorez cet aspect essentiel de la cybersécurité, qui consiste à identifier, comprendre et anticiper les vulnérabilités potentielles d’un système. Cette section propose un guide étape par étape, riche en exemples du monde réel, en logiciels utiles et en explications faciles à comprendre. Elle convient aussi bien aux débutants qu’aux professionnels expérimentés souhaitant renforcer leurs défenses en cybersécurité.

### Scénarios couramment utilisés

1. **Développement logiciel** : dans le cadre du Secure Software Development Life Cycle (SSDLC), la Threat Modeling aide à **identifier les sources potentielles de vulnérabilités** dès les premières étapes du développement.
2. **Penetration Testing** : le framework Penetration Testing Execution Standard (PTES) exige une **Threat Modeling pour comprendre les vulnérabilités du système** avant d’effectuer le test.

### Le Threat Model en bref

Un Threat Model est généralement représenté par un diagramme, une image ou une autre forme d’illustration visuelle décrivant l’architecture prévue ou la version existante d’une application. Il ressemble à un **data flow diagram**, mais la différence essentielle réside dans sa conception axée sur la sécurité.

Les Threat Models comportent souvent des éléments marqués en rouge, symbolisant des vulnérabilités, des risques ou des barrières potentielles. Pour simplifier le processus d’identification des risques, on utilise la triade CIA (Confidentiality, Integrity, Availability), qui constitue la base de nombreuses méthodologies de Threat Modeling, STRIDE étant l’une des plus courantes. Toutefois, la méthodologie choisie peut varier selon le contexte et les exigences spécifiques.

### La triade CIA

La triade CIA est un modèle largement reconnu dans le domaine de la sécurité de l’information. Elle signifie Confidentiality, Integrity et Availability. Ces trois piliers constituent la base de nombreuses mesures et politiques de sécurité, notamment des méthodologies de Threat Modeling.

1. **Confidentiality** : garantir que les données ou le système ne sont pas accessibles à des personnes non autorisées. Il s’agit d’un aspect central de la sécurité, qui nécessite des contrôles d’accès appropriés, du chiffrement et d’autres mesures visant à empêcher les data breaches.
2. **Integrity** : l’exactitude, la cohérence et la fiabilité des données tout au long de leur cycle de vie. Ce principe garantit que les données ne sont pas modifiées ou altérées par des parties non autorisées. Il implique souvent l’utilisation de checksums, du hashing et d’autres méthodes de vérification des données.
3. **Availability** : garantir que les données et les services sont accessibles aux utilisateurs autorisés lorsqu’ils en ont besoin. Cela implique souvent de la redondance, de la fault tolerance et des configurations high-availability afin de maintenir les systèmes en fonctionnement même en cas de perturbations.

### Méthodologies de Threat Modeling

1. **STRIDE** : développée par Microsoft, STRIDE est l’acronyme de **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service et Elevation of Privilege**. Chaque catégorie représente un type de menace, et cette méthodologie est couramment utilisée lors de la phase de conception d’un programme ou d’un système afin d’identifier les menaces potentielles.
2. **DREAD** : il s’agit d’une autre méthodologie de Microsoft utilisée pour évaluer les risques associés aux menaces identifiées. DREAD signifie **Damage potential, Reproducibility, Exploitability, Affected users et Discoverability**. Chacun de ces facteurs reçoit une note, et le résultat sert à prioriser les menaces identifiées.
3. **PASTA** (Process for Attack Simulation and Threat Analysis) : il s’agit d’une méthodologie en sept étapes, **centrée sur les risques**. Elle comprend la définition et l’identification des objectifs de sécurité, la création d’un périmètre technique, la décomposition de l’application, l’analyse des menaces, l’analyse des vulnérabilités ainsi que l’évaluation et le triage des risques.
4. **Trike** : il s’agit d’une méthodologie basée sur les risques qui se concentre sur la protection des actifs. Elle adopte d’abord une perspective de **risk management**, puis examine les menaces et les vulnérabilités dans ce contexte.
5. **VAST** (Visual, Agile, and Simple Threat modeling) : cette approche vise à être plus accessible et s’intègre aux environnements de développement Agile. Elle combine des éléments issus d’autres méthodologies et se concentre sur les **représentations visuelles des menaces**.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation) : développé par le CERT Coordination Center, ce framework est destiné à l’**évaluation des risques organisationnels plutôt qu’à celle de systèmes ou de logiciels spécifiques**.

## Outils

Plusieurs outils et solutions logicielles peuvent **aider** à créer et gérer des Threat Models. En voici quelques-uns que vous pouvez envisager.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Un web spider/crawler GUI avancé, multiplateforme et doté de nombreuses fonctionnalités, destiné aux professionnels de la cybersécurité. Spider Suite peut être utilisé pour effectuer la cartographie et l’analyse de la attack surface.

**Utilisation**

1. Choisissez une URL et lancez le Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Affichez le Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Projet open source d’OWASP, Threat Dragon est une application web et desktop qui inclut la création de diagrammes système ainsi qu’un rule engine permettant de générer automatiquement des menaces et des mitigations.

**Utilisation**

1. Créez un New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Parfois, cela peut ressembler à ceci :

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lancez le New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Enregistrez le New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Créez votre modèle

Vous pouvez utiliser des outils comme SpiderSuite Crawler pour vous inspirer ; un modèle de base pourrait ressembler à ceci :

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Voici une courte explication des entités :

- Process (L’entité elle-même, comme un Webserver ou une fonctionnalité web)
- Actor (Une personne, comme un Website Visitor, un User ou un Administrator)
- Data Flow Line (Indicateur d’interaction)
- Trust Boundary (Différents segments ou périmètres réseau.)
- Store (Emplacements où les données sont stockées, comme des Databases)

5. Créez une Threat (Étape 1)

Vous devez d’abord choisir la couche à laquelle vous souhaitez ajouter une menace.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Vous pouvez maintenant créer la menace.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Gardez à l’esprit qu’il existe une différence entre les Actor Threats et les Process Threats. Si vous ajoutez une menace à un Actor, vous pourrez uniquement choisir "Spoofing" et "Repudiation". Cependant, dans notre exemple, nous ajoutons une menace à une entité Process ; nous verrons donc ceci dans la boîte de création de menace :

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Terminé

Votre modèle terminé devrait maintenant ressembler à ceci. Voici comment créer un Threat Model simple avec OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Il s’agit d’un outil gratuit de Microsoft qui aide à identifier les menaces lors de la phase de conception des projets logiciels. Il utilise la méthodologie STRIDE et convient particulièrement aux personnes développant sur la stack de Microsoft.

{{#include ../banners/hacktricks-training.md}}
