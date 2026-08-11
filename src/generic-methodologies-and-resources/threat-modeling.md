# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

Bienvenue dans le guide complet de HackTricks sur le Threat Modeling ! Explorez cet aspect essentiel de la cybersécurité, qui consiste à identifier, comprendre et anticiper les vulnérabilités potentielles d'un système. Ce guide propose une démarche étape par étape, accompagnée d'exemples concrets, de logiciels utiles et d'explications faciles à comprendre. Il s'adresse aussi bien aux débutants qu'aux professionnels expérimentés souhaitant renforcer leurs défenses en cybersécurité.

### Scénarios couramment utilisés

1. **Développement logiciel** : dans le cadre du Secure Software Development Life Cycle (SSDLC), le Threat Modeling aide à **identifier les sources potentielles de vulnérabilités** dès les premières étapes du développement.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing** : le Penetration Testing Execution Standard (PTES) considère le Threat Modeling comme nécessaire à une exécution correcte et demande de documenter les actifs métier, les processus métier, les communautés de menace et leurs capacités.<sup>[[2]](#references)</sup>

### Le Threat Model en bref

Un Threat Model est généralement représenté par un diagramme, une image ou toute autre illustration visuelle d'une architecture prévue ou d'une application existante. Les Data-flow diagrams (DFD) sont une manière courante de modéliser un système et ses interactions, tandis que le Threat Modeling ajoute une analyse axée sur la sécurité.<sup>[[1]](#references)</sup>

Dans le Microsoft Threat Modeling Tool, les lignes rouges en pointillés indiquent les limites de confiance ; d'autres outils peuvent utiliser des conventions visuelles différentes.<sup>[[4]](#references)</sup> Pour faciliter l'identification des risques, les équipes peuvent utiliser le modèle CIA (Confidentiality, Integrity, Availability) ou les catégories de menace STRIDE, mais la méthodologie appropriée dépend du contexte et des exigences du projet.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### Le modèle CIA

Le modèle CIA est un modèle de sécurité de l'information largement reconnu, correspondant à Confidentiality, Integrity et Availability. Ces propriétés sont couramment utilisées pour décrire les objectifs de sécurité des données et des systèmes.<sup>[[3]](#references)</sup>

1. **Confidentiality** : garantir que les données ou le système ne sont pas accessibles à des personnes non autorisées. Il s'agit d'un aspect central de la sécurité, qui nécessite des contrôles d'accès appropriés, du chiffrement et d'autres mesures visant à empêcher les data breaches.
2. **Integrity** : exactitude, cohérence et fiabilité des données tout au long de leur cycle de vie. Ce principe garantit que les données ne sont pas modifiées ou altérées par des parties non autorisées. Il implique souvent des checksums, du hashing et d'autres méthodes de vérification des données.
3. **Availability** : garantir que les données et les services sont accessibles aux utilisateurs autorisés lorsqu'ils en ont besoin. Cela implique souvent de la redondance, de la fault tolerance et des configurations high-availability afin de maintenir les systèmes en fonctionnement même en cas de perturbations.

### Méthodologies de Threat Modeling

1. **STRIDE** : l'approche STRIDE de Microsoft catégorise les menaces logicielles en **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service et Elevation of Privilege**. Ces catégories aident les analystes à identifier les menaces possibles à chaque point vulnérable d'une conception.<sup>[[5]](#references)</sup>
2. **DREAD** : cette méthode d'évaluation de Microsoft attribue un score aux menaces selon **Damage, Reproducibility, Exploitability, Affected users et Discoverability**. Le score obtenu peut aider à prioriser les menaces à atténuer.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis) : il s'agit d'une méthodologie **risk-centric** en sept étapes couvrant les objectifs, le périmètre technique, la décomposition de l'application, l'analyse des menaces, l'analyse des vulnérabilités et des faiblesses, la modélisation des attaques ainsi que l'analyse des risques et de l'impact.<sup>[[8]](#references)</sup>
4. **Trike** : ce framework d'audit de sécurité aborde le Threat Modeling sous un angle de **risk-management** et de défense.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling) : cette méthode met l'accent sur des Threat Models évolutifs et utilisables pour les vues applicatives et opérationnelles, et peut s'intégrer aux cycles de développement et de DevOps.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation) : créé par la CERT Division du Software Engineering Institute de Carnegie Mellon, OCTAVE est une méthode stratégique d'évaluation et de planification fondée sur les risques, axée sur les risques organisationnels plutôt que sur la technologie seule.<sup>[[10]](#references)</sup>

## Tools

Plusieurs outils et solutions logicielles peuvent **aider** à créer et gérer des Threat Models. En voici quelques-uns que vous pouvez envisager.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite est un web crawler cross-platform destiné aux professionnels de la sécurité. Il prend en charge la cartographie de la surface d'attaque, la découverte des endpoints et l'analyse des applications web.<sup>[[6]](#references)</sup>

**Utilisation**

1. Choisissez une URL et lancez le Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Affichez le Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon est une application gratuite, open source et cross-platform de Threat Modeling, permettant de dessiner des diagrammes, de suggérer des menaces et d'enregistrer les mesures d'atténuation. Elle est disponible sous forme d'application web et desktop.<sup>[[7]](#references)</sup>

**Utilisation**

1. Créez un nouveau projet

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Il peut parfois se présenter ainsi :

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Lancez le nouveau projet

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Enregistrez le nouveau projet

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Créez votre modèle

Vous pouvez utiliser des outils comme SpiderSuite Crawler pour vous inspirer ; un modèle de base pourrait ressembler à ceci :

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Voici une brève explication des entités :

- Process (L'entité elle-même, comme un Webserver ou une fonctionnalité web)
- Actor (Une personne, comme un visiteur du site web, un utilisateur ou un administrateur)
- Data Flow Line (Indicateur d'interaction)
- Trust Boundary (Différents segments ou périmètres réseau.)
- Store (Éléments dans lesquels les données sont stockées, comme des bases de données)

5. Créez une menace (étape 1)

Vous devez d'abord sélectionner la couche à laquelle vous souhaitez ajouter une menace

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Vous pouvez maintenant créer la menace

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Gardez à l'esprit qu'il existe une différence entre les Actor Threats et les Process Threats. Si vous ajoutez une menace à un Actor, vous pourrez uniquement choisir « Spoofing » et « Repudiation ». Cependant, dans notre exemple, nous ajoutons une menace à une entité Process ; nous verrons donc ceci dans la boîte de création de menace :

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Terminé

Votre modèle terminé devrait maintenant ressembler à ceci. Voici comment créer un Threat Model simple avec OWASP Threat Dragon.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Le Microsoft Threat Modeling Tool est un outil téléchargeable gratuitement destiné à l'analyse de la conception logicielle. Son workflow crée un diagramme, identifie les menaces et prend en charge leur atténuation ainsi que la validation à l'aide de l'approche STRIDE.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - Guide du développeur OWASP](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Premiers pas avec le Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Threat Modeling for Drivers - Pilotes Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [Threat Modeling avec PASTA : les 7 étapes expliquées](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Document de méthodologie Trike v1](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling : résumé des méthodes disponibles](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
