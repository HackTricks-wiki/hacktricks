# AI Risks

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp a identifié les 10 principales vulnérabilités en apprentissage automatique qui peuvent affecter les systèmes d'IA. Ces vulnérabilités peuvent entraîner divers problèmes de sécurité, notamment le poisoning de données, l'inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est crucial pour construire des systèmes d'IA sécurisés.

Pour une liste mise à jour et détaillée des 10 principales vulnérabilités en apprentissage automatique, référez-vous au projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack** : Un attaquant ajoute de minuscules changements, souvent invisibles, aux **données entrantes** afin que le modèle prenne la mauvaise décision.\
*Exemple* : Quelques éclaboussures de peinture sur un panneau stop trompent une voiture autonome en lui faisant "voir" un panneau de limite de vitesse.

- **Data Poisoning Attack** : L'**ensemble d'entraînement** est délibérément pollué avec de mauvais échantillons, enseignant au modèle des règles nuisibles.\
*Exemple* : Des binaires de malware sont mal étiquetés comme "bénins" dans un corpus d'entraînement antivirus, permettant à des malwares similaires de passer plus tard.

- **Model Inversion Attack** : En sondant les sorties, un attaquant construit un **modèle inverse** qui reconstruit des caractéristiques sensibles des entrées originales.\
*Exemple* : Recréer l'image IRM d'un patient à partir des prédictions d'un modèle de détection de cancer.

- **Membership Inference Attack** : L'adversaire teste si un **enregistrement spécifique** a été utilisé lors de l'entraînement en repérant des différences de confiance.\
*Exemple* : Confirmer qu'une transaction bancaire d'une personne apparaît dans les données d'entraînement d'un modèle de détection de fraude.

- **Model Theft** : Des requêtes répétées permettent à un attaquant d'apprendre les frontières de décision et de **cloner le comportement du modèle** (et la propriété intellectuelle).\
*Exemple* : Récolter suffisamment de paires Q&A d'une API ML-as-a-Service pour construire un modèle local quasi équivalent.

- **AI Supply‑Chain Attack** : Compromettre n'importe quel composant (données, bibliothèques, poids pré-entraînés, CI/CD) dans le **pipeline ML** pour corrompre les modèles en aval.\
*Exemple* : Une dépendance empoisonnée sur un hub de modèles installe un modèle d'analyse de sentiment avec porte dérobée dans de nombreuses applications.

- **Transfer Learning Attack** : Une logique malveillante est plantée dans un **modèle pré-entraîné** et survit à l'ajustement fin sur la tâche de la victime.\
*Exemple* : Un backbone de vision avec un déclencheur caché continue de changer les étiquettes après avoir été adapté pour l'imagerie médicale.

- **Model Skewing** : Des données subtilement biaisées ou mal étiquetées **déplacent les sorties du modèle** pour favoriser l'agenda de l'attaquant.\
*Exemple* : Injecter des e-mails de spam "propres" étiquetés comme ham afin qu'un filtre anti-spam laisse passer des e-mails similaires à l'avenir.

- **Output Integrity Attack** : L'attaquant **modifie les prédictions du modèle en transit**, pas le modèle lui-même, trompant les systèmes en aval.\
*Exemple* : Changer le verdict "malveillant" d'un classificateur de malware en "bénin" avant que la phase de quarantaine de fichier ne le voie.

- **Model Poisoning** --- Changements directs et ciblés aux **paramètres du modèle** eux-mêmes, souvent après avoir obtenu un accès en écriture, pour altérer le comportement.\
*Exemple* : Ajuster les poids d'un modèle de détection de fraude en production afin que les transactions de certaines cartes soient toujours approuvées.


## Google SAIF Risks

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google décrit divers risques associés aux systèmes d'IA :

- **Data Poisoning** : Des acteurs malveillants modifient ou injectent des données d'entraînement/ajustement pour dégrader la précision, implanter des portes dérobées ou fausser les résultats, compromettant l'intégrité du modèle tout au long du cycle de vie des données.

- **Unauthorized Training Data** : L'ingestion de jeux de données protégés par des droits d'auteur, sensibles ou non autorisés crée des responsabilités légales, éthiques et de performance car le modèle apprend à partir de données qu'il n'était jamais autorisé à utiliser.

- **Model Source Tampering** : La manipulation de la chaîne d'approvisionnement ou d'un initié du code du modèle, des dépendances ou des poids avant ou pendant l'entraînement peut intégrer une logique cachée qui persiste même après le réentraînement.

- **Excessive Data Handling** : Des contrôles de conservation et de gouvernance des données faibles conduisent les systèmes à stocker ou traiter plus de données personnelles que nécessaire, augmentant l'exposition et le risque de conformité.

- **Model Exfiltration** : Les attaquants volent des fichiers/poids de modèle, entraînant une perte de propriété intellectuelle et permettant des services de copie ou des attaques ultérieures.

- **Model Deployment Tampering** : Les adversaires modifient les artefacts du modèle ou l'infrastructure de service afin que le modèle en cours d'exécution diffère de la version validée, changeant potentiellement le comportement.

- **Denial of ML Service** : Inonder les API ou envoyer des entrées "éponge" peut épuiser les ressources de calcul/énergie et mettre le modèle hors ligne, imitant les attaques DoS classiques.

- **Model Reverse Engineering** : En récoltant un grand nombre de paires entrée-sortie, les attaquants peuvent cloner ou distiller le modèle, alimentant des produits d'imitation et des attaques adversariales personnalisées.

- **Insecure Integrated Component** : Des plugins, agents ou services en amont vulnérables permettent aux attaquants d'injecter du code ou d'escalader des privilèges au sein du pipeline d'IA.

- **Prompt Injection** : Élaborer des invites (directement ou indirectement) pour faire passer des instructions qui contournent l'intention du système, amenant le modèle à exécuter des commandes non intentionnelles.

- **Model Evasion** : Des entrées soigneusement conçues déclenchent le modèle pour qu'il classe mal, hallucine ou produise du contenu interdit, érodant la sécurité et la confiance.

- **Sensitive Data Disclosure** : Le modèle révèle des informations privées ou confidentielles provenant de ses données d'entraînement ou du contexte utilisateur, violant la vie privée et les réglementations.

- **Inferred Sensitive Data** : Le modèle déduit des attributs personnels qui n'ont jamais été fournis, créant de nouveaux préjudices à la vie privée par inférence.

- **Insecure Model Output** : Des réponses non assainies transmettent du code nuisible, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions** : Des agents intégrés de manière autonome exécutent des opérations réelles non intentionnelles (écritures de fichiers, appels API, achats, etc.) sans supervision adéquate de l'utilisateur.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d'IA. Elle catégorise diverses techniques et tactiques d'attaque que les adversaires peuvent utiliser contre les modèles d'IA et comment utiliser les systèmes d'IA pour effectuer différentes attaques.


{{#include ../banners/hacktricks-training.md}}
