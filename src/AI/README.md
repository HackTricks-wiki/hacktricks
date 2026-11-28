# L’IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de machine learning

Pour commencer à apprendre l’IA, il est préférable de comprendre le fonctionnement des principaux algorithmes de machine learning. Cela vous aidera à comprendre comment fonctionne l’IA, comment l’utiliser et comment l’attaquer :

{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### Préparation et évaluation des données de modèles

Pour les partitions de jeux de données, les métriques classiques et les attaques côté réponse sur la notation basée sur les LLM, consultez la page [préparation et évaluation des données de modèles](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architecture des LLM

La page suivante présente les bases de chaque composant nécessaire à la création d’un LLM élémentaire avec des transformers :

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Outils et plateformes pour les modèles d’IA

Pour exécuter, affiner, héberger ou essayer des modèles, consultez le [guide des outils et plateformes pour les modèles d’IA](AI-Model-Tools-and-Platforms.md).

## Sécurité de l’IA

### Limites de confiance des passerelles LLM

Pour la sécurité des passerelles, consultez :

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Méthodologie de sécurité des agents d’IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Cadres de gestion des risques liés à l’IA

Deux cadres de référence utiles pour évaluer les risques des systèmes d’IA sont l’OWASP Machine Learning Security Top 10 et le Secure AI Framework (SAIF) de Google. Ils sont complémentaires et ne constituent pas une liste exhaustive des cadres de gestion des risques liés à l’IA.<sup>[[1]](#references)[[2]](#references)</sup>

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attaques adversariales guidées par l’interprétabilité mécanistique

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Limites de confiance des navigateurs intégrés

Pour les ponts de navigateurs d’assistants de bureau, l’usurpation d’adresse d’onglet et la lecture de fichiers locaux depuis le contexte d’un worker, consultez [les limites de confiance des navigateurs intégrés aux assistants d’IA](AI-Embedded-Browser-Trust-Boundaries.md).

### Sécurité des prompts d’IA

L’utilisation de l’IA a explosé ces dernières années grâce aux LLM, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il est essentiel de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE des modèles d’IA

Les développeurs et les entreprises exécutent souvent des modèles téléchargés depuis Internet. Pourtant, il peut suffire de charger un modèle pour exécuter du code arbitraire sur le système. Il est essentiel de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :

{{#ref}}
AI-Models-RCE.md
{{#endref}}

Pour les risques liés au chargement de modèles Keras `.keras`/HDF5, aux couches Lambda et à l’analyse de gadgets après correctif, consultez [la désérialisation de modèles Keras et la recherche de gadgets](keras-model-deserialization-rce-and-gadget-hunting.md).

### Contournement du KYC assisté par l’IA

La vidéo générative peut être combinée à l’injection de caméra virtuelle et à la manipulation de l’API de caméra pour contourner les processus KYC, de vérification de l’âge et de détection de présence biométrique peu robustes :

{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de l’IA

MCP (Model Context Protocol) est un protocole ouvert permettant de connecter des applications d’IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent couvrir l’autorisation, le consentement, la validation des entrées des outils et l’examen des limites de confiance.<sup>[[3]](#references)</sup>

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocole Agent-to-Agent (A2A) de l’IA

A2A permet aux agents de se découvrir au moyen d’une fiche d’agent et de s’envoyer des tâches via HTTP. Testez les fiches d’agent, l’autorisation des tâches, les webhooks de notification push et les fiches étendues :

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Services d’IA auto-hébergés exposés

Empreinte et tests des exécuteurs de modèles, outils de création d’agents, interfaces de démonstration ML, clusters de calcul et bases de données vectorielles exposés sans authentification :

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assisté par l’IA et découverte automatisée de vulnérabilités

{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analyse de code source et validation de vulnérabilités assistées par l’IA

Pour l’analyse des sources et des sinks, les parcours de tâches des points d’entrée mobiles, l’audit de patterns du noyau et la validation fondée sur des preuves :

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Rétro-ingénierie assistée par l’IA

[Levée partielle, détection d’invariants MBA, décodage lié à l’environnement et validation d’extracteurs automatisés](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web en boîte noire avec l’IA

Les agents propulsés par des LLM peuvent automatiser des workflows de pentesting web en boîte noire de longue durée, à condition de disposer d’observabilité, d’orchestration, de gestion de sessions authentifiées et de validation adversariale :

{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — Top 10 de la sécurité du machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Cadre Secure AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
