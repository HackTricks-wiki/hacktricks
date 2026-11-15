# L’IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de machine learning

Pour commencer à découvrir l’IA, il est préférable de comprendre le fonctionnement des principaux algorithmes de machine learning. Cela vous aidera à comprendre comment fonctionne l’IA, comment l’utiliser et comment l’attaquer :


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

Pour les partitions de jeux de données, les métriques classiques et les attaques côté réponse contre l’évaluation basée sur les LLM, consultez [la préparation et l’évaluation des données de modèles](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architecture des LLM

La page suivante présente les bases de chaque composant nécessaire pour construire un LLM simple avec des transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Outils et plateformes d’IA

Pour exécuter, affiner, déployer ou tester des modèles, consultez le [guide des outils et plateformes de modèles d’IA](AI-Model-Tools-and-Platforms.md).

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

Deux cadres utiles pour commencer à évaluer les risques des systèmes d’IA sont l’OWASP Machine Learning Security Top 10 et le Secure AI Framework (SAIF) de Google. Ils sont complémentaires et ne constituent pas une liste exhaustive des cadres de gestion des risques liés à l’IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Attaques adversariales guidées par l’interprétabilité mécanistique

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Limites de confiance des navigateurs intégrés

Pour les passerelles de navigateur des assistants de bureau, l’usurpation d’adresse d’onglet et la lecture de fichiers locaux dans le contexte d’un worker, consultez [les limites de confiance des navigateurs intégrés aux assistants d’IA](AI-Embedded-Browser-Trust-Boundaries.md).

### Sécurité des prompts d’IA

Ces dernières années, les LLM ont fortement popularisé l’utilisation de l’IA, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il est très important de comprendre comment utiliser l’IA en toute sécurité et comment l’attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE sur les modèles d’IA

Il est très courant que des développeurs et des entreprises exécutent des modèles téléchargés depuis Internet. Or, le simple chargement d’un modèle peut suffire à exécuter du code arbitraire sur le système. Il est très important de comprendre comment utiliser l’IA en toute sécurité et comment l’attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Contournement du KYC assisté par l’IA

La vidéo générative peut être combinée à l’injection d’une caméra virtuelle et à la manipulation des API de caméra pour contourner des processus KYC, de vérification de l’âge et de détection de présence biométrique peu robustes :


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol de l’IA

MCP (Model Context Protocol) est un protocole ouvert qui permet de connecter des applications d’IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent porter sur l’autorisation, le consentement, la validation des entrées des outils et l’examen des limites de confiance.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocole agent-à-agent (A2A) de l’IA

A2A permet aux agents de se découvrir grâce à une fiche d’agent et de s’envoyer des tâches via HTTP. Testez les fiches d’agent, l’autorisation des tâches, les webhooks de notification push et les fiches étendues :

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Services d’IA auto-hébergés exposés

Identifiez et testez les moteurs de modèles, les outils de création d’agents, les interfaces de démonstration ML, les clusters de calcul et les bases de données vectorielles exposés et fonctionnant sans authentification :

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assisté par l’IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analyse de code source assistée par l’IA et validation des vulnérabilités

Pour l’analyse des sources et des puits, les taskflows de points d’entrée mobiles, les audits de motifs du noyau et la validation soumise à des exigences de preuve :

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Rétro-ingénierie assistée par l’IA

[Levée partielle, détection d’invariants MBA, décodage lié à l’environnement et validation des extracteurs automatisés](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web en boîte noire basés sur l’IA

Les agents basés sur des LLM peuvent automatiser des workflows de pentesting web en boîte noire de longue durée, à condition de disposer d’observabilité, d’orchestration, de gestion de sessions authentifiées et de validation adversariale :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [Top 10 OWASP de la sécurité du machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Cadre de sécurité de l’IA (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
