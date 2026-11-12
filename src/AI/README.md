# L’IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de machine learning

Le meilleur point de départ pour découvrir l’IA est de comprendre le fonctionnement des principaux algorithmes de machine learning. Cela vous aidera à comprendre comment fonctionne l’IA, comment l’utiliser et comment l’attaquer :


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

### Préparation et évaluation des données des modèles

Pour les divisions de jeux de données, les métriques classiques et les attaques côté réponse contre l’évaluation basée sur les LLM, consultez [la préparation et l’évaluation des données des modèles](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architecture des LLM

La page suivante présente les bases de chaque composant nécessaire à la création d’un LLM élémentaire à l’aide de transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Outils et plateformes de modèles d’IA

Pour exécuter, affiner, déployer ou essayer des modèles, consultez le [guide des outils et plateformes de modèles d’IA](AI-Model-Tools-and-Platforms.md).

## Sécurité de l’IA

### Limites de confiance des passerelles LLM

Pour la sécurité des passerelles, consultez :

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Méthodologie de sécurité des agents IA

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

### Sécurité des prompts d’IA

Ces dernières années, les LLM ont entraîné une explosion de l’utilisation de l’IA, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il est essentiel de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dans les modèles d’IA

Il est très courant que des développeurs et des entreprises exécutent des modèles téléchargés depuis Internet. Or, le simple chargement d’un modèle peut suffire à exécuter du code arbitraire sur le système. Il est essentiel de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Contournement du KYC assisté par l’IA

La vidéo générative peut être associée à l’injection de caméra virtuelle et à la manipulation de l’API de la caméra pour contourner les processus KYC, de vérification de l’âge et de détection de présence biométrique peu robustes :


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol pour l’IA

MCP (Model Context Protocol) est un protocole ouvert qui permet de connecter des applications d’IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent couvrir l’autorisation, le consentement, la validation des entrées des outils et l’examen des limites de confiance.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protocole agent-à-agent (A2A) de l’IA

A2A permet aux agents de se découvrir mutuellement au moyen d’une fiche d’agent et de s’envoyer des tâches via HTTP. Testez les fiches d’agent, l’autorisation des tâches, les webhooks de notification push et les fiches étendues :

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Services d’IA auto-hébergés exposés

Identifiez et testez les runners de modèles, les constructeurs d’agents, les interfaces de démonstration ML, les clusters de calcul et les bases de données vectorielles exposés et fonctionnant sans authentification :

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing assisté par l’IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analyse du code source et validation des vulnérabilités assistées par l’IA

Pour l’examen des sources et des sinks, des workflows de tâches ciblant les points d’entrée mobiles, des audits de motifs du kernel et une validation soumise à des critères de preuve :

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Rétro-ingénierie assistée par l’IA

[Levée partielle, détection d’invariants MBA, décodage lié à l’environnement et validation d’extracteurs automatisés](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web IA en boîte noire

Les agents propulsés par des LLM peuvent automatiser des workflows de pentesting web en boîte noire de longue durée, à condition de disposer d’observabilité, d’orchestration, de gestion des sessions authentifiées et de validation adversariale :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [Les 10 principaux risques de sécurité du machine learning selon OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Cadre de sécurité de l’IA (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
