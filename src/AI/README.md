# L’IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de machine learning

Pour commencer à découvrir l’IA, il est préférable de comprendre le fonctionnement des principaux algorithmes de machine learning. Cela vous aidera à comprendre le fonctionnement de l’IA, comment l’utiliser et comment l’attaquer :


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

### Architecture des LLM

La page suivante présente les bases de chaque composant nécessaire pour créer un LLM simple à l’aide de transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Outils et plateformes pour les modèles

Pour exécuter, effectuer le fine-tuning, déployer ou tester des modèles, consultez le [guide des outils et plateformes pour les modèles d’IA](AI-Model-Tools-and-Platforms.md).

## Sécurité de l’IA

### Limites de confiance des LLM Gateway

Pour la sécurité des gateways, consultez :

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

### Sécurité des prompts d’IA

L’utilisation de l’IA a explosé ces dernières années grâce aux LLM, mais ceux-ci ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il est très important de comprendre comment utiliser l’IA en toute sécurité et comment l’attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dans les modèles d’IA

Les développeurs et les entreprises exécutent très souvent des modèles téléchargés depuis Internet. Or, le simple fait de charger un modèle peut suffire à exécuter du code arbitraire sur le système. Il est très important de comprendre comment utiliser l’IA en toute sécurité et comment l’attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Contournement du KYC assisté par l’IA

La vidéo générative peut être combinée à l’injection d’une caméra virtuelle et à la manipulation de l’API de la caméra pour contourner les processus KYC, de vérification de l’âge et de détection de présence biométrique peu robustes :


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol pour l’IA

MCP (Model Context Protocol) est un protocole ouvert qui permet de connecter des applications d’IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent inclure l’autorisation, le consentement, la validation des entrées des outils et l’examen des limites de confiance.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assisté par l’IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analyse du code source et validation des vulnérabilités assistées par l’IA

Pour l’analyse des sources et des sinks, des flux de tâches liés aux points d’entrée mobiles, l’audit de patterns du noyau et la validation conditionnée par des preuves :

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Rétro-ingénierie assistée par l’IA

[Levée partielle, détection d’invariants MBA, décodage lié à l’environnement et validation d’extracteurs automatisés](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web black-box assistés par l’IA

Les agents propulsés par les LLM peuvent automatiser des workflows de pentesting web black-box de longue durée lorsqu’ils bénéficient d’observabilité, d’orchestration, de gestion de sessions authentifiées et de validation adversariale :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [Top 10 OWASP de la sécurité du machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Cadre d’IA sécurisée (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Présentation](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
