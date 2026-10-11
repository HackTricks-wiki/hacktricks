# L’IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de machine learning

Pour découvrir l’IA, le mieux est de commencer par comprendre le fonctionnement des principaux algorithmes de machine learning. Cela vous aidera à comprendre le fonctionnement de l’IA, à l’utiliser et à l’attaquer :


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

La page suivante présente les bases de chaque composant nécessaire pour créer un LLM élémentaire à l’aide de transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sécurité de l’IA

### Méthodologie de sécurité des agents IA

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Frameworks de gestion des risques liés à l’IA

Deux frameworks utiles pour commencer à évaluer les risques des systèmes d’IA sont l’OWASP Machine Learning Security Top 10 et le Secure AI Framework (SAIF) de Google. Ils sont complémentaires et ne constituent pas une liste exhaustive des frameworks de gestion des risques liés à l’IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sécurité des prompts IA

L’utilisation de l’IA a explosé ces dernières années grâce aux LLM, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il est très important de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE via des modèles d’IA

Il est très fréquent que des développeurs et des entreprises exécutent des modèles téléchargés depuis Internet. Or, le simple fait de charger un modèle peut suffire à exécuter du code arbitraire sur le système. Il est très important de comprendre ce sujet pour utiliser l’IA en toute sécurité et savoir comment l’attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Contournement du KYC assisté par l’IA

La vidéo générative peut être combinée à l’injection d’une caméra virtuelle et à la manipulation des API de caméra pour contourner des procédures de KYC, de vérification de l’âge et de contrôle de présence biométrique peu robustes :


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol pour l’IA

MCP (Model Context Protocol) est un protocole ouvert qui permet de connecter des applications d’IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent porter sur l’autorisation, le consentement, la validation des entrées des outils et l’examen des frontières de confiance.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assisté par l’IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Rétro-ingénierie assistée par l’IA

[Réduction partielle, détection d’invariants MBA, décodage lié à l’environnement et validation d’extracteurs automatisés](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Bots de pentesting web en boîte noire assistés par l’IA

Les agents propulsés par des LLM peuvent automatiser des workflows de pentesting web en boîte noire de longue durée, à condition de disposer d’observabilité, d’orchestration, de gestion de sessions authentifiées et de validation adversariale :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [Top 10 OWASP de la sécurité du machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Framework d’IA sécurisée (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
