# L'IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de Machine Learning

Le meilleur point de départ pour découvrir l'IA est de comprendre le fonctionnement des principaux algorithmes de Machine Learning. Cela vous aidera à comprendre comment fonctionne l'IA, comment l'utiliser et comment l'attaquer :


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

### Architecture des LLMs

Dans la page suivante, vous trouverez les bases de chaque composant nécessaire pour construire un LLM basique à l'aide de transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sécurité de l'IA

### Frameworks de gestion des risques liés à l'IA

Deux frameworks de départ utiles pour évaluer les risques liés aux systèmes d'IA sont l'OWASP Machine Learning Security Top 10 et le Secure AI Framework (SAIF) de Google. Ils sont complémentaires et ne constituent pas une liste exhaustive des frameworks de gestion des risques liés à l'IA.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sécurité des prompts d'IA

Les LLMs ont considérablement accru l'utilisation de l'IA ces dernières années, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adverses. Il s'agit d'un sujet très important pour comprendre comment utiliser l'IA de manière sûre et comment l'attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE dans les modèles d'IA

Il est très courant que les développeurs et les entreprises exécutent des modèles téléchargés depuis Internet. Cependant, le simple chargement d'un modèle peut suffire à exécuter du code arbitraire sur le système. Il s'agit d'un sujet très important pour comprendre comment utiliser l'IA de manière sûre et comment l'attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Contournement du KYC assisté par l'IA

La vidéo générative peut être combinée à une injection de caméra virtuelle et à la manipulation de l'API de la caméra pour contourner les processus KYC, de vérification de l'âge et de détection de présence biométrique insuffisamment sécurisés :


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol pour l'IA

MCP (Model Context Protocol) est un protocole ouvert permettant de connecter des applications d'IA à des outils et à des sources de données. Comme les serveurs MCP peuvent exposer des données et des actions, les évaluations doivent inclure l'autorisation, le consentement, la validation des entrées des outils et l'examen des limites de confiance.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assisté par l'IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bots de pentesting Web black-box utilisant l'IA

Les agents propulsés par des LLMs peuvent automatiser des workflows de pentesting Web black-box de longue durée lorsqu'ils bénéficient d'une observabilité, d'une orchestration, de la gestion de sessions authentifiées et d'une validation adverse :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
