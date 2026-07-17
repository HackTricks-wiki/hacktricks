# L'IA en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes de Machine Learning

Le meilleur point de départ pour apprendre l'IA est de comprendre le fonctionnement des principaux algorithmes de Machine Learning. Cela vous aidera à comprendre comment fonctionne l'IA, comment l'utiliser et comment l'attaquer :


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

Sur la page suivante, vous trouverez les bases de chaque composant nécessaire pour créer un LLM basique à l'aide de transformers :


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sécurité de l'IA

### Frameworks de gestion des risques liés à l'IA

À l'heure actuelle, les deux principaux frameworks permettant d'évaluer les risques des systèmes d'IA sont l'OWASP ML Top 10 et le Google SAIF :


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sécurité des prompts d'IA

Les LLM ont fait exploser l'utilisation de l'IA ces dernières années, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. Il s'agit d'un sujet très important pour comprendre comment utiliser l'IA en toute sécurité et comment l'attaquer :


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE des modèles d'IA

Il est très courant que les développeurs et les entreprises exécutent des modèles téléchargés depuis Internet. Cependant, le simple chargement d'un modèle peut suffire à exécuter du code arbitraire sur le système. Il s'agit d'un sujet très important pour comprendre comment utiliser l'IA en toute sécurité et comment l'attaquer :


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Model Context Protocol de l'IA

MCP (Model Context Protocol) est un protocole qui permet aux clients agents d'IA de se connecter à des outils et à des sources de données externes de manière plug-and-play. Cela permet des workflows complexes et des interactions entre les modèles d'IA et les systèmes externes :


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing assisté par l'IA et découverte automatisée de vulnérabilités


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Bots de pentesting Web Black-Box alimentés par l'IA

Les agents alimentés par des LLM peuvent automatiser des workflows de pentesting Web Black-Box de longue durée lorsqu'ils bénéficient d'observabilité, d'orchestration, de gestion de sessions authentifiées et de validation adversariale :


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
