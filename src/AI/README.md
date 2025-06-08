# AI en cybersécurité

{{#include ../banners/hacktricks-training.md}}

## Principaux algorithmes d'apprentissage automatique

Le meilleur point de départ pour apprendre sur l'IA est de comprendre comment fonctionnent les principaux algorithmes d'apprentissage automatique. Cela vous aidera à comprendre comment l'IA fonctionne, comment l'utiliser et comment l'attaquer :

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

Dans la page suivante, vous trouverez les bases de chaque composant pour construire un LLM de base en utilisant des transformateurs :

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Sécurité de l'IA

### Cadres de risque de l'IA

À ce moment, les 2 principaux cadres pour évaluer les risques des systèmes d'IA sont l'OWASP ML Top 10 et le Google SAIF :

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sécurité des prompts d'IA

Les LLMs ont fait exploser l'utilisation de l'IA ces dernières années, mais ils ne sont pas parfaits et peuvent être trompés par des prompts adversariaux. C'est un sujet très important pour comprendre comment utiliser l'IA en toute sécurité et comment l'attaquer :

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE des modèles d'IA

Il est très courant pour les développeurs et les entreprises d'exécuter des modèles téléchargés depuis Internet, cependant, le simple chargement d'un modèle peut suffire à exécuter du code arbitraire sur le système. C'est un sujet très important pour comprendre comment utiliser l'IA en toute sécurité et comment l'attaquer :

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protocole de contexte des modèles d'IA

MCP (Model Context Protocol) est un protocole qui permet aux clients agents d'IA de se connecter à des outils externes et à des sources de données de manière plug-and-play. Cela permet des flux de travail complexes et des interactions entre les modèles d'IA et les systèmes externes :

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
