# Outils et plateformes de modèles d’IA

{{#include ../banners/hacktricks-training.md}}

## Exécuter et entraîner des modèles localement

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers est une bibliothèque open source permettant de charger, d’entraîner et de servir des modèles préentraînés pour des tâches liées au texte, à la vision, à l’audio, à la vidéo et au multimodal. L’hébergement des modèles et des jeux de données est assuré séparément par Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain est un framework permettant de créer des applications et des agents pilotés par des modèles, avec des fonctions de construction de prompts, de gestion de l’historique et de l’état des conversations, d’utilisation d’outils, de récupération d’informations et d’intégration de modèles, d’API et de bases de données.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT fournit des implémentations lisibles et des workflows en ligne de commande pour le préentraînement, le fine-tuning, l’évaluation et le déploiement des modèles de langage pris en charge.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description :**\
LitServe est un framework de déploiement de modèles de Lightning AI qui permet d’exposer des API d’inférence avec des mécanismes de batching, de streaming, d’accélération et de mise à l’échelle.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl est un framework open source de post-entraînement et de fine-tuning, configuré à l’aide de fichiers YAML. Il prend en charge des techniques telles que le fine-tuning complet, LoRA/QLoRA, l’optimisation des préférences et l’entraînement multi-GPU ; il ne s’agit pas en soi d’une plateforme de déploiement cloud.<sup>[[5]](#references)</sup>

## Essayer des modèles en ligne

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** est une plateforme et une communauté de premier plan dans le domaine du machine learning, particulièrement connue pour ses travaux en traitement automatique du langage naturel (NLP). Elle fournit des outils, des bibliothèques et des ressources qui facilitent le développement, le partage et le déploiement de modèles de machine learning.\
Le Hub propose plusieurs sections pertinentes :<sup>[[6]](#references)</sup>

* **Models** : Un vaste référentiel de **modèles de machine learning préentraînés** que les utilisateurs peuvent parcourir, télécharger et intégrer pour diverses tâches, comme la génération de texte, la traduction, la reconnaissance d’images, etc.
* **Datasets :** Une vaste **collection de jeux de données** utilisés pour entraîner et évaluer des modèles. Elle facilite l’accès à diverses sources de données, permettant aux utilisateurs de trouver et d’exploiter des données pour leurs projets de machine learning.
* **Spaces :** Une plateforme d’hébergement et de partage d’**applications interactives de machine learning** et de démonstrations. Elle permet aux développeurs de **présenter** leurs modèles en action, de créer des interfaces conviviales et de collaborer avec d’autres en partageant des démonstrations en direct.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **et** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** est un référentiel et une bibliothèque de composants de modèles entraînés et réutilisables, notamment des modules utilisés avec TensorFlow/Keras. **Kaggle** propose séparément des notebooks, des jeux de données, des compétitions et des modèles.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules :** Une vaste collection de modèles et de composants de modèles préentraînés que les utilisateurs peuvent parcourir, télécharger et intégrer pour des tâches telles que la classification d’images, la représentation vectorielle de texte, etc.
* **Tutoriels :** Des guides détaillés et des exemples qui aident les utilisateurs à implémenter et à affiner des modèles à l’aide de TensorFlow Hub.
* **Documentation :** Des guides complets et des références d’API qui aident les développeurs à utiliser efficacement les ressources du référentiel.

## [**Replicate**](https://replicate.com/home)

**Replicate** est une plateforme hébergée permettant d’exécuter des modèles de machine learning empaquetés via une interface web ou une API.<sup>[[8]](#references)</sup>

* **Models :** Un référentiel de modèles de machine learning proposés par la communauté, que les utilisateurs peuvent parcourir, essayer et intégrer à leurs applications avec un minimum d’efforts.
* **Accès à l’API :** Des API permettant d’appeler des modèles depuis des applications sans gérer l’infrastructure d’inférence sous-jacente.

## Attaquer des services d’IA exposés et auto-hébergés

Pour le fingerprinting et les tests en boîte noire de moteurs de modèles auto-hébergés, de constructeurs d’agents, d’interfaces de démonstration ML, de clusters de calcul et de bases de données vectorielles, consultez [Services d’IA exposés et auto-hébergés](AI-Exposed-Self-Hosted-AI-Services.md).

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Documentation de Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Documentation de Replicate](https://replicate.com/docs)
- [9] [Documentation de Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
