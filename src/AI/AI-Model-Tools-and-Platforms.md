# Outils et plateformes de modèles d’IA

{{#include ../banners/hacktricks-training.md}}

## Exécuter et entraîner des modèles localement

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers est une bibliothèque open source permettant de charger, d’entraîner et de servir des modèles préentraînés pour des tâches liées au texte, à la vision, à l’audio, à la vidéo et au multimodal. L’hébergement des modèles et des datasets est fourni séparément par Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain est un framework pour créer des applications et des agents pilotés par des modèles. Il permet de construire des prompts, de gérer l’historique et l’état des conversations, et d’intégrer des outils, la recherche d’informations, des modèles, des API et des bases de données.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT propose des implémentations lisibles et des workflows en ligne de commande pour le préentraînement, le fine-tuning, l’évaluation et le déploiement des modèles de langage pris en charge.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description :**\
LitServe est un framework de serving de modèles de Lightning AI permettant d’exposer des API d’inférence avec des mécanismes de batching, de streaming, d’accélération et de mise à l’échelle.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl est un framework open source de post-entraînement et de fine-tuning piloté par une configuration YAML. Il prend en charge des techniques telles que le fine-tuning complet, LoRA/QLoRA, l’optimisation des préférences et l’entraînement multi-GPU ; ce n’est pas en soi une plateforme de déploiement cloud.<sup>[[5]](#references)</sup>

## Essayer des modèles en ligne

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** est une plateforme et une communauté de premier plan dans le domaine du machine learning, particulièrement connue pour ses travaux en traitement automatique du langage naturel (NLP). Elle fournit des outils, des bibliothèques et des ressources qui facilitent le développement, le partage et le déploiement de modèles de machine learning.\
Le Hub propose plusieurs sections pertinentes :<sup>[[6]](#references)</sup>

* **Modèles** : Un vaste répertoire de **modèles de machine learning préentraînés** que les utilisateurs peuvent parcourir, télécharger et intégrer pour diverses tâches telles que la génération de texte, la traduction, la reconnaissance d’images et bien plus encore.
* **Datasets :** Une vaste **collection de datasets** utilisés pour entraîner et évaluer des modèles. Elle facilite l’accès à diverses sources de données, permettant aux utilisateurs de trouver et d’utiliser des données pour leurs projets de machine learning.
* **Spaces :** Une plateforme d’hébergement et de partage d’**applications interactives de machine learning** et de démos. Elle permet aux développeurs de **présenter** leurs modèles en action, de créer des interfaces conviviales et de collaborer avec d’autres en partageant des démos en direct.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** est un répertoire et une bibliothèque de composants de modèles entraînés réutilisables, notamment des modules utilisés via TensorFlow/Keras. **Kaggle** fournit séparément des notebooks, des datasets, des compétitions et des modèles.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules :** Une vaste collection de modèles préentraînés et de composants de modèles que les utilisateurs peuvent parcourir, télécharger et intégrer pour des tâches telles que la classification d’images, la vectorisation de texte et bien plus encore.
* **Tutoriels :** Des guides détaillés et des exemples qui aident les utilisateurs à implémenter et à affiner des modèles avec TensorFlow Hub.
* **Documentation :** Des guides complets et des références d’API qui aident les développeurs à utiliser efficacement les ressources du répertoire.

## [**Replicate**](https://replicate.com/home)

**Replicate** est une plateforme hébergée permettant d’exécuter des modèles de machine learning empaquetés via une interface web ou une API.<sup>[[8]](#references)</sup>

* **Modèles :** Un répertoire de modèles de machine learning proposés par la communauté. Les utilisateurs peuvent les parcourir, les essayer et les intégrer à leurs applications avec un minimum d’efforts.
* **Accès à l’API :** Des API permettant d’appeler des modèles depuis des applications sans exploiter l’infrastructure d’inférence sous-jacente.

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
