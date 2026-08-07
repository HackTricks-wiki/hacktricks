# Entraînement des LLM - Préparation des données

{{#include ../../banners/hacktricks-training.md}}

**Voici mes notes tirées du livre vivement recommandé** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **avec quelques informations supplémentaires.**<sup>[[1]](#references)</sup>

## Informations de base

Vous devriez commencer par lire cet article pour découvrir certains concepts de base que vous devez connaître :


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> L'objectif de cette phase initiale est très simple : **Diviser l'entrée en tokens (ids) d'une manière cohérente**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> L'objectif de cette deuxième phase est très simple : **Échantillonner les données d'entrée et les préparer pour la phase d'entraînement, généralement en séparant le dataset en phrases d'une longueur spécifique et en générant également la réponse attendue.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'objectif de cette troisième phase est très simple : **Attribuer à chacun des tokens précédents du vocabulaire un vecteur des dimensions souhaitées afin d'entraîner le modèle.** Chaque mot du vocabulaire sera un point dans un espace de X dimensions.\
> Notez qu'initialement, la position de chaque mot dans l'espace est simplement initialisée de manière « aléatoire » et que ces positions sont des paramètres entraînables (elles seront améliorées pendant l'entraînement).
>
> De plus, pendant le token embedding, **une autre couche d'embeddings est créée**, qui représente (dans ce cas) la **position absolue du mot dans la phrase d'entraînement**. Ainsi, un mot situé à différentes positions dans la phrase aura une représentation (signification) différente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> L'objectif de cette quatrième phase est très simple : **Appliquer certains mécanismes d'attention**. Il s'agira de nombreuses **couches répétées** qui vont **capturer la relation entre un mot du vocabulaire et ses voisins dans la phrase utilisée pour entraîner le LLM**.\
> De nombreuses couches sont utilisées à cette fin ; de nombreux paramètres entraînables vont donc capturer ces informations.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architecture du LLM

> [!TIP]
> L'objectif de cette cinquième phase est très simple : **Développer l'architecture complète du LLM**. Tout assembler, appliquer toutes les couches et créer toutes les fonctions permettant de générer du texte ou de transformer du texte en IDs et inversement.
>
> Cette architecture sera utilisée à la fois pour l'entraînement et pour la prédiction de texte après son entraînement.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> L'objectif de cette sixième phase est très simple : **Entraîner le modèle from scratch**. Pour cela, l'architecture précédente du LLM sera utilisée avec des boucles parcourant les datasets, en utilisant les fonctions de perte et l'optimizer définis afin d'entraîner tous les paramètres du modèle.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> L'utilisation de **LoRA réduit considérablement les calculs** nécessaires pour **fine-tuner** des modèles déjà entraînés.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> L'objectif de cette section est de montrer comment fine-tuner un modèle déjà pré-entraîné afin qu'au lieu de générer du nouveau texte, le LLM sélectionne et donne les **probabilités que le texte fourni appartienne à chacune des catégories données** (par exemple, déterminer si un texte est du spam ou non).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> L'objectif de cette section est de montrer comment **fine-tuner un modèle déjà pré-entraîné pour suivre des instructions**, plutôt que de simplement générer du texte, par exemple en répondant à des tâches comme un chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Références

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
