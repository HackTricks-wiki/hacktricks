# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**Ce sont mes notes du livre très recommandé** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **avec quelques informations supplémentaires.**

## Basic Information

Vous devriez commencer par lire ce post pour quelques concepts de base que vous devez connaître :

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> L'objectif de cette phase initiale est très simple : **Diviser l'entrée en tokens (ids) d'une manière qui a du sens**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> L'objectif de cette deuxième phase est très simple : **Échantillonner les données d'entrée et les préparer pour la phase d'entraînement, généralement en séparant le jeu de données en phrases d'une longueur spécifique et en générant également la réponse attendue.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'objectif de cette troisième phase est très simple : **Attribuer à chacun des tokens précédents dans le vocabulaire un vecteur des dimensions souhaitées pour entraîner le modèle.** Chaque mot dans le vocabulaire sera un point dans un espace de X dimensions.\
> Notez qu'initialement, la position de chaque mot dans l'espace est simplement initialisée "au hasard" et ces positions sont des paramètres entraînables (seront améliorés pendant l'entraînement).
>
> De plus, pendant l'embedding des tokens, **une autre couche d'embeddings est créée** qui représente (dans ce cas) la **position absolue du mot dans la phrase d'entraînement**. De cette façon, un mot à différentes positions dans la phrase aura une représentation différente (signification).

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> L'objectif de cette quatrième phase est très simple : **Appliquer certains mécanismes d'attention**. Ceux-ci vont être beaucoup de **couches répétées** qui vont **capturer la relation d'un mot dans le vocabulaire avec ses voisins dans la phrase actuelle utilisée pour entraîner le LLM**.\
> Beaucoup de couches sont utilisées pour cela, donc beaucoup de paramètres entraînables vont capturer cette information.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> L'objectif de cette cinquième phase est très simple : **Développer l'architecture du LLM complet**. Mettre tout ensemble, appliquer toutes les couches et créer toutes les fonctions pour générer du texte ou transformer du texte en IDs et vice versa.
>
> Cette architecture sera utilisée à la fois pour l'entraînement et pour prédire du texte après qu'il ait été entraîné.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> L'objectif de cette sixième phase est très simple : **Entraîner le modèle à partir de zéro**. Pour cela, l'architecture LLM précédente sera utilisée avec quelques boucles parcourant les ensembles de données en utilisant les fonctions de perte et l'optimiseur définis pour entraîner tous les paramètres du modèle.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> L'utilisation de **LoRA réduit beaucoup le calcul** nécessaire pour **affiner** des modèles déjà entraînés.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> L'objectif de cette section est de montrer comment affiner un modèle déjà pré-entraîné afin qu'au lieu de générer un nouveau texte, le LLM donnera les **probabilités que le texte donné soit catégorisé dans chacune des catégories données** (comme si un texte est un spam ou non).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> L'objectif de cette section est de montrer comment **affiner un modèle déjà pré-entraîné pour suivre des instructions** plutôt que de simplement générer du texte, par exemple, répondre à des tâches en tant que chatbot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
