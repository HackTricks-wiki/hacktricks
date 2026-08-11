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
> L'objectif de cette phase est de **diviser l'entrée en tokens et de les associer à des identifiants de tokens**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Échantillonnage des données

> [!TIP]
> L'objectif de cette phase est de préparer des séquences d'entraînement d'une longueur de contexte choisie, ainsi que leurs cibles de prédiction décalées.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'objectif de cette troisième phase est très simple : **attribuer à chacun des tokens précédents du vocabulaire un vecteur des dimensions souhaitées afin d'entraîner le modèle.** Chaque mot du vocabulaire sera un point dans un espace de X dimensions.\
> Notez qu'initialement, la position de chaque mot dans l'espace est simplement initialisée de manière « aléatoire », et que ces positions sont des paramètres entraînables (elles seront améliorées pendant l'entraînement).
>
> De plus, pendant le token embedding, **une autre couche d'embedding est créée** pour représenter (dans ce cas) la **position absolue du mot dans la phrase d'entraînement**. Ainsi, un mot placé à différentes positions dans la phrase possède une représentation différente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mécanismes d'attention

> [!TIP]
> L'objectif de cette quatrième phase est très simple : **appliquer certains mécanismes d'attention**. Il s'agit de nombreuses **couches répétées** qui vont **capturer la relation entre un mot du vocabulaire et ses voisins dans la phrase utilisée pour entraîner le LLM**.\
> De nombreuses couches sont utilisées à cette fin ; un grand nombre de paramètres entraînables vont donc capturer ces informations.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architecture du LLM

> [!TIP]
> L'objectif de cette cinquième phase est très simple : **développer l'architecture complète du LLM**. Tout regrouper, appliquer toutes les couches et créer toutes les fonctions permettant de générer du texte ou de transformer du texte en identifiants, et inversement.
>
> Cette architecture sera utilisée à la fois pour l'entraînement et pour la prédiction de texte après l'entraînement.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pré-entraînement et chargement des modèles

> [!TIP]
> L'objectif de cette sixième phase est très simple : **entraîner le modèle à partir de zéro**. Pour cela, l'architecture précédente du LLM sera utilisée avec des boucles parcourant les jeux de données, ainsi que les fonctions de perte et l'optimiseur définis pour entraîner tous les paramètres du modèle.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Améliorations de LoRA lors du fine-tuning

> [!TIP]
> LoRA réduit considérablement le nombre de paramètres entraînables et l'état de l'optimiseur nécessaires pour effectuer le fine-tuning d'un modèle pré-entraîné.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning pour la classification

> [!TIP]
> L'objectif de cette section est de montrer comment effectuer le fine-tuning d'un modèle déjà pré-entraîné afin qu'au lieu de générer du nouveau texte, le LLM sélectionne et donne les **probabilités que le texte fourni soit classé dans chacune des catégories données** (par exemple, si un texte est un spam ou non).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning pour suivre des instructions

> [!TIP]
> L'objectif de cette section est de montrer comment **effectuer le fine-tuning d'un modèle déjà pré-entraîné pour suivre des instructions**, plutôt que de simplement générer du texte, par exemple en répondant à des tâches comme un chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Construire un grand modèle de langage (à partir de zéro) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
