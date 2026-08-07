# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**Dies sind meine Notizen aus dem sehr empfehlenswerten Buch** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **mit einigen zusätzlichen Informationen.**<sup>[[1]](#references)</sup>

## Basic Information

Du solltest zunächst diesen Beitrag lesen, um einige grundlegende Konzepte kennenzulernen:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Das Ziel dieser ersten Phase ist sehr einfach: **Die Eingabe auf eine sinnvolle Weise in Tokens (IDs) aufteilen**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Das Ziel dieser zweiten Phase ist sehr einfach: **Die Eingabedaten samplen und sie für die Trainingsphase vorbereiten, normalerweise indem der Datensatz in Sätze einer bestimmten Länge aufgeteilt und außerdem die erwartete Antwort generiert wird.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Das Ziel dieser dritten Phase ist sehr einfach: **Jedem der vorherigen Tokens im Vocabulary einen Vektor mit den gewünschten Dimensionen zuzuweisen, um das Modell zu trainieren.** Jedes Wort im Vocabulary wird zu einem Punkt in einem Raum mit X Dimensionen.\
> Beachte, dass die Position jedes Wortes im Raum zunächst lediglich „zufällig“ initialisiert wird und diese Positionen trainierbare Parameter sind (sie werden während des Trainings verbessert).
>
> Außerdem wird während der Token Embedding **eine weitere Embedding-Schicht erstellt**, die (in diesem Fall) die **absolute Position des Wortes im Trainingssatz** darstellt. Auf diese Weise hat ein Wort an verschiedenen Positionen im Satz eine unterschiedliche Repräsentation (Bedeutung).


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Das Ziel dieser vierten Phase ist sehr einfach: **Einige Attention Mechanisms anzuwenden**. Dabei handelt es sich um viele **wiederholte Schichten**, die die **Beziehung eines Wortes im Vocabulary zu seinen Nachbarn im aktuellen Satz erfassen, der zum Training des LLM verwendet wird**.\
> Dafür werden viele Schichten eingesetzt, sodass viele trainierbare Parameter diese Informationen erfassen werden.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Das Ziel dieser fünften Phase ist sehr einfach: **Die Architektur des vollständigen LLM zu entwickeln**. Alles zusammenzufügen, alle Schichten anzuwenden und alle Funktionen zum Generieren von Text oder zum Umwandeln von Text in IDs und zurück zu erstellen.
>
> Diese Architektur wird sowohl für das Training als auch für die Vorhersage von Text nach dem Training verwendet.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Das Ziel dieser sechsten Phase ist sehr einfach: **Das Modell von Grund auf zu trainieren**. Dafür wird die vorherige LLM Architecture verwendet, wobei Schleifen über die Datensätze ausgeführt werden und die definierten Loss-Funktionen sowie der Optimizer zum Trainieren aller Parameter des Modells verwendet werden.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> Der Einsatz von **LoRA reduziert den erforderlichen Rechenaufwand** für das **Fine-Tuning** bereits trainierter Modelle erheblich.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Das Ziel dieses Abschnitts ist zu zeigen, wie ein bereits vortrainiertes Modell per Fine-Tuning angepasst werden kann, sodass das LLM nicht stattdessen neuen Text generiert, sondern die **Wahrscheinlichkeiten dafür angibt, dass der gegebene Text jeder der vorgegebenen Kategorien zugeordnet wird** (beispielsweise, ob ein Text Spam ist oder nicht).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Das Ziel dieses Abschnitts ist zu zeigen, wie ein **bereits vortrainiertes Modell per Fine-Tuning so angepasst wird, dass es Anweisungen befolgt**, anstatt lediglich Text zu generieren, beispielsweise indem es auf Aufgaben wie ein Chatbot antwortet.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
