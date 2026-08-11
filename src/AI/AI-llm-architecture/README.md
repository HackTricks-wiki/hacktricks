# LLM-Training - Datenvorbereitung

{{#include ../../banners/hacktricks-training.md}}

**Dies sind meine Notizen aus dem sehr empfehlenswerten Buch** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **mit einigen zusätzlichen Informationen.**<sup>[[1]](#references)</sup>

## Grundlegende Informationen

Du solltest zunächst diesen Beitrag lesen, um einige grundlegende Konzepte kennenzulernen:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenisierung

> [!TIP]
> Das Ziel dieser Phase besteht darin, **die Eingabe in Tokens aufzuteilen und ihnen Token-IDs zuzuweisen**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Daten-Sampling

> [!TIP]
> Das Ziel dieser Phase besteht darin, Trainingssequenzen mit einer ausgewählten Kontextlänge zusammen mit ihren verschobenen Vorhersagezielen vorzubereiten.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token-Embeddings

> [!TIP]
> Das Ziel dieser dritten Phase ist sehr einfach: **Jedem der zuvor im Vokabular enthaltenen Tokens einen Vektor mit den gewünschten Dimensionen zuzuweisen, um das Modell zu trainieren.** Jedes Wort im Vokabular wird zu einem Punkt in einem Raum mit X Dimensionen.\
> Beachte, dass die Position jedes Wortes im Raum zunächst einfach „zufällig“ initialisiert wird und diese Positionen trainierbare Parameter sind (sie werden während des Trainings verbessert).
>
> Außerdem wird während des Token-Embeddings **eine weitere Embedding-Schicht erstellt**, die (in diesem Fall) die **absolute Position des Wortes im Trainingssatz** repräsentiert. Dadurch hat ein Wort an verschiedenen Positionen im Satz eine unterschiedliche Repräsentation.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention-Mechanismen

> [!TIP]
> Das Ziel dieser vierten Phase ist sehr einfach: **Einige Attention-Mechanismen anzuwenden**. Diese werden aus vielen **wiederholten Schichten** bestehen, die **die Beziehung eines Wortes im Vokabular zu seinen Nachbarn im aktuellen Satz erfassen, der zum Trainieren des LLM verwendet wird**.\
> Dafür werden viele Schichten verwendet, sodass viele trainierbare Parameter diese Informationen erfassen werden.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM-Architektur

> [!TIP]
> Das Ziel dieser fünften Phase ist sehr einfach: **Die Architektur des vollständigen LLM zu entwickeln**. Alles zusammenzufügen, alle Schichten anzuwenden und alle Funktionen zu erstellen, um Text zu generieren oder Text in IDs und zurück umzuwandeln.
>
> Diese Architektur wird sowohl zum Trainieren als auch zum Vorhersagen von Text verwendet, nachdem das Modell trainiert wurde.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-Training und Laden von Modellen

> [!TIP]
> Das Ziel dieser sechsten Phase ist sehr einfach: **Das Modell von Grund auf zu trainieren**. Dafür wird die vorherige LLM-Architektur verwendet, wobei Schleifen über die Datensätze laufen und die definierten Verlustfunktionen sowie der Optimizer verwendet werden, um alle Parameter des Modells zu trainieren.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA-Verbesserungen beim Fine-Tuning

> [!TIP]
> LoRA reduziert die Anzahl der trainierbaren Parameter und des für das Fine-Tuning eines vortrainierten Modells benötigten Optimizer-Zustands erheblich.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning für Klassifizierung

> [!TIP]
> Das Ziel dieses Abschnitts besteht darin zu zeigen, wie ein bereits vortrainiertes Modell per Fine-Tuning angepasst werden kann, sodass das LLM nicht stattdessen neuen Text generiert, sondern die **Wahrscheinlichkeiten angibt, mit denen der gegebene Text jeder der vorgegebenen Kategorien zugeordnet wird** (beispielsweise, ob ein Text Spam ist oder nicht).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning zum Befolgen von Anweisungen

> [!TIP]
> Das Ziel dieses Abschnitts besteht darin zu zeigen, wie ein bereits vortrainiertes Modell per Fine-Tuning so angepasst werden kann, dass es **Anweisungen befolgt**, anstatt lediglich Text zu generieren, beispielsweise indem es auf Aufgaben wie ein Chatbot antwortet.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
