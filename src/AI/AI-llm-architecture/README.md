# LLM Training - Datenvorbereitung

**Dies sind meine Notizen aus dem sehr empfohlenen Buch** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **mit einigen zusätzlichen Informationen.**

## Grundinformationen

Sie sollten mit dem Lesen dieses Beitrags beginnen, um einige grundlegende Konzepte zu verstehen, die Sie wissen sollten:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenisierung

> [!TIP]
> Das Ziel dieser ersten Phase ist sehr einfach: **Teilen Sie die Eingabe in Tokens (IDs) auf eine Weise, die Sinn macht**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Datensampling

> [!TIP]
> Das Ziel dieser zweiten Phase ist sehr einfach: **Proben Sie die Eingabedaten und bereiten Sie sie für die Trainingsphase vor, indem Sie den Datensatz normalerweise in Sätze einer bestimmten Länge unterteilen und auch die erwartete Antwort generieren.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token-Embeddings

> [!TIP]
> Das Ziel dieser dritten Phase ist sehr einfach: **Weisen Sie jedem der vorherigen Tokens im Vokabular einen Vektor der gewünschten Dimensionen zu, um das Modell zu trainieren.** Jedes Wort im Vokabular wird einen Punkt in einem Raum von X Dimensionen haben.\
> Beachten Sie, dass die Position jedes Wortes im Raum zunächst "zufällig" initialisiert wird und diese Positionen trainierbare Parameter sind (während des Trainings verbessert werden).
>
> Darüber hinaus wird während des Token-Embeddings **eine weitere Schicht von Embeddings erstellt**, die (in diesem Fall) die **absolute Position des Wortes im Trainingssatz** darstellt. Auf diese Weise hat ein Wort an verschiedenen Positionen im Satz eine unterschiedliche Darstellung (Bedeutung).

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Aufmerksamkeitsmechanismen

> [!TIP]
> Das Ziel dieser vierten Phase ist sehr einfach: **Wenden Sie einige Aufmerksamkeitsmechanismen an**. Diese werden viele **wiederholte Schichten** sein, die die **Beziehung eines Wortes im Vokabular zu seinen Nachbarn im aktuellen Satz, der zum Trainieren des LLM verwendet wird, erfassen**.\
> Viele Schichten werden dafür verwendet, sodass viele trainierbare Parameter diese Informationen erfassen werden.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM-Architektur

> [!TIP]
> Das Ziel dieser fünften Phase ist sehr einfach: **Entwickeln Sie die Architektur des gesamten LLM**. Fügen Sie alles zusammen, wenden Sie alle Schichten an und erstellen Sie alle Funktionen, um Text zu generieren oder Text in IDs und umgekehrt zu transformieren.
>
> Diese Architektur wird sowohl für das Training als auch für die Vorhersage von Text nach dem Training verwendet.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Vortraining & Laden von Modellen

> [!TIP]
> Das Ziel dieser sechsten Phase ist sehr einfach: **Trainieren Sie das Modell von Grund auf neu**. Dazu wird die vorherige LLM-Architektur mit einigen Schleifen über die Datensätze unter Verwendung der definierten Verlustfunktionen und Optimierer verwendet, um alle Parameter des Modells zu trainieren.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA-Verbesserungen beim Feintuning

> [!TIP]
> Die Verwendung von **LoRA reduziert die benötigte Berechnung** erheblich, um **bereits trainierte Modelle fein abzustimmen**.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Feintuning für Klassifikation

> [!TIP]
> Das Ziel dieses Abschnitts ist zu zeigen, wie man ein bereits vortrainiertes Modell fein abstimmt, sodass das LLM anstelle von neuem Text die **Wahrscheinlichkeiten angibt, dass der gegebene Text in jede der angegebenen Kategorien eingeordnet wird** (zum Beispiel, ob ein Text Spam ist oder nicht).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Feintuning zur Befolgung von Anweisungen

> [!TIP]
> Das Ziel dieses Abschnitts ist zu zeigen, wie man ein **bereits vortrainiertes Modell fein abstimmt, um Anweisungen zu befolgen**, anstatt nur Text zu generieren, zum Beispiel, um auf Aufgaben als Chatbot zu antworten.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
