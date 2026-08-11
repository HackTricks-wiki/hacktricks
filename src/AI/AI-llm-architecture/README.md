# Addestramento degli LLM - Preparazione dei dati

{{#include ../../banners/hacktricks-training.md}}

**Questi sono i miei appunti tratti dal libro** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **che consiglio vivamente, con alcune informazioni aggiuntive.**<sup>[[1]](#references)</sup>

## Informazioni di base

Dovresti iniziare leggendo questo post per conoscere alcuni concetti di base:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizzazione

> [!TIP]
> L'obiettivo di questa fase è **dividere l'input in token e associarli ai rispettivi token ID**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Campionamento dei dati

> [!TIP]
> L'obiettivo di questa fase è preparare sequenze di addestramento di una lunghezza di contesto scelta, insieme ai rispettivi target di predizione traslati.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'obiettivo di questa terza fase è molto semplice: **assegnare a ciascuno dei token precedenti nel vocabolario un vettore delle dimensioni desiderate per addestrare il modello.** Ogni parola del vocabolario sarà un punto in uno spazio di X dimensioni.\
> Nota che inizialmente la posizione di ogni parola nello spazio viene semplicemente inizializzata in modo "casuale" e queste posizioni sono parametri addestrabili (che verranno migliorati durante l'addestramento).
>
> Inoltre, durante il token embedding, viene creato **un altro livello di embedding** che rappresenta (in questo caso) la **posizione assoluta della parola nella frase di addestramento**. In questo modo, una parola che si trova in posizioni diverse nella frase ha una rappresentazione diversa.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Meccanismi di Attention

> [!TIP]
> L'obiettivo di questa quarta fase è molto semplice: **applicare alcuni meccanismi di attention**. Questi consisteranno in numerosi **livelli ripetuti** che **cattureranno la relazione tra una parola del vocabolario e le parole vicine nella frase corrente utilizzata per addestrare l'LLM**.\
> A questo scopo vengono utilizzati numerosi livelli, quindi molti parametri addestrabili acquisiranno queste informazioni.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architettura dell'LLM

> [!TIP]
> L'obiettivo di questa quinta fase è molto semplice: **sviluppare l'architettura dell'LLM completo**. Riunire tutto, applicare tutti i livelli e creare tutte le funzioni per generare testo o trasformare il testo in ID e viceversa.
>
> Questa architettura verrà utilizzata sia per l'addestramento sia per la predizione del testo dopo l'addestramento.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training e caricamento dei modelli

> [!TIP]
> L'obiettivo di questa sesta fase è molto semplice: **addestrare il modello da zero**. A questo scopo verrà utilizzata la precedente architettura dell'LLM, con alcuni cicli che elaborano i dataset utilizzando le funzioni di loss e l'optimizer definiti per addestrare tutti i parametri del modello.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Miglioramenti con LoRA nel fine-tuning

> [!TIP]
> LoRA riduce sostanzialmente il numero di parametri addestrabili e lo stato dell'optimizer necessari per eseguire il fine-tuning di un modello pre-addestrato.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning per la classificazione

> [!TIP]
> L'obiettivo di questa sezione è mostrare come eseguire il fine-tuning di un modello già pre-addestrato affinché, invece di generare nuovo testo, l'LLM selezioni e fornisca le **probabilità che il testo fornito appartenga a ciascuna delle categorie indicate** (ad esempio, se un testo è spam oppure no).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning per seguire le istruzioni

> [!TIP]
> L'obiettivo di questa sezione è mostrare come **eseguire il fine-tuning di un modello già pre-addestrato affinché segua le istruzioni**, invece di limitarsi a generare testo, ad esempio rispondendo alle attività come un chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
