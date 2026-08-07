# Training degli LLM - Preparazione dei dati

{{#include ../../banners/hacktricks-training.md}}

**Questi sono i miei appunti tratti dal libro vivamente consigliato** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **con alcune informazioni aggiuntive.**<sup>[[1]](#references)</sup>

## Informazioni di base

Dovresti iniziare leggendo questo post per apprendere alcuni concetti di base che dovresti conoscere:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> L'obiettivo di questa fase iniziale è molto semplice: **dividere l'input in token (ids) in un modo sensato**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Campionamento dei dati

> [!TIP]
> L'obiettivo di questa seconda fase è molto semplice: **campionare i dati di input e prepararli per la fase di training, solitamente separando il dataset in frasi di una lunghezza specifica e generando anche la risposta prevista.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'obiettivo di questa terza fase è molto semplice: **assegnare a ciascuno dei token precedenti nel vocabolario un vettore delle dimensioni desiderate per eseguire il training del modello.** Ogni parola nel vocabolario sarà un punto in uno spazio di X dimensioni.\
> Nota che inizialmente la posizione di ogni parola nello spazio viene semplicemente inizializzata in modo "casuale" e queste posizioni sono parametri addestrabili (verranno migliorate durante il training).
>
> Inoltre, durante il token embedding **viene creato un altro livello di embeddings** che rappresenta (in questo caso) la **posizione assoluta della parola nella frase di training**. In questo modo, una parola in posizioni diverse nella frase avrà una rappresentazione (significato) diversa.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Meccanismi di attenzione

> [!TIP]
> L'obiettivo di questa quarta fase è molto semplice: **applicare alcuni meccanismi di attenzione**. Questi saranno molti **livelli ripetuti** che **cattureranno la relazione di una parola nel vocabolario con le parole vicine nella frase corrente utilizzata per il training dell'LLM**.\
> A questo scopo vengono utilizzati molti livelli, quindi numerosi parametri addestrabili cattureranno queste informazioni.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architettura dell'LLM

> [!TIP]
> L'obiettivo di questa quinta fase è molto semplice: **sviluppare l'architettura dell'LLM completo**. Unire tutto, applicare tutti i livelli e creare tutte le funzioni per generare testo o trasformare il testo in IDs e viceversa.
>
> Questa architettura verrà utilizzata sia per il training sia per prevedere il testo dopo il training.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training e caricamento dei modelli

> [!TIP]
> L'obiettivo di questa sesta fase è molto semplice: **addestrare il modello da zero**. A questo scopo verrà utilizzata la precedente architettura dell'LLM, con alcuni loop che elaborano i dataset usando le funzioni di loss e l'optimizer definiti per addestrare tutti i parametri del modello.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Miglioramenti di LoRA nel fine-tuning

> [!TIP]
> L'uso di **LoRA riduce notevolmente la computazione** necessaria per eseguire il **fine-tuning** di modelli già addestrati.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning per la classificazione

> [!TIP]
> L'obiettivo di questa sezione è mostrare come eseguire il fine-tuning di un modello già pre-addestrato affinché, invece di generare nuovo testo, l'LLM selezioni e fornisca le **probabilità che il testo fornito appartenga a ciascuna delle categorie indicate** (ad esempio, se un testo è spam o meno).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning per seguire le istruzioni

> [!TIP]
> L'obiettivo di questa sezione è mostrare come **eseguire il fine-tuning di un modello già pre-addestrato affinché segua le istruzioni**, invece di limitarsi a generare testo, ad esempio rispondendo alle attività come un chat bot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Riferimenti

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
