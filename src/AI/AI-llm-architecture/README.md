# LLM Training - Data Preparation

**Queste sono le mie note dal libro molto raccomandato** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **con alcune informazioni extra.**

## Basic Information

Dovresti iniziare leggendo questo post per alcuni concetti di base che dovresti conoscere:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> L'obiettivo di questa fase iniziale è molto semplice: **Dividere l'input in token (ids) in un modo che abbia senso**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> L'obiettivo di questa seconda fase è molto semplice: **Campionare i dati di input e prepararli per la fase di addestramento solitamente separando il dataset in frasi di una lunghezza specifica e generando anche la risposta attesa.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> L'obiettivo di questa terza fase è molto semplice: **Assegnare a ciascuno dei token precedenti nel vocabolario un vettore delle dimensioni desiderate per addestrare il modello.** Ogni parola nel vocabolario sarà un punto in uno spazio di X dimensioni.\
> Nota che inizialmente la posizione di ogni parola nello spazio è semplicemente inizializzata "casualmente" e queste posizioni sono parametri addestrabili (saranno migliorati durante l'addestramento).
>
> Inoltre, durante l'embedding dei token **viene creata un'altra layer di embeddings** che rappresenta (in questo caso) la **posizione assoluta della parola nella frase di addestramento**. In questo modo, una parola in posizioni diverse nella frase avrà una rappresentazione (significato) diversa.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> L'obiettivo di questa quarta fase è molto semplice: **Applicare alcuni meccanismi di attenzione**. Questi saranno molti **layer ripetuti** che andranno a **catturare la relazione di una parola nel vocabolario con i suoi vicini nella frase attuale utilizzata per addestrare il LLM**.\
> Vengono utilizzati molti layer per questo, quindi molti parametri addestrabili andranno a catturare queste informazioni.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> L'obiettivo di questa quinta fase è molto semplice: **Sviluppare l'architettura del LLM completo**. Metti tutto insieme, applica tutti i layer e crea tutte le funzioni per generare testo o trasformare testo in ID e viceversa.
>
> Questa architettura sarà utilizzata sia per l'addestramento che per la previsione del testo dopo che è stata addestrata.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> L'obiettivo di questa sesta fase è molto semplice: **Addestrare il modello da zero**. Per questo verrà utilizzata l'architettura LLM precedente con alcuni cicli sui dataset utilizzando le funzioni di perdita e l'ottimizzatore definiti per addestrare tutti i parametri del modello.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> L'uso di **LoRA riduce notevolmente il calcolo** necessario per **ottimizzare** modelli già addestrati.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> L'obiettivo di questa sezione è mostrare come ottimizzare un modello già pre-addestrato in modo che, invece di generare nuovo testo, il LLM fornisca le **probabilità che il testo fornito venga categorizzato in ciascuna delle categorie date** (come se un testo fosse spam o meno).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> L'obiettivo di questa sezione è mostrare come **ottimizzare un modello già pre-addestrato per seguire istruzioni** piuttosto che semplicemente generare testo, ad esempio, rispondendo a compiti come un chatbot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
