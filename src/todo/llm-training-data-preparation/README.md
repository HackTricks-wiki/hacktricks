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
> Nota che inizialmente la posizione di ciascuna parola nello spazio è semplicemente inizializzata "randomicamente" e queste posizioni sono parametri addestrabili (saranno migliorati durante l'addestramento).
>
> Inoltre, durante l'embedding dei token **viene creata un'altra layer di embeddings** che rappresenta (in questo caso) la **posizione assoluta della parola nella frase di addestramento**. In questo modo, una parola in posizioni diverse nella frase avrà una rappresentazione (significato) diversa.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
