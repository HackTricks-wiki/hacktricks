# LLM Training - Data Preparation

{{#include /banners/hacktricks-training.md}}

**Estas são minhas anotações do livro muito recomendado** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **com algumas informações extras.**

## Basic Information

Você deve começar lendo este post para alguns conceitos básicos que você deve conhecer:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> O objetivo desta fase inicial é muito simples: **Dividir a entrada em tokens (ids) de uma forma que faça sentido**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> O objetivo desta segunda fase é muito simples: **Amostrar os dados de entrada e prepará-los para a fase de treinamento, geralmente separando o conjunto de dados em sentenças de um comprimento específico e gerando também a resposta esperada.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> O objetivo desta terceira fase é muito simples: **Atribuir a cada um dos tokens anteriores no vocabulário um vetor das dimensões desejadas para treinar o modelo.** Cada palavra no vocabulário será um ponto em um espaço de X dimensões.\
> Note que inicialmente a posição de cada palavra no espaço é apenas inicializada "aleatoriamente" e essas posições são parâmetros treináveis (serão melhorados durante o treinamento).
>
> Além disso, durante a incorporação de tokens **outra camada de incorporações é criada** que representa (neste caso) a **posição absoluta da palavra na sentença de treinamento**. Dessa forma, uma palavra em diferentes posições na sentença terá uma representação (significado) diferente.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> O objetivo desta quarta fase é muito simples: **Aplicar alguns mecanismos de atenção**. Estes serão muitas **camadas repetidas** que vão **capturar a relação de uma palavra no vocabulário com seus vizinhos na sentença atual sendo usada para treinar o LLM**.\
> Muitas camadas são usadas para isso, então muitos parâmetros treináveis estarão capturando essa informação.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> O objetivo desta quinta fase é muito simples: **Desenvolver a arquitetura do LLM completo**. Juntar tudo, aplicar todas as camadas e criar todas as funções para gerar texto ou transformar texto em IDs e vice-versa.
>
> Esta arquitetura será usada tanto para treinar quanto para prever texto após ter sido treinada.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> O objetivo desta sexta fase é muito simples: **Treinar o modelo do zero**. Para isso, a arquitetura LLM anterior será usada com alguns loops sobre os conjuntos de dados usando as funções de perda e otimizador definidos para treinar todos os parâmetros do modelo.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> O uso de **LoRA reduz muito a computação** necessária para **ajustar** modelos já treinados.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> O objetivo desta seção é mostrar como ajustar um modelo já pré-treinado para que, em vez de gerar novo texto, o LLM selecione e forneça as **probabilidades do texto dado ser categorizado em cada uma das categorias dadas** (como se um texto é spam ou não).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> O objetivo desta seção é mostrar como **ajustar um modelo já pré-treinado para seguir instruções** em vez de apenas gerar texto, por exemplo, respondendo a tarefas como um chatbot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

{{#include /banners/hacktricks-training.md}}
