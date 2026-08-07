# Treinamento de LLM - Preparação de Dados

{{#include ../../banners/hacktricks-training.md}}

**Estas são minhas anotações do livro altamente recomendado** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **com algumas informações adicionais.**<sup>[[1]](#references)</sup>

## Informações básicas

Você deve começar lendo este post para conhecer alguns conceitos básicos:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> O objetivo desta fase inicial é muito simples: **Dividir a entrada em tokens (ids) de alguma forma que faça sentido**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Amostragem de dados

> [!TIP]
> O objetivo desta segunda fase é muito simples: **Amostrar os dados de entrada e prepará-los para a fase de treinamento, normalmente separando o dataset em frases de um tamanho específico e gerando também a resposta esperada.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> O objetivo desta terceira fase é muito simples: **Atribuir a cada um dos tokens anteriores no vocabulário um vetor com as dimensões desejadas para treinar o modelo.** Cada palavra no vocabulário será um ponto em um espaço de X dimensões.\
> Observe que, inicialmente, a posição de cada palavra no espaço é apenas inicializada de forma "aleatória", e essas posições são parâmetros treináveis (serão aprimoradas durante o treinamento).
>
> Além disso, durante o token embedding, **outra camada de embeddings é criada**, representando, neste caso, a **posição absoluta da palavra na frase de treinamento**. Dessa forma, uma palavra em posições diferentes na frase terá uma representação (significado) diferente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mecanismos de atenção

> [!TIP]
> O objetivo desta quarta fase é muito simples: **Aplicar alguns mecanismos de atenção**. Eles consistirão em muitas **camadas repetidas** que irão **capturar a relação de uma palavra no vocabulário com suas vizinhas na frase atual usada para treinar o LLM**.\
> Muitas camadas são usadas para isso, portanto muitos parâmetros treináveis irão capturar essas informações.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arquitetura do LLM

> [!TIP]
> O objetivo desta quinta fase é muito simples: **Desenvolver a arquitetura completa do LLM**. Reunir tudo, aplicar todas as camadas e criar todas as funções para gerar texto ou transformar texto em IDs e vice-versa.
>
> Essa arquitetura será usada tanto para o treinamento quanto para prever texto depois que o modelo for treinado.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pré-treinamento e carregamento de modelos

> [!TIP]
> O objetivo desta sexta fase é muito simples: **Treinar o modelo do zero**. Para isso, a arquitetura anterior do LLM será usada com alguns loops percorrendo os datasets, utilizando as funções de perda e o otimizador definidos para treinar todos os parâmetros do modelo.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Melhorias de LoRA no fine-tuning

> [!TIP]
> O uso de **LoRA reduz bastante a computação** necessária para fazer **fine-tuning** em modelos já treinados.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning para classificação

> [!TIP]
> O objetivo desta seção é mostrar como fazer fine-tuning em um modelo já pré-treinado para que, em vez de gerar novo texto, o LLM selecione e forneça as **probabilidades de o texto fornecido ser categorizado em cada uma das categorias especificadas** (por exemplo, se um texto é spam ou não).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning para seguir instruções

> [!TIP]
> O objetivo desta seção é mostrar como fazer **fine-tuning em um modelo já pré-treinado para seguir instruções**, em vez de apenas gerar texto, por exemplo, respondendo a tarefas como um chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Referências

- [1] [Construir um Large Language Model (do zero) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
