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
> O objetivo desta fase é **dividir a entrada em tokens e mapeá-los para IDs de tokens**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Amostragem de dados

> [!TIP]
> O objetivo desta fase é preparar sequências de treinamento com um comprimento de contexto escolhido, juntamente com seus alvos de previsão deslocados.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> O objetivo desta terceira fase é muito simples: **Atribuir a cada token anterior do vocabulário um vetor com as dimensões desejadas para treinar o modelo.** Cada palavra do vocabulário será um ponto em um espaço de X dimensões.\
> Observe que, inicialmente, a posição de cada palavra no espaço é apenas inicializada "aleatoriamente", e essas posições são parâmetros treináveis (serão aprimoradas durante o treinamento).
>
> Além disso, durante o token embedding, **outra camada de embedding é criada** para representar, neste caso, a **posição absoluta da palavra na frase de treinamento**. Dessa forma, uma palavra em posições diferentes na frase tem uma representação diferente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mecanismos de Attention

> [!TIP]
> O objetivo desta quarta fase é muito simples: **Aplicar alguns mecanismos de attention**. Eles consistirão em muitas **camadas repetidas** que irão **capturar a relação de uma palavra do vocabulário com suas vizinhas na frase atual usada para treinar o LLM**.\
> Muitas camadas são usadas para isso, portanto, muitos parâmetros treináveis irão capturar essas informações.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arquitetura de LLM

> [!TIP]
> O objetivo desta quinta fase é muito simples: **Desenvolver a arquitetura completa do LLM**. Reunir tudo, aplicar todas as camadas e criar todas as funções para gerar texto ou transformar texto em IDs e vice-versa.
>
> Essa arquitetura será usada tanto para treinar quanto para prever texto depois que o treinamento for concluído.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pré-treinamento e carregamento de modelos

> [!TIP]
> O objetivo desta sexta fase é muito simples: **Treinar o modelo do zero**. Para isso, a arquitetura de LLM anterior será usada com alguns loops percorrendo os conjuntos de dados, usando as funções de perda e o optimizer definidos para treinar todos os parâmetros do modelo.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Melhorias de LoRA no fine-tuning

> [!TIP]
> LoRA reduz substancialmente o número de parâmetros treináveis e o estado do optimizer necessários para fazer fine-tuning de um modelo pré-treinado.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning para classificação

> [!TIP]
> O objetivo desta seção é mostrar como fazer fine-tuning de um modelo já pré-treinado para que, em vez de gerar novo texto, o LLM forneça as **probabilidades de o texto fornecido ser categorizado em cada uma das categorias fornecidas** (por exemplo, se um texto é spam ou não).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning para seguir instruções

> [!TIP]
> O objetivo desta seção é mostrar como **fazer fine-tuning de um modelo já pré-treinado para seguir instruções**, em vez de apenas gerar texto, por exemplo, respondendo a tarefas como um chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (Do zero) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
