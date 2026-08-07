# Trening LLM - przygotowanie danych

{{#include ../../banners/hacktricks-training.md}}

**Są to moje notatki z bardzo polecanej książki** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **z dodatkowymi informacjami.**<sup>[[1]](#references)</sup>

## Podstawowe informacje

Na początek przeczytaj ten post dotyczący podstawowych pojęć, które warto znać:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizacja

> [!TIP]
> Cel tej początkowej fazy jest bardzo prosty: **Podzielić dane wejściowe na tokeny (ids) w sposób, który ma sens.**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Próbkowanie danych

> [!TIP]
> Cel tej drugiej fazy jest bardzo prosty: **Próbkować dane wejściowe i przygotować je do fazy treningu, zwykle oddzielając dataset na zdania o określonej długości i generując również oczekiwaną odpowiedź.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Embeddingi tokenów

> [!TIP]
> Cel tej trzeciej fazy jest bardzo prosty: **Przypisać każdemu z wcześniejszych tokenów w vocabulary wektor o wymaganych wymiarach, aby wytrenować model.** Każde słowo w vocabulary będzie punktem w przestrzeni o X wymiarach.\
> Należy zauważyć, że początkowo pozycja każdego słowa w przestrzeni jest inicjalizowana „losowo”, a pozycje te są trainable parameters (będą ulepszane podczas treningu).
>
> Ponadto podczas tworzenia embeddingów tokenów **tworzona jest kolejna warstwa embeddingów**, która reprezentuje (w tym przypadku) **absolutną pozycję słowa w zdaniu treningowym**. Dzięki temu słowo znajdujące się na różnych pozycjach w zdaniu będzie miało inną reprezentację (znaczenie).


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mechanizmy attention

> [!TIP]
> Cel tej czwartej fazy jest bardzo prosty: **Zastosować mechanizmy attention**. Będą to liczne **powtarzające się warstwy**, które będą **wychwytywać relację słowa w vocabulary z jego sąsiadami w aktualnym zdaniu używanym do trenowania LLM**.\
> Wykorzystywanych jest do tego wiele warstw, dlatego wiele trainable parameters będzie przechwytywać te informacje.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architektura LLM

> [!TIP]
> Cel tej piątej fazy jest bardzo prosty: **Opracować architekturę pełnego LLM**. Połączyć wszystko, zastosować wszystkie warstwy i utworzyć wszystkie funkcje służące do generowania tekstu lub przekształcania tekstu na IDs i z powrotem.
>
> Architektura ta będzie używana zarówno do treningu, jak i do przewidywania tekstu po zakończeniu treningu.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training i ładowanie modeli

> [!TIP]
> Cel tej szóstej fazy jest bardzo prosty: **Wytrenować model od podstaw**. W tym celu zostanie użyta wcześniejsza architektura LLM wraz z pętlami przetwarzającymi datasety, wykorzystującymi zdefiniowane funkcje straty i optimizer do trenowania wszystkich parametrów modelu.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Ulepszenia LoRA w fine-tuning

> [!TIP]
> Zastosowanie **LoRA znacznie ogranicza obliczenia** wymagane do wykonania **fine-tuning** już wytrenowanych modeli.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning do klasyfikacji

> [!TIP]
> Celem tej sekcji jest pokazanie, jak wykonać fine-tuning już pre-trained modelu, aby zamiast generować nowy tekst LLM **podawał prawdopodobieństwa zaklasyfikowania danego tekstu do każdej z określonych kategorii** (na przykład czy tekst jest spamem).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning w celu wykonywania instrukcji

> [!TIP]
> Celem tej sekcji jest pokazanie, jak wykonać **fine-tuning już pre-trained modelu, aby wykonywał instrukcje**, zamiast jedynie generować tekst, na przykład odpowiadając na zadania jako chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Referencje

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
