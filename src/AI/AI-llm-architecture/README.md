# Trenowanie LLM - przygotowanie danych

{{#include ../../banners/hacktricks-training.md}}

**To moje notatki z bardzo polecanej książki** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **wraz z dodatkowymi informacjami.**<sup>[[1]](#references)</sup>

## Podstawowe informacje

Na początek przeczytaj ten artykuł dotyczący podstawowych pojęć, które należy znać:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizacja

> [!TIP]
> Celem tej fazy jest **podzielenie danych wejściowych na tokeny i przypisanie im identyfikatorów tokenów**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Próbkowanie danych

> [!TIP]
> Celem tej fazy jest przygotowanie sekwencji treningowych o wybranej długości kontekstu wraz z przesuniętymi celami predykcji.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Embeddingi tokenów

> [!TIP]
> Cel tej trzeciej fazy jest bardzo prosty: **Przypisanie każdemu z wcześniejszych tokenów w słowniku wektora o pożądanych wymiarach, aby wytrenować model.** Każde słowo w słowniku stanie się punktem w przestrzeni o X wymiarach.\
> Należy zauważyć, że początkowo pozycja każdego słowa w przestrzeni jest inicjalizowana w sposób „losowy”, a pozycje te są trenowalnymi parametrami (będą ulepszane podczas trenowania).
>
> Ponadto podczas tworzenia embeddingów tokenów tworzona jest **kolejna warstwa embeddingów**, która reprezentuje (w tym przypadku) **bezwzględną pozycję słowa w zdaniu treningowym**. Dzięki temu słowo znajdujące się na różnych pozycjach w zdaniu ma inną reprezentację.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mechanizmy attention

> [!TIP]
> Cel tej czwartej fazy jest bardzo prosty: **Zastosowanie mechanizmów attention**. Będą to liczne **powtarzające się warstwy**, które będą **wychwytywać relację słowa w słowniku z jego sąsiadami w bieżącym zdaniu używanym do trenowania LLM**.\
> W tym celu używa się wielu warstw, więc wiele trenowalnych parametrów będzie przechwytywać te informacje.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architektura LLM

> [!TIP]
> Cel tej piątej fazy jest bardzo prosty: **Opracowanie pełnej architektury LLM**. Należy połączyć wszystkie elementy, zastosować wszystkie warstwy i utworzyć wszystkie funkcje służące do generowania tekstu lub przekształcania tekstu na identyfikatory i odwrotnie.
>
> Ta architektura będzie używana zarówno do trenowania, jak i do przewidywania tekstu po zakończeniu trenowania.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training i ładowanie modeli

> [!TIP]
> Cel tej szóstej fazy jest bardzo prosty: **Wytrenowanie modelu od podstaw**. W tym celu wcześniejsza architektura LLM będzie używana w pętlach przechodzących po zbiorach danych, z wykorzystaniem zdefiniowanych funkcji straty i optymalizatora do trenowania wszystkich parametrów modelu.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Ulepszenia LoRA podczas fine-tuningu

> [!TIP]
> LoRA znacząco zmniejsza liczbę trenowalnych parametrów oraz stan optymalizatora wymagany do przeprowadzenia fine-tuningu wytrenowanego modelu.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-tuning do klasyfikacji

> [!TIP]
> Celem tej sekcji jest pokazanie, jak przeprowadzić fine-tuning już wstępnie wytrenowanego modelu, aby zamiast generować nowy tekst LLM **podawał prawdopodobieństwa zaklasyfikowania danego tekstu do każdej z podanych kategorii** (na przykład, czy tekst jest spamem).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-tuning w celu wykonywania instrukcji

> [!TIP]
> Celem tej sekcji jest pokazanie, jak **przeprowadzić fine-tuning już wstępnie wytrenowanego modelu, aby wykonywał instrukcje**, zamiast tylko generować tekst, na przykład odpowiadając na zadania jako chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Budowa dużego modelu językowego (od podstaw) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
