# LLM Training - Przygotowanie Danych

**To są moje notatki z bardzo polecanej książki** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **z dodatkowymi informacjami.**

## Podstawowe Informacje

Powinieneś zacząć od przeczytania tego posta, aby poznać podstawowe pojęcia, które powinieneś znać:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenizacja

> [!TIP]
> Celem tej początkowej fazy jest bardzo proste: **Podzielić dane wejściowe na tokeny (id) w sposób, który ma sens**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Próbkowanie Danych

> [!TIP]
> Celem tej drugiej fazy jest bardzo proste: **Próbkować dane wejściowe i przygotować je do fazy treningowej, zazwyczaj dzieląc zbiór danych na zdania o określonej długości i generując również oczekiwaną odpowiedź.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Osadzenia Tokenów

> [!TIP]
> Celem tej trzeciej fazy jest bardzo proste: **Przypisać każdemu z poprzednich tokenów w słowniku wektor o pożądanych wymiarach do trenowania modelu.** Każde słowo w słowniku będzie punktem w przestrzeni o X wymiarach.\
> Zauważ, że początkowo pozycja każdego słowa w przestrzeni jest po prostu "losowo" inicjowana, a te pozycje są parametrami, które można trenować (będą poprawiane podczas treningu).
>
> Ponadto, podczas osadzania tokenów **tworzona jest kolejna warstwa osadzeń**, która reprezentuje (w tym przypadku) **absolutną pozycję słowa w zdaniu treningowym**. W ten sposób słowo w różnych pozycjach w zdaniu będzie miało różne reprezentacje (znaczenie).

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mechanizmy Uwagowe

> [!TIP]
> Celem tej czwartej fazy jest bardzo proste: **Zastosować pewne mechanizmy uwagi**. Będą to liczne **powtarzające się warstwy**, które będą **uchwytywać relację słowa w słowniku z jego sąsiadami w bieżącym zdaniu używanym do trenowania LLM**.\
> Do tego celu używa się wielu warstw, więc wiele parametrów do trenowania będzie uchwytywać te informacje.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Architektura LLM

> [!TIP]
> Celem tej piątej fazy jest bardzo proste: **Opracować architekturę całego LLM**. Połączyć wszystko, zastosować wszystkie warstwy i stworzyć wszystkie funkcje do generowania tekstu lub przekształcania tekstu na ID i odwrotnie.
>
> Ta architektura będzie używana zarówno do trenowania, jak i przewidywania tekstu po jego wytrenowaniu.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Wstępne trenowanie i ładowanie modeli

> [!TIP]
> Celem tej szóstej fazy jest bardzo proste: **Wytrenować model od podstaw**. W tym celu zostanie użyta wcześniejsza architektura LLM z pewnymi pętlami przechodzącymi przez zbiory danych, używając zdefiniowanych funkcji straty i optymalizatora do trenowania wszystkich parametrów modelu.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Ulepszenia LoRA w dostrajaniu

> [!TIP]
> Użycie **LoRA znacznie redukuje obliczenia** potrzebne do **dostrajania** już wytrenowanych modeli.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Dostrajanie do klasyfikacji

> [!TIP]
> Celem tej sekcji jest pokazanie, jak dostroić już wytrenowany model, aby zamiast generować nowy tekst, LLM podałby **prawdopodobieństwa przypisania danego tekstu do każdej z podanych kategorii** (na przykład, czy tekst jest spamem, czy nie).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Dostrajanie do wykonywania poleceń

> [!TIP]
> Celem tej sekcji jest pokazanie, jak **dostroić już wytrenowany model do wykonywania poleceń** zamiast tylko generować tekst, na przykład, odpowiadając na zadania jako chatbot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
