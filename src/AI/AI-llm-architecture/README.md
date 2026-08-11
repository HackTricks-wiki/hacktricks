# Entrenamiento de LLM - Preparación de datos

{{#include ../../banners/hacktricks-training.md}}

**Estas son mis notas del libro muy recomendado** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **con información adicional.**<sup>[[1]](#references)</sup>

## Información básica

Deberías comenzar leyendo este post para conocer algunos conceptos básicos:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenización

> [!TIP]
> El objetivo de esta fase es **dividir la entrada en tokens y asignarles IDs de token**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Muestreo de datos

> [!TIP]
> El objetivo de esta fase es preparar secuencias de entrenamiento de una longitud de contexto determinada junto con sus objetivos de predicción desplazados.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Embeddings de tokens

> [!TIP]
> El objetivo de esta tercera fase es muy sencillo: **Asignar a cada uno de los tokens anteriores del vocabulario un vector de las dimensiones deseadas para entrenar el modelo.** Cada palabra del vocabulario será un punto en un espacio de X dimensiones.\
> Ten en cuenta que inicialmente la posición de cada palabra en el espacio se inicializa de forma "aleatoria" y estas posiciones son parámetros entrenables (se mejorarán durante el entrenamiento).
>
> Además, durante el embedding de tokens, **se crea otra capa de embeddings** que representa (en este caso) la **posición absoluta de la palabra en la frase de entrenamiento**. De esta forma, una palabra situada en distintas posiciones de la frase tiene una representación diferente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mecanismos de atención

> [!TIP]
> El objetivo de esta cuarta fase es muy sencillo: **Aplicar algunos mecanismos de atención**. Estos consistirán en muchas **capas repetidas** que van a **capturar la relación de una palabra del vocabulario con sus vecinas en la frase actual que se está utilizando para entrenar el LLM**.\
> Para ello se utilizan muchas capas, por lo que una gran cantidad de parámetros entrenables capturarán esta información.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arquitectura del LLM

> [!TIP]
> El objetivo de esta quinta fase es muy sencillo: **Desarrollar la arquitectura completa del LLM**. Unirlo todo, aplicar todas las capas y crear todas las funciones para generar texto o transformar texto en IDs y viceversa.
>
> Esta arquitectura se utilizará tanto para entrenar como para predecir texto después del entrenamiento.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Preentrenamiento y carga de modelos

> [!TIP]
> El objetivo de esta sexta fase es muy sencillo: **Entrenar el modelo desde cero**. Para ello se utilizará la arquitectura del LLM anterior con algunos bucles que recorren los conjuntos de datos usando las funciones de pérdida y el optimizador definidos para entrenar todos los parámetros del modelo.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Mejoras de LoRA en el fine-tuning

> [!TIP]
> LoRA reduce considerablemente el número de parámetros entrenables y el estado del optimizador necesarios para aplicar fine-tuning a un modelo preentrenado.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning para clasificación

> [!TIP]
> El objetivo de esta sección es mostrar cómo aplicar fine-tuning a un modelo ya preentrenado para que, en lugar de generar texto nuevo, el LLM seleccione y proporcione las **probabilidades de que el texto dado se clasifique en cada una de las categorías indicadas** (por ejemplo, si un texto es spam o no).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning para seguir instrucciones

> [!TIP]
> El objetivo de esta sección es mostrar cómo **aplicar fine-tuning a un modelo ya preentrenado para que siga instrucciones**, en lugar de limitarse a generar texto; por ejemplo, respondiendo a tareas como un chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
