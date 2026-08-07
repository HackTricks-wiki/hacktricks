# Training de LLM - Preparación de datos

{{#include ../../banners/hacktricks-training.md}}

**Estas son mis notas del libro muy recomendado** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **con información adicional.**<sup>[[1]](#references)</sup>

## Información básica

Deberías empezar leyendo este post para conocer algunos conceptos básicos:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenización

> [!TIP]
> El objetivo de esta fase inicial es muy sencillo: **Dividir la entrada en tokens (ids) de alguna manera que tenga sentido**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Muestreo de datos

> [!TIP]
> El objetivo de esta segunda fase es muy sencillo: **Muestrear los datos de entrada y prepararlos para la fase de training, normalmente separando el dataset en frases de una longitud específica y generando también la respuesta esperada.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> El objetivo de esta tercera fase es muy sencillo: **Asignar a cada uno de los tokens anteriores del vocabulario un vector con las dimensiones deseadas para entrenar el modelo.** Cada palabra del vocabulario será un punto en un espacio de X dimensiones.\
> Ten en cuenta que inicialmente la posición de cada palabra en el espacio se inicializa de forma «aleatoria» y estas posiciones son parámetros entrenables (se mejorarán durante el training).
>
> Además, durante el token embedding **se crea otra capa de embeddings** que representa (en este caso) la **posición absoluta de la palabra en la frase de training**. De esta manera, una palabra situada en diferentes posiciones de la frase tendrá una representación (significado) diferente.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mecanismos de atención

> [!TIP]
> El objetivo de esta cuarta fase es muy sencillo: **Aplicar algunos mecanismos de atención**. Estos consistirán en muchas **capas repetidas** que van a **capturar la relación de una palabra del vocabulario con sus palabras vecinas en la frase actual que se está utilizando para entrenar el LLM**.\
> Se utilizan muchas capas para esto, por lo que muchos parámetros entrenables van a capturar esta información.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arquitectura del LLM

> [!TIP]
> El objetivo de esta quinta fase es muy sencillo: **Desarrollar la arquitectura completa del LLM**. Integrarlo todo, aplicar todas las capas y crear todas las funciones para generar texto o transformar texto a IDs y viceversa.
>
> Esta arquitectura se utilizará tanto para el training como para predecir texto después de haber sido entrenada.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training y carga de modelos

> [!TIP]
> El objetivo de esta sexta fase es muy sencillo: **Entrenar el modelo desde cero**. Para ello, se utilizará la arquitectura del LLM anterior con algunos bucles que recorren los datasets usando las funciones de pérdida y el optimizador definidos para entrenar todos los parámetros del modelo.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Mejoras de LoRA en fine-tuning

> [!TIP]
> El uso de **LoRA reduce mucho la computación** necesaria para hacer **fine-tuning** de modelos ya entrenados.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning para clasificación

> [!TIP]
> El objetivo de esta sección es mostrar cómo hacer fine-tuning de un modelo ya pre-entrenado para que, en lugar de generar texto nuevo, el LLM seleccione y proporcione las **probabilidades de que el texto dado pertenezca a cada una de las categorías indicadas** (por ejemplo, si un texto es spam o no).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning para seguir instrucciones

> [!TIP]
> El objetivo de esta sección es mostrar cómo hacer **fine-tuning de un modelo ya pre-entrenado para seguir instrucciones**, en lugar de limitarse a generar texto; por ejemplo, respondiendo a tareas como un chatbot.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Referencias

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
