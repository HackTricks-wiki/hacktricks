# LLM Training - Preparación de Datos

**Estas son mis notas del libro muy recomendado** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **con información adicional.**

## Información Básica

Deberías comenzar leyendo esta publicación para algunos conceptos básicos que deberías conocer:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenización

> [!TIP]
> El objetivo de esta fase inicial es muy simple: **Dividir la entrada en tokens (ids) de una manera que tenga sentido**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Muestreo de Datos

> [!TIP]
> El objetivo de esta segunda fase es muy simple: **Muestrear los datos de entrada y prepararlos para la fase de entrenamiento, generalmente separando el conjunto de datos en oraciones de una longitud específica y generando también la respuesta esperada.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Embeddings de Tokens

> [!TIP]
> El objetivo de esta tercera fase es muy simple: **Asignar a cada uno de los tokens anteriores en el vocabulario un vector de las dimensiones deseadas para entrenar el modelo.** Cada palabra en el vocabulario será un punto en un espacio de X dimensiones.\
> Ten en cuenta que inicialmente la posición de cada palabra en el espacio se inicializa "aleatoriamente" y estas posiciones son parámetros entrenables (se mejorarán durante el entrenamiento).
>
> Además, durante el embedding de tokens **se crea otra capa de embeddings** que representa (en este caso) la **posición absoluta de la palabra en la oración de entrenamiento**. De esta manera, una palabra en diferentes posiciones en la oración tendrá una representación (significado) diferente.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Mecanismos de Atención

> [!TIP]
> El objetivo de esta cuarta fase es muy simple: **Aplicar algunos mecanismos de atención**. Estos serán muchas **capas repetidas** que van a **capturar la relación de una palabra en el vocabulario con sus vecinos en la oración actual que se está utilizando para entrenar el LLM**.\
> Se utilizan muchas capas para esto, por lo que muchos parámetros entrenables van a capturar esta información.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. Arquitectura del LLM

> [!TIP]
> El objetivo de esta quinta fase es muy simple: **Desarrollar la arquitectura del LLM completo**. Juntar todo, aplicar todas las capas y crear todas las funciones para generar texto o transformar texto a IDs y viceversa.
>
> Esta arquitectura se utilizará tanto para entrenar como para predecir texto después de haber sido entrenada.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-entrenamiento y Carga de Modelos

> [!TIP]
> El objetivo de esta sexta fase es muy simple: **Entrenar el modelo desde cero**. Para esto se utilizará la arquitectura LLM anterior con algunos bucles sobre los conjuntos de datos utilizando las funciones de pérdida y optimizador definidos para entrenar todos los parámetros del modelo.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. Mejoras de LoRA en el ajuste fino

> [!TIP]
> El uso de **LoRA reduce mucho la computación** necesaria para **ajustar finamente** modelos ya entrenados.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Ajuste Fino para Clasificación

> [!TIP]
> El objetivo de esta sección es mostrar cómo ajustar finamente un modelo ya preentrenado para que en lugar de generar nuevo texto, el LLM seleccione y dé las **probabilidades de que el texto dado sea categorizado en cada una de las categorías dadas** (como si un texto es spam o no).

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Ajuste Fino para seguir instrucciones

> [!TIP]
> El objetivo de esta sección es mostrar cómo **ajustar finamente un modelo ya preentrenado para seguir instrucciones** en lugar de solo generar texto, por ejemplo, respondiendo a tareas como un chatbot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
