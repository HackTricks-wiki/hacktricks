# Herramientas y plataformas para modelos de IA

{{#include ../banners/hacktricks-training.md}}

## Ejecutar y entrenar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers es una biblioteca de código abierto para cargar, entrenar y servir modelos preentrenados para tareas de texto, visión, audio, video y multimodales. El alojamiento de modelos y conjuntos de datos se ofrece por separado a través de Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain es un framework para crear aplicaciones y agentes basados en modelos, con herramientas para construir prompts, gestionar el historial y el estado de las conversaciones, integrar herramientas, recuperar información e integrar modelos, API y bases de datos.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT ofrece implementaciones fáciles de leer y flujos de trabajo de línea de comandos para preentrenar, ajustar, evaluar e implementar los modelos de lenguaje compatibles.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descripción:**\
LitServe es un framework de Lightning AI para servir modelos mediante API de inferencia, con opciones para batching, streaming, aceleración y escalado.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl es un framework de código abierto para el postentrenamiento y el ajuste fino, basado en una configuración YAML. Admite técnicas como el ajuste fino completo, LoRA/QLoRA, la optimización de preferencias y el entrenamiento en varias GPU; no es en sí una plataforma de implementación en la nube.<sup>[[5]](#references)</sup>

## Probar modelos en línea

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** es una plataforma y comunidad líder en aprendizaje automático, especialmente conocida por su trabajo en procesamiento del lenguaje natural (NLP). Ofrece herramientas, bibliotecas y recursos que facilitan el desarrollo, el intercambio y la implementación de modelos de aprendizaje automático.\
Hub ofrece varias secciones relevantes:<sup>[[6]](#references)</sup>

* **Modelos**: Un amplio repositorio de **modelos de aprendizaje automático preentrenados** en el que los usuarios pueden explorar, descargar e integrar modelos para diversas tareas, como generación de texto, traducción, reconocimiento de imágenes y más.
* **Conjuntos de datos:** Una amplia **colección de conjuntos de datos** utilizados para entrenar y evaluar modelos. Facilita el acceso a diversas fuentes de datos, lo que permite a los usuarios encontrar y utilizar datos para sus proyectos específicos de aprendizaje automático.
* **Spaces:** Una plataforma para alojar y compartir **aplicaciones interactivas de aprendizaje automático** y demostraciones. Permite a los desarrolladores **mostrar** sus modelos en funcionamiento, crear interfaces fáciles de usar y colaborar con otros compartiendo demostraciones en vivo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **y** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** es un repositorio y una biblioteca de componentes de modelos entrenados reutilizables, especialmente módulos que se utilizan con TensorFlow/Keras. **Kaggle** ofrece por separado notebooks, conjuntos de datos, competiciones y modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Módulos:** Una amplia colección de modelos preentrenados y componentes de modelos que los usuarios pueden explorar, descargar e integrar para tareas como clasificación de imágenes, representación vectorial de texto y más.
* **Tutoriales:** Guías e ejemplos paso a paso que ayudan a los usuarios a implementar y ajustar modelos mediante TensorFlow Hub.
* **Documentación:** Guías completas y referencias de API que ayudan a los desarrolladores a utilizar eficazmente los recursos del repositorio.

## [**Replicate**](https://replicate.com/home)

**Replicate** es una plataforma alojada para ejecutar modelos de aprendizaje automático empaquetados mediante una interfaz web o una API.<sup>[[8]](#references)</sup>

* **Modelos:** Un repositorio de modelos de aprendizaje automático aportados por la comunidad, donde los usuarios pueden explorar y probar modelos e integrarlos en sus aplicaciones con un esfuerzo mínimo.
* **Acceso a la API:** API para invocar modelos desde aplicaciones sin operar la infraestructura de inferencia subyacente.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Documentación de Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Documentación de Replicate](https://replicate.com/docs)
- [9] [Documentación de Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
