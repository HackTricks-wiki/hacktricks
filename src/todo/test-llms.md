# Probar LLMs

{{#include ../banners/hacktricks-training.md}}

## Ejecutar y entrenar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers es una library open-source para cargar, entrenar y servir modelos preentrenados en tareas de texto, visión, audio, vídeo y multimodales. El alojamiento de modelos y datasets se proporciona por separado mediante Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain es un framework para crear aplicaciones y agentes basados en modelos, con construcción de prompts, gestión del historial/estado de conversaciones, tools, retrieval e integraciones con modelos, API y bases de datos.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT proporciona implementaciones legibles y workflows de línea de comandos para pretraining, fine-tuning, evaluación y despliegue de language models compatibles.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descripción:**\
LitServe es un framework de model-serving de Lightning AI para exponer APIs de inferencia con batching, streaming, aceleración y hooks de scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl es un framework open-source de post-training y fine-tuning basado en configuración YAML. Admite técnicas como fine-tuning completo, LoRA/QLoRA, optimización de preferencias y entrenamiento multi-GPU; no es una plataforma de despliegue cloud.<sup>[[5]](#references)</sup>

## Probar modelos online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** es una plataforma y comunidad líder en machine learning, especialmente conocida por su trabajo en natural language processing (NLP). Proporciona tools, libraries y resources que facilitan el desarrollo, uso compartido y despliegue de machine learning models.\
El Hub ofrece varias secciones relevantes:<sup>[[6]](#references)</sup>

* **Models**: Un amplio repositorio de **machine learning models preentrenados** donde los usuarios pueden explorar, descargar e integrar modelos para diversas tareas, como generación de texto, traducción, reconocimiento de imágenes y mucho más.
* **Datasets:** Una **colección completa de datasets** utilizados para entrenar y evaluar modelos. Facilita el acceso a diversas fuentes de datos, permitiendo a los usuarios encontrar y utilizar datos para sus proyectos específicos de machine learning.
* **Spaces:** Una plataforma para alojar y compartir **aplicaciones interactivas de machine learning** y demos. Permite a los desarrolladores **mostrar** sus modelos en funcionamiento, crear interfaces fáciles de usar y colaborar con otros compartiendo demos en vivo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** es un repositorio y library de componentes de modelos entrenados reutilizables, especialmente módulos consumidos mediante TensorFlow/Keras. **Kaggle** proporciona por separado notebooks, datasets, competiciones y modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Una amplia colección de modelos preentrenados y componentes de modelos donde los usuarios pueden explorar, descargar e integrar módulos para tareas como clasificación de imágenes, embeddings de texto y mucho más.
* **Tutorials:** Guías y ejemplos paso a paso que ayudan a los usuarios a implementar y ajustar modelos utilizando TensorFlow Hub.
* **Documentation:** Guías completas y referencias de API que ayudan a los desarrolladores a utilizar eficazmente los recursos del repositorio.

## [**Replicate**](https://replicate.com/home)

**Replicate** es una plataforma hosted para ejecutar modelos de machine learning empaquetados mediante una interfaz web o API.<sup>[[8]](#references)</sup>

* **Models:** Un repositorio de machine learning models aportados por la comunidad que los usuarios pueden explorar, probar e integrar en sus aplicaciones con un esfuerzo mínimo.
* **API access:** APIs para invocar modelos desde aplicaciones sin operar la infraestructura de inferencia subyacente.

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
