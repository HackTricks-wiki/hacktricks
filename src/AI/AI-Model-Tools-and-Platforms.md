# Herramientas y plataformas de modelos de IA

{{#include ../banners/hacktricks-training.md}}

## Ejecutar y entrenar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers es una biblioteca de código abierto para cargar, entrenar y servir modelos preentrenados para tareas de texto, visión, audio, vídeo y multimodales. El alojamiento de modelos y conjuntos de datos se ofrece por separado en Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain es un framework para crear aplicaciones y agentes basados en modelos, con construcción de prompts, gestión del historial de conversación y del estado, herramientas, recuperación e integraciones con modelos, API y bases de datos.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT ofrece implementaciones fáciles de leer y flujos de trabajo de línea de comandos para preentrenar, hacer fine-tuning, evaluar y desplegar los modelos de lenguaje compatibles.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descripción:**\
LitServe es un framework de Lightning AI para exponer API de inferencia con opciones de batching, streaming, aceleración y escalado.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl es un framework de código abierto para post-training y fine-tuning basado en configuración YAML. Admite técnicas como fine-tuning completo, LoRA/QLoRA, optimización de preferencias y entrenamiento con varias GPU; no es en sí una plataforma de despliegue en la nube.<sup>[[5]](#references)</sup>

## Probar modelos en línea

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** es una plataforma y comunidad líder en machine learning, conocida especialmente por su trabajo en procesamiento del lenguaje natural (NLP). Ofrece herramientas, bibliotecas y recursos que facilitan el desarrollo, el intercambio y el despliegue de modelos de machine learning.\
Hub ofrece varias secciones relevantes:<sup>[[6]](#references)</sup>

* **Modelos**: Un amplio repositorio de **modelos de machine learning preentrenados** donde los usuarios pueden explorar, descargar e integrar modelos para diversas tareas, como generación de texto, traducción, reconocimiento de imágenes y otras.
* **Conjuntos de datos:** Una completa **colección de conjuntos de datos** usados para entrenar y evaluar modelos. Facilita el acceso a diversas fuentes de datos, lo que permite a los usuarios encontrar y utilizar datos para sus proyectos específicos de machine learning.
* **Spaces:** Una plataforma para alojar y compartir **aplicaciones interactivas de machine learning** y demostraciones. Permite a los desarrolladores **mostrar** sus modelos en acción, crear interfaces fáciles de usar y colaborar con otras personas compartiendo demostraciones en vivo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **y** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** es un repositorio y una biblioteca de componentes de modelos entrenados reutilizables, especialmente módulos que se utilizan mediante TensorFlow/Keras. **Kaggle** ofrece por separado notebooks, conjuntos de datos, competiciones y modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Módulos:** Una amplia colección de modelos preentrenados y componentes de modelos que los usuarios pueden explorar, descargar e integrar para tareas como clasificación de imágenes, embeddings de texto y otras.
* **Tutoriales:** Guías paso a paso y ejemplos que ayudan a los usuarios a implementar y ajustar modelos con TensorFlow Hub.
* **Documentación:** Guías completas y referencias de API que ayudan a los desarrolladores a utilizar eficazmente los recursos del repositorio.

## [**Replicate**](https://replicate.com/home)

**Replicate** es una plataforma alojada para ejecutar modelos de machine learning empaquetados mediante una interfaz web o una API.<sup>[[8]](#references)</sup>

* **Modelos:** Un repositorio de modelos de machine learning aportados por la comunidad que los usuarios pueden explorar, probar e integrar en sus aplicaciones con un esfuerzo mínimo.
* **Acceso a la API:** API para invocar modelos desde aplicaciones sin gestionar la infraestructura de inferencia subyacente.

## Atacar servicios de IA autoalojados expuestos

Para realizar fingerprinting y pruebas de caja negra de ejecutores de modelos autoalojados, constructores de agentes, interfaces de demostración de ML, clústeres de cómputo y bases de datos vectoriales, consulta [Servicios de IA autoalojados expuestos](AI-Exposed-Self-Hosted-AI-Services.md).

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
