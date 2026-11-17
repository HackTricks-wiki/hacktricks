# Herramientas y plataformas de modelos de IA

{{#include ../banners/hacktricks-training.md}}

## Ejecutar y entrenar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers es una biblioteca de código abierto para cargar, entrenar y servir modelos preentrenados para tareas de texto, visión, audio, video y multimodales. El alojamiento de modelos y conjuntos de datos se ofrece por separado a través de Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain es un framework para crear aplicaciones y agentes basados en modelos, con funciones para construir prompts, gestionar el historial y el estado de las conversaciones, usar herramientas y recuperar datos, e integrar modelos, API y bases de datos.<sup>[[2]](#references)</sup>

#### Probar la reactivación de objetos serializados de LangChain

Cuando una aplicación acepta entradas estructuradas del usuario o salidas del modelo, comprueba si los diccionarios anidados se conservan en `metadata`, `additional_kwargs`, `response_metadata`, el historial de chat guardado o un flujo de ejecución. LangChain usa diccionarios etiquetados con `lc` como objetos serializados. En los ciclos de ida y vuelta afectados de `dumps()`/`dumpd()` → `load()`/`loads()`, un diccionario controlado por un atacante podría reactivarse como un objeto del framework en vez de permanecer como datos. Cargar directamente un manifiesto no confiable también es peligroso; una entrada de texto simple que nunca se analiza como diccionario no cumple este requisito previo.<sup>[[10]](#references)[[11]](#references)</sup>

Para una prueba autorizada, envía un canary inofensivo con forma de constructor **como objeto JSON anidado**, no como una cadena, y comprueba si el historial o el flujo posterior contienen un objeto `AIMessage` en lugar del diccionario original:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Comprueba `RunnableWithMessageHistory`, `astream_log()` y `astream_events(version="v1")` cuando se utilicen realmente. Una revivificación correcta del objeto puede envenenar el historial de chat posterior; las allowlists más amplias pueden instanciar otras clases de confianza cuyos constructores tienen efectos secundarios. No equipares esto con la ejecución irrestricta de pickle. La vulnerabilidad original de escape se corrigió en `langchain-core` 0.3.81/1.2.5, y una corrección posterior para allowlists amplias y marcadores de secretos se incorporó en 0.3.85/1.3.3. Para manifiestos no confiables, usa una versión actual y restringe `allowed_objects` a clases de mensajes o a una lista segura explícita, con `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Para el [mapeo de límites de confianza de agentes](AI-Agent-Security-Methodology.md), mantén esto diferenciado de la [ejecución remota de código al cargar archivos de modelos](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT proporciona implementaciones fáciles de leer y flujos de trabajo de línea de comandos para preentrenar, ajustar, evaluar e implementar los modelos de lenguaje compatibles.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descripción:**\
LitServe es un framework de serving de modelos de Lightning AI para exponer API de inferencia con batching, streaming y mecanismos de aceleración y escalado.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl es un framework open source de post-training y fine-tuning que utiliza configuración YAML. Admite técnicas como el fine-tuning completo, LoRA/QLoRA, la optimización de preferencias y el entrenamiento multi-GPU; no es en sí una plataforma de despliegue en la nube.<sup>[[5]](#references)</sup>

## Probar modelos en línea

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** es una plataforma y comunidad líder en machine learning, conocida especialmente por su trabajo en procesamiento del lenguaje natural (NLP). Proporciona herramientas, bibliotecas y recursos que facilitan el desarrollo, el uso compartido y el despliegue de modelos de machine learning.\
El Hub ofrece varias secciones relevantes:<sup>[[6]](#references)</sup>

* **Models**: Un amplio repositorio de **modelos de machine learning preentrenados** donde los usuarios pueden explorar, descargar e integrar modelos para diversas tareas, como la generación de texto, la traducción, el reconocimiento de imágenes y más.
* **Datasets:** Una amplia **colección de conjuntos de datos** utilizados para entrenar y evaluar modelos. Facilita el acceso a diversas fuentes de datos, lo que permite encontrar y utilizar datos para proyectos específicos de machine learning.
* **Spaces:** Una plataforma para alojar y compartir **aplicaciones interactivas de machine learning** y demos. Permite a los desarrolladores **mostrar** sus modelos en funcionamiento, crear interfaces fáciles de usar y colaborar con otros compartiendo demos en vivo.

#### Inspeccionar los logs de ejecución de un Space público

El código del repositorio de un Space público puede revelar qué entradas y variables de entorno registra su aplicación. En una evaluación autorizada, inspecciona su flujo de logs de **run** como una superficie distinta de la interfaz de la aplicación. Hugging Face documenta el endpoint SSE de logs de Space; una investigación descubrió que otros usuarios del Hub podían leer los logs de Spaces públicos y que, a veces, estos contenían API keys, prompts de usuarios o un token de acceso a Dev Mode registrado en una URL de solicitud. La presencia de un token en un log solo importa si el modo privilegiado correspondiente sigue habilitado y el token aún es válido.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Usa un token de tu cuenta autorizada de Hub; esto **no** es una solicitud del secreto del propietario del Space. La respuesta es un flujo SSE (líneas `data:`). Correlaciona los valores expuestos con el código del Space y el runtime actual, en lugar de asumir que el nombre de una variable demuestra que su valor se filtró. Para un endpoint de Gradio o model-runner autohospedado, sigue esa página.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** es un repositorio y una biblioteca de componentes de modelos entrenados reutilizables, especialmente módulos que se usan mediante TensorFlow/Keras. **Kaggle** ofrece por separado notebooks, conjuntos de datos, competiciones y modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Módulos:** Una amplia colección de modelos y componentes de modelos preentrenados que los usuarios pueden explorar, descargar e integrar para tareas como clasificación de imágenes, embeddings de texto y más.
* **Tutoriales:** Guías paso a paso y ejemplos que ayudan a los usuarios a implementar y ajustar modelos mediante TensorFlow Hub.
* **Documentación:** Guías completas y referencias de API que ayudan a los desarrolladores a aprovechar eficazmente los recursos del repositorio.

## [**Replicate**](https://replicate.com/home)

**Replicate** es una plataforma alojada para ejecutar modelos de machine learning empaquetados mediante una interfaz web o una API.<sup>[[8]](#references)</sup>

* **Modelos:** Un repositorio de modelos de machine learning aportados por la comunidad que los usuarios pueden explorar y probar, e integrar en sus aplicaciones con un esfuerzo mínimo.
* **Acceso a la API:** API para invocar modelos desde aplicaciones sin operar la infraestructura de inferencia subyacente.

## Ataque a servicios de IA autohospedados expuestos

Para la identificación y las pruebas de caja negra de model runners autohospedados, constructores de agentes, interfaces de demostración de ML, clústeres de cómputo y bases de datos vectoriales, consulta [Servicios de IA autohospedados expuestos](AI-Exposed-Self-Hosted-AI-Services.md).



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
- [10] [Aviso sobre inyección de serialización de LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Aviso sobre la reactivación insegura de objetos de LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load y modelo de amenazas de LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API de logs de Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Tu Space es mi zona: riesgos de seguridad de las aplicaciones de IA en los hubs de modelos](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
