# LLMs testen

{{#include ../banners/hacktricks-training.md}}

## Modelle lokal ausführen und trainieren

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ist eine Open-Source-Bibliothek zum Laden, Trainieren und Bereitstellen vortrainierter Modelle für Text-, Bild-, Audio-, Video- und multimodale Aufgaben. Das Hosten von Modellen und Datasets wird separat vom Hugging Face Hub bereitgestellt.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ist ein Framework zum Erstellen modellgesteuerter Anwendungen und Agents mit Funktionen für Prompt-Erstellung, die Verwaltung von Konversationsverlauf und Zuständen, Tools, Retrieval sowie Integrationen von Modellen, APIs und Datenbanken.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT bietet übersichtliche Implementierungen und Befehlszeilen-Workflows für das Pretraining, Fine-Tuning, Evaluieren und Bereitstellen unterstützter Sprachmodelle.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Beschreibung:**\
LitServe ist ein Model-Serving-Framework von Lightning AI zum Bereitstellen von Inference-APIs mit Funktionen für Batching, Streaming, Beschleunigung und Skalierung.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ist ein Open-Source-Framework für Post-Training und Fine-Tuning, das durch eine YAML-Konfiguration gesteuert wird. Es unterstützt Techniken wie vollständiges Fine-Tuning, LoRA/QLoRA, Preference Optimization und Multi-GPU-Training; es ist selbst keine Cloud-Deployment-Plattform.<sup>[[5]](#references)</sup>

## Modelle online testen

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ist eine führende Plattform und Community für Machine Learning, die besonders für ihre Arbeit im Bereich Natural Language Processing (NLP) bekannt ist. Sie bietet Tools, Bibliotheken und Ressourcen, die das Entwickeln, Teilen und Bereitstellen von Machine-Learning-Modellen erleichtern.\
Der Hub bietet mehrere relevante Bereiche:<sup>[[6]](#references)</sup>

* **Models**: Ein umfangreiches Repository mit **vortrainierten Machine-Learning-Modellen**, in dem Benutzer Modelle für verschiedene Aufgaben wie Textgenerierung, Übersetzung, Bilderkennung und mehr durchsuchen, herunterladen und integrieren können.
* **Datasets:** Eine umfassende **Sammlung von Datasets**, die zum Trainieren und Evaluieren von Modellen verwendet werden. Sie ermöglicht den einfachen Zugriff auf vielfältige Datenquellen, sodass Benutzer Daten für ihre spezifischen Machine-Learning-Projekte finden und nutzen können.
* **Spaces:** Eine Plattform zum Hosten und Teilen **interaktiver Machine-Learning-Anwendungen** und Demos. Sie ermöglicht Entwicklern, ihre Modelle in Aktion zu **präsentieren**, benutzerfreundliche Oberflächen zu erstellen und durch das Teilen von Live-Demos mit anderen zusammenzuarbeiten.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ist ein Repository und eine Bibliothek für wiederverwendbare trainierte Modellkomponenten, insbesondere Module, die über TensorFlow/Keras verwendet werden. **Kaggle** bietet separat Notebooks, Datasets, Wettbewerbe und Modelle.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Eine umfangreiche Sammlung vortrainierter Modelle und Modellkomponenten, in der Benutzer Module für Aufgaben wie Bildklassifizierung, Text-Embedding und mehr durchsuchen, herunterladen und integrieren können.
* **Tutorials:** Schritt-für-Schritt-Anleitungen und Beispiele, die Benutzern helfen, Modelle mit TensorFlow Hub zu implementieren und feinzujustieren.
* **Documentation:** Umfassende Anleitungen und API-Referenzen, die Entwicklern helfen, die Ressourcen des Repositorys effektiv zu nutzen.

## [**Replicate**](https://replicate.com/home)

**Replicate** ist eine gehostete Plattform zum Ausführen paketierter Machine-Learning-Modelle über eine Weboberfläche oder API.<sup>[[8]](#references)</sup>

* **Models:** Ein Repository mit Machine-Learning-Modellen, die von der Community bereitgestellt werden und die Benutzer durchsuchen, ausprobieren und mit minimalem Aufwand in ihre Anwendungen integrieren können.
* **API access:** APIs zum Aufrufen von Modellen aus Anwendungen, ohne die zugrunde liegende Inference-Infrastruktur betreiben zu müssen.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Dokumentation des Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Dokumentation von Replicate](https://replicate.com/docs)
- [9] [Dokumentation von Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
