# KI-Modellwerkzeuge und -Plattformen

{{#include ../banners/hacktricks-training.md}}

## Modelle lokal ausführen und trainieren

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ist eine Open-Source-Bibliothek zum Laden, Trainieren und Bereitstellen vortrainierter Modelle für Text-, Bild-, Audio-, Video- und multimodale Aufgaben. Das Hosting von Modellen und Datasets wird separat vom Hugging Face Hub bereitgestellt.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ist ein Framework zum Erstellen modellgesteuerter Anwendungen und Agents mit Funktionen zur Erstellung von Prompts, Verwaltung von Konversationsverlauf und Status sowie zur Integration von Tools, Retrieval, Modellen, APIs und Datenbanken.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT bietet gut lesbare Implementierungen und Kommandozeilen-Workflows für das Pretraining, Fine-Tuning, Evaluieren und Bereitstellen unterstützter Sprachmodelle.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Beschreibung:**\
LitServe ist ein Model-Serving-Framework von Lightning AI, mit dem sich Inference-APIs samt Batch-Verarbeitung, Streaming, Beschleunigung und Skalierung bereitstellen lassen.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ist ein Open-Source-Framework für Post-Training und Fine-Tuning, das über eine YAML-Konfiguration gesteuert wird. Es unterstützt Techniken wie vollständiges Fine-Tuning, LoRA/QLoRA, Preference Optimization und Multi-GPU-Training; es ist selbst keine Cloud-Bereitstellungsplattform.<sup>[[5]](#references)</sup>

## Modelle online ausprobieren

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ist eine führende Plattform und Community für Machine Learning, die besonders für ihre Arbeit im Bereich Natural Language Processing (NLP) bekannt ist. Sie bietet Tools, Bibliotheken und Ressourcen, die die Entwicklung, gemeinsame Nutzung und Bereitstellung von Machine-Learning-Modellen erleichtern.\
Der Hub bietet mehrere relevante Bereiche:<sup>[[6]](#references)</sup>

* **Modelle**: Ein umfangreiches Repository mit **vortrainierten Machine-Learning-Modellen**, in dem Nutzer Modelle für verschiedene Aufgaben wie Textgenerierung, Übersetzung, Bilderkennung und mehr durchsuchen, herunterladen und integrieren können.
* **Datasets:** Eine umfassende **Sammlung von Datasets**, die zum Trainieren und Evaluieren von Modellen verwendet werden. Sie ermöglicht den einfachen Zugriff auf vielfältige Datenquellen, sodass Nutzer Daten für ihre spezifischen Machine-Learning-Projekte finden und verwenden können.
* **Spaces:** Eine Plattform zum Hosten und Teilen **interaktiver Machine-Learning-Anwendungen** und Demos. Entwickler können damit ihre Modelle **präsentieren**, benutzerfreundliche Oberflächen erstellen und durch das Teilen von Live-Demos mit anderen zusammenarbeiten.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ist ein Repository und eine Bibliothek für wiederverwendbare trainierte Modellkomponenten, insbesondere Module, die über TensorFlow/Keras verwendet werden. **Kaggle** bietet separat Notebooks, Datasets, Wettbewerbe und Modelle.<sup>[[7]](#references)[[9]](#references)</sup>

* **Module:** Eine umfangreiche Sammlung vortrainierter Modelle und Modellkomponenten, in der Nutzer Module für Aufgaben wie Bildklassifizierung, Texteinbettung und mehr durchsuchen, herunterladen und integrieren können.
* **Tutorials:** Schritt-für-Schritt-Anleitungen und Beispiele, die Nutzern helfen, Modelle mit TensorFlow Hub zu implementieren und fein abzustimmen.
* **Dokumentation:** Umfassende Anleitungen und API-Referenzen, die Entwicklern helfen, die Ressourcen des Repositorys effektiv zu nutzen.

## [**Replicate**](https://replicate.com/home)

**Replicate** ist eine gehostete Plattform zum Ausführen paketierter Machine-Learning-Modelle über eine Weboberfläche oder API.<sup>[[8]](#references)</sup>

* **Modelle:** Ein Repository mit von der Community beigesteuerten Machine-Learning-Modellen, die Nutzer durchsuchen und ausprobieren sowie mit minimalem Aufwand in ihre Anwendungen integrieren können.
* **API-Zugriff:** APIs zum Aufrufen von Modellen aus Anwendungen, ohne die zugrunde liegende Inference-Infrastruktur betreiben zu müssen.

## Angriffe auf exponierte, selbst gehostete KI-Dienste

Informationen zu Black-Box-Fingerprinting und Tests von selbst gehosteten Model Runnern, Agent Buildern, ML-Demo-UIs, Compute-Clustern und Vektordatenbanken findest du unter [Exponierte, selbst gehostete KI-Dienste](AI-Exposed-Self-Hosted-AI-Services.md).

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Dokumentation zum Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate-Dokumentation](https://replicate.com/docs)
- [9] [Kaggle-Dokumentation](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
