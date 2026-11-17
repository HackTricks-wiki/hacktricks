# AI-Modelle und Plattformen

{{#include ../banners/hacktricks-training.md}}

## Modelle lokal ausführen und trainieren

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ist eine Open-Source-Bibliothek zum Laden, Trainieren und Bereitstellen vortrainierter Modelle für Text-, Bild-, Audio-, Video- und multimodale Aufgaben. Das Hosting von Modellen und Datensätzen wird separat über den Hugging Face Hub angeboten.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ist ein Framework zum Erstellen modellgesteuerter Anwendungen und Agents mit Funktionen zur Prompt-Erstellung, Verwaltung des Gesprächsverlaufs/Zustands sowie Integrationen für Tools, Retrieval, Modelle, APIs und Datenbanken.<sup>[[2]](#references)</sup>

#### Wiederherstellung serialisierter Objekte in LangChain testen

Wenn eine Anwendung **strukturierte** Benutzereingaben oder Modellausgaben akzeptiert, prüfe, ob verschachtelte Dictionaries in `metadata`, `additional_kwargs`, `response_metadata`, gespeichertem Chat-Verlauf oder einem Ausführungsstream erhalten bleiben. LangChain verwendet mit `lc` markierte Dictionaries als serialisierte Objekte. Bei betroffenen `dumps()`/`dumpd()` → `load()`/`loads()`-Rundreisen kann ein vom Angreifer kontrolliertes Dictionary als Framework-Objekt wiederhergestellt werden, statt Daten zu bleiben. Auch das direkte Laden eines nicht vertrauenswürdigen Manifests ist gefährlich; eine einfache String-Eingabe, die nie als Dictionary geparst wird, erfüllt diese Voraussetzung nicht.<sup>[[10]](#references)[[11]](#references)</sup>

Sende für einen autorisierten Test einen harmlosen, konstruktorähnlichen Canary **als verschachteltes JSON-Objekt**, nicht als String, und prüfe, ob der nachgelagerte Verlauf oder Stream ein `AIMessage`-Objekt statt des ursprünglichen Dictionarys enthält:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Check `RunnableWithMessageHistory`, `astream_log()`, und `astream_events(version="v1")`, wenn sie tatsächlich verwendet werden. Eine erfolgreiche Wiederherstellung eines Objekts kann den späteren Chatverlauf vergiften; breitere Allowlists können andere vertrauenswürdige Klassen instanziieren, deren Konstruktoren Nebenwirkungen haben. Setze dies nicht mit uneingeschränkter pickle-Ausführung gleich. Der ursprüngliche Fehler, der das Entweichen ermöglichte, wurde in `langchain-core` 0.3.81/1.2.5 behoben; ein späterer Fix für breite Allowlists und Secret-Marker wurde in 0.3.85/1.3.3 eingeführt. Verwende für nicht vertrauenswürdige Manifeste eine aktuelle Version und beschränke `allowed_objects` auf Nachrichtenklassen oder eine explizite sichere Liste, mit `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Halte dies für die [Zuordnung von Agent-Trust-Grenzen](AI-Agent-Security-Methodology.md) getrennt von [RCE durch das Laden von Modelldateien](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT bietet gut lesbare Implementierungen und Kommandozeilen-Workflows für das Pretraining, Fine-Tuning, Evaluieren und Bereitstellen unterstützter Sprachmodelle.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Beschreibung:**\
LitServe ist ein Model-Serving-Framework von Lightning AI, um Inference-APIs mit Hooks für Batching, Streaming, Beschleunigung und Skalierung bereitzustellen.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ist ein Open-Source-Framework für Post-Training und Fine-Tuning, das über YAML-Konfiguration gesteuert wird. Es unterstützt Techniken wie vollständiges Fine-Tuning, LoRA/QLoRA, Preference Optimization und Multi-GPU-Training; es ist selbst keine Cloud-Deployment-Plattform.<sup>[[5]](#references)</sup>

## Modelle online ausprobieren

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ist eine führende Plattform und Community für Machine Learning, die besonders für ihre Arbeit im Bereich Natural Language Processing (NLP) bekannt ist. Sie stellt Tools, Bibliotheken und Ressourcen bereit, die die Entwicklung, den Austausch und die Bereitstellung von Machine-Learning-Modellen erleichtern.\
Der Hub bietet mehrere relevante Bereiche:<sup>[[6]](#references)</sup>

* **Models**: Ein umfangreiches Repository mit **vortrainierten Machine-Learning-Modellen**, in dem Benutzer Modelle für verschiedene Aufgaben wie Textgenerierung, Übersetzung, Bilderkennung und mehr durchsuchen, herunterladen und integrieren können.
* **Datasets:** Eine umfassende **Sammlung von Datensätzen** für das Training und die Evaluierung von Modellen. Sie ermöglicht den einfachen Zugriff auf vielfältige Datenquellen, sodass Benutzer Daten für ihre spezifischen Machine-Learning-Projekte finden und verwenden können.
* **Spaces:** Eine Plattform zum Hosten und Teilen von **interaktiven Machine-Learning-Anwendungen** und Demos. Entwickler können damit ihre Modelle in Aktion **präsentieren**, benutzerfreundliche Oberflächen erstellen und mit anderen zusammenarbeiten, indem sie Live-Demos teilen.

#### Öffentliche Laufzeitprotokolle von Spaces prüfen

Der Repository-Code eines öffentlichen Space kann zeigen, welche Eingaben und Umgebungsvariablen die App protokolliert. Prüfe im Rahmen einer autorisierten Untersuchung den **run**-Protokollstream als separate Angriffsfläche neben der App-Oberfläche. Hugging Face dokumentiert den SSE-Endpunkt für Space-Protokolle; Untersuchungen ergaben, dass andere Hub-Benutzer öffentliche Space-Protokolle lesen konnten und diese mitunter API-Schlüssel, Benutzer-Prompts oder ein in einer Request-URL protokolliertes Dev-Mode-Zugriffstoken enthielten. Ein Token in einem Protokoll ist nur dann relevant, wenn der zugehörige privilegierte Modus weiterhin aktiviert und das Token noch gültig ist.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Verwende ein Token für dein autorisiertes Hub-Konto; dies ist **keine** Anfrage nach dem Secret des Space-Eigentümers. Die Antwort ist ein SSE-Stream (`data:`-Zeilen). Ordne offengelegte Werte dem Code des Space und der aktuellen Laufzeit zu, statt anzunehmen, dass ein Variablenname beweist, dass sein Wert geleakt wurde. Für einen [self-hosted Gradio- oder Model-Runner-Endpunkt](AI-Exposed-Self-Hosted-AI-Services.md) folge stattdessen dieser Seite.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ist ein Repository und eine Bibliothek für wiederverwendbare trainierte Modellkomponenten, insbesondere Module, die über TensorFlow/Keras verwendet werden. **Kaggle** bietet unabhängig davon Notebooks, Datensätze, Wettbewerbe und Modelle.<sup>[[7]](#references)[[9]](#references)</sup>

* **Module:** Eine umfangreiche Sammlung vortrainierter Modelle und Modellkomponenten, in der Nutzer Module für Aufgaben wie Bildklassifizierung, Texteinbettung und mehr durchsuchen, herunterladen und integrieren können.
* **Tutorials:** Schritt-für-Schritt-Anleitungen und Beispiele, die Nutzern helfen, Modelle mit TensorFlow Hub zu implementieren und zu fine-tunen.
* **Dokumentation:** Umfassende Anleitungen und API-Referenzen, die Entwicklern helfen, die Ressourcen des Repositorys effektiv zu nutzen.

## [**Replicate**](https://replicate.com/home)

**Replicate** ist eine gehostete Plattform, auf der sich verpackte Machine-Learning-Modelle über eine Weboberfläche oder API ausführen lassen.<sup>[[8]](#references)</sup>

* **Modelle:** Ein Repository mit von der Community beigesteuerten Machine-Learning-Modellen, die Nutzer durchsuchen, ausprobieren und mit minimalem Aufwand in ihre Anwendungen integrieren können.
* **API-Zugriff:** APIs zum Aufrufen von Modellen aus Anwendungen, ohne die zugrunde liegende Inferenzinfrastruktur betreiben zu müssen.

## Angriffe auf exponierte self-hosted AI-Dienste

Informationen zu Black-Box-Fingerprinting und Tests von self-hosted Model Runnern, Agent-Buildern, ML-Demo-UIs, Compute-Clustern und Vektordatenbanken findest du unter [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Dokumentation zu Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate-Dokumentation](https://replicate.com/docs)
- [9] [Kaggle-Dokumentation](https://www.kaggle.com/docs)
- [10] [Sicherheitshinweis zu LangChain-Serialisierungsinjektion](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Sicherheitshinweis zur unsicheren Objektwiederherstellung in LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChain-Load-API und Bedrohungsmodell](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging-Face-Spaces-Logs-API](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Dein Space ist meine Zone: Sicherheitsrisiken von AI-Apps auf Modell-Hubs](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
