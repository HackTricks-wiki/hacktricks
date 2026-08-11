# Testowanie LLM-ów

{{#include ../banners/hacktricks-training.md}}

## Uruchamianie i trenowanie modeli lokalnie

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers to open-source'owa biblioteka służąca do ładowania, trenowania i udostępniania wstępnie wytrenowanych modeli do zadań związanych z tekstem, obrazem, dźwiękiem, wideo i multimodalnością. Hosting modeli i datasetów jest udostępniany osobno przez Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain to framework do tworzenia aplikacji i agentów opartych na modelach, obejmujący konstruowanie promptów, zarządzanie historią/stanem konwersacji, tools, retrieval oraz integracje z modelami, API i bazami danych.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT udostępnia czytelne implementacje i workflows wiersza poleceń do pretrainingu, fine-tuningu, ewaluacji i wdrażania obsługiwanych modeli językowych.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServe to framework model-serving od Lightning AI, służący do udostępniania API inference z obsługą batchingu, streamingu, akceleracji i hooków skalowania.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl to open-source'owy framework post-trainingu i fine-tuningu oparty na konfiguracji YAML. Obsługuje techniki takie jak pełny fine-tuning, LoRA/QLoRA, optymalizację preferencji i trenowanie na wielu GPU; sam w sobie nie jest platformą cloud deploymentu.<sup>[[5]](#references)</sup>

## Wypróbuj modele online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** to wiodąca platforma i społeczność związana z machine learningiem, znana przede wszystkim z prac nad przetwarzaniem języka naturalnego (NLP). Udostępnia tools, biblioteki i zasoby ułatwiające tworzenie, udostępnianie i wdrażanie modeli machine learning.\
Hub oferuje kilka istotnych sekcji:<sup>[[6]](#references)</sup>

* **Models**: Obszerne repozytorium **wstępnie wytrenowanych modeli machine learning**, w którym użytkownicy mogą przeglądać, pobierać i integrować modele do różnych zadań, takich jak generowanie tekstu, tłumaczenie, rozpoznawanie obrazów i inne.
* **Datasets:** Obszerna **kolekcja datasetów** używanych do trenowania i ewaluacji modeli. Ułatwia dostęp do różnorodnych źródeł danych, umożliwiając użytkownikom znalezienie i wykorzystanie danych w konkretnych projektach machine learning.
* **Spaces:** Platforma do hostowania i udostępniania **interaktywnych aplikacji machine learning** oraz demonstracji. Pozwala developerom **prezentować** działanie modeli, tworzyć przyjazne interfejsy i współpracować z innymi poprzez udostępnianie działających demonstracji.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** to repozytorium i biblioteka wielokrotnego użytku dla wytrenowanych komponentów modeli, zwłaszcza modułów wykorzystywanych przez TensorFlow/Keras. **Kaggle** osobno udostępnia notebooki, datasety, competitions i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Obszerna kolekcja wstępnie wytrenowanych modeli i komponentów modeli, w której użytkownicy mogą przeglądać, pobierać i integrować moduły do zadań takich jak klasyfikacja obrazów, embedding tekstu i inne.
* **Tutorials:** Przewodniki i przykłady krok po kroku pomagające użytkownikom implementować i dostrajać modele z wykorzystaniem TensorFlow Hub.
* **Documentation:** Kompleksowe przewodniki i referencje API pomagające developerom skutecznie korzystać z zasobów repozytorium.

## [**Replicate**](https://replicate.com/home)

**Replicate** to hostowana platforma do uruchamiania spakowanych modeli machine learning za pośrednictwem interfejsu webowego lub API.<sup>[[8]](#references)</sup>

* **Models:** Repozytorium modeli machine learning udostępnionych przez społeczność, które użytkownicy mogą przeglądać, wypróbowywać i integrować ze swoimi aplikacjami przy minimalnym wysiłku.
* **API access:** API umożliwiające wywoływanie modeli z aplikacji bez obsługi znajdującej się pod spodem infrastruktury inference.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Dokumentacja Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Dokumentacja Replicate](https://replicate.com/docs)
- [9] [Dokumentacja Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
