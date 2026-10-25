# Narzędzia i platformy modeli AI

{{#include ../banners/hacktricks-training.md}}

## Uruchamianie i trenowanie modeli lokalnie

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers to biblioteka open source do ładowania, trenowania i udostępniania wstępnie wytrenowanych modeli do zadań związanych z tekstem, obrazem, dźwiękiem, wideo i multimodalnością. Modele i zbiory danych są udostępniane osobno za pośrednictwem Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain to framework do tworzenia aplikacji i agentów opartych na modelach, oferujący konstruowanie promptów, zarządzanie historią rozmów i stanem, narzędzia, wyszukiwanie, integracje z modelami, API i bazami danych.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT udostępnia czytelne implementacje i przepływy pracy z wiersza poleceń do pretrenowania, dostrajania, ewaluacji i wdrażania obsługiwanych modeli językowych.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe to framework Lightning AI do udostępniania modeli, który pozwala wystawiać API do inferencji z obsługą batchowania, streamingu, akceleracji i skalowania.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl to framework open source do post-treningu i dostrajania, konfigurowany za pomocą YAML. Obsługuje techniki takie jak pełne dostrajanie, LoRA/QLoRA, optymalizacja preferencji i trenowanie na wielu GPU; sam w sobie nie jest platformą do wdrażania w chmurze.<sup>[[5]](#references)</sup>

## Wypróbuj modele online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** to wiodąca platforma i społeczność zajmująca się uczeniem maszynowym, znana szczególnie z pracy nad przetwarzaniem języka naturalnego (NLP). Udostępnia narzędzia, biblioteki i zasoby, które ułatwiają tworzenie, udostępnianie i wdrażanie modeli uczenia maszynowego.\
Hub oferuje kilka istotnych sekcji:<sup>[[6]](#references)</sup>

* **Modele**: obszerne repozytorium **wstępnie wytrenowanych modeli uczenia maszynowego**, które można przeglądać, pobierać i integrować z różnymi zadaniami, takimi jak generowanie tekstu, tłumaczenie, rozpoznawanie obrazów i inne.
* **Zbiory danych:** kompleksowy **zbiór danych** używanych do trenowania i ewaluacji modeli. Ułatwia dostęp do różnorodnych źródeł danych, umożliwiając użytkownikom wyszukiwanie i wykorzystywanie danych w konkretnych projektach uczenia maszynowego.
* **Spaces:** platforma do hostowania i udostępniania **interaktywnych aplikacji i demonstracji uczenia maszynowego**. Pozwala programistom **prezentować** działanie swoich modeli, tworzyć przyjazne dla użytkownika interfejsy i współpracować z innymi przez udostępnianie działających demonstracji.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **i** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** to repozytorium i biblioteka wielokrotnego użytku komponentów wytrenowanych modeli, zwłaszcza modułów używanych przez TensorFlow/Keras. **Kaggle** udostępnia osobno notatniki, zbiory danych, konkursy i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduły:** obszerna kolekcja wstępnie wytrenowanych modeli i komponentów modeli, które można przeglądać, pobierać i integrować z zadaniami takimi jak klasyfikacja obrazów, osadzanie tekstu i inne.
* **Samouczki:** instrukcje krok po kroku i przykłady pomagające wdrażać i dostrajać modele przy użyciu TensorFlow Hub.
* **Dokumentacja:** kompleksowe przewodniki i dokumentacja API pomagające programistom efektywnie korzystać z zasobów repozytorium.

## [**Replicate**](https://replicate.com/home)

**Replicate** to hostowana platforma do uruchamiania spakowanych modeli uczenia maszynowego przez interfejs webowy lub API.<sup>[[8]](#references)</sup>

* **Modele:** repozytorium modeli uczenia maszynowego udostępnianych przez społeczność. Użytkownicy mogą je przeglądać, wypróbowywać i z łatwością integrować ze swoimi aplikacjami.
* **Dostęp przez API:** API umożliwiające wywoływanie modeli z aplikacji bez konieczności obsługi infrastruktury inferencyjnej.

## Atakowanie wystawionych, samodzielnie hostowanych usług AI

Informacje o fingerprintingu i testowaniu black-box samodzielnie hostowanych runnerów modeli, kreatorów agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych znajdziesz w sekcji [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

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
