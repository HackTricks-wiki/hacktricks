# Narzędzia i platformy modeli AI

{{#include ../banners/hacktricks-training.md}}

## Uruchamianie i trenowanie modeli lokalnie

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers to biblioteka open source do ładowania, trenowania i udostępniania wstępnie wytrenowanych modeli do zadań związanych z tekstem, obrazem, dźwiękiem, wideo i multimodalnością. Modele i zbiory danych są hostowane osobno w Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain to framework do tworzenia aplikacji i agentów opartych na modelach. Oferuje konstruowanie promptów, zarządzanie historią rozmów i stanem, narzędzia, wyszukiwanie, integracje z modelami, API i bazami danych.<sup>[[2]](#references)</sup>

#### Testowanie odtwarzania serializowanych obiektów w LangChain

Gdy aplikacja przyjmuje **ustrukturyzowane** dane wejściowe od użytkownika lub dane wyjściowe modelu, sprawdź, czy zagnieżdżone słowniki są zachowywane w `metadata`, `additional_kwargs`, `response_metadata`, zapisanej historii czatu lub strumieniu przebiegu. LangChain używa słowników z tagiem `lc` jako obiektów serializowanych. W podatnych rundach `dumps()`/`dumpd()` → `load()`/`loads()` kontrolowany przez atakującego słownik może zostać odtworzony jako obiekt frameworka, zamiast pozostać danymi. Bezpośrednie ładowanie niezaufanego manifestu również jest niebezpieczne; zwykłe wejście tekstowe, które nigdy nie jest analizowane jako słownik, nie spełnia tego warunku wstępnego.<sup>[[10]](#references)[[11]](#references)</sup>

W ramach autoryzowanego testu prześlij nieszkodliwy canary o kształcie wywołania konstruktora **jako zagnieżdżony obiekt JSON**, a nie jako ciąg znaków, i sprawdź, czy w dalszej historii lub strumieniu pojawia się obiekt `AIMessage` zamiast oryginalnego słownika:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Sprawdź `RunnableWithMessageHistory`, `astream_log()` i `astream_events(version="v1")` w rzeczywistym użyciu. Pomyślne odtworzenie obiektu może zatruć późniejszą historię czatu; szersze listy dozwolonych obiektów mogą tworzyć inne zaufane klasy, których konstruktory mają skutki uboczne. Nie należy utożsamiać tego z nieograniczonym wykonywaniem kodu pickle. Pierwotny błąd umożliwiający ucieczkę naprawiono w `langchain-core` 0.3.81/1.2.5, a późniejsza poprawka dotycząca szerokiej listy dozwolonych obiektów i znaczników sekretów trafiła do wersji 0.3.85/1.3.3. W przypadku niezaufanych manifestów używaj aktualnej wersji i ogranicz `allowed_objects` do klas wiadomości albo jawnej bezpiecznej listy, ustawiając `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> W ramach [mapowania granic zaufania agentów](AI-Agent-Security-Methodology.md) traktuj to jako odrębne zagrożenie od [RCE przy ładowaniu plików modeli](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT udostępnia czytelne implementacje i procesy pracy w wierszu poleceń do wstępnego trenowania, dostrajania, oceny i wdrażania obsługiwanych modeli językowych.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Opis:**\
LitServe to framework do udostępniania modeli, stworzony przez Lightning AI, który umożliwia wystawianie API wnioskowania z obsługą batchingu, strumieniowania, akceleracji i skalowania.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl to framework open source do post-treningu i dostrajania, konfigurowany za pomocą YAML. Obsługuje techniki takie jak pełne dostrajanie, LoRA/QLoRA, optymalizacja preferencji i trenowanie na wielu GPU; sam w sobie nie jest platformą wdrażania w chmurze.<sup>[[5]](#references)</sup>

## Wypróbuj modele online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** to wiodąca platforma i społeczność zajmująca się uczeniem maszynowym, znana zwłaszcza z prac nad przetwarzaniem języka naturalnego (NLP). Udostępnia narzędzia, biblioteki i zasoby ułatwiające tworzenie, udostępnianie i wdrażanie modeli uczenia maszynowego.\
Hub oferuje kilka przydatnych sekcji:<sup>[[6]](#references)</sup>

* **Modele**: obszerne repozytorium **wstępnie wytrenowanych modeli uczenia maszynowego**, które użytkownicy mogą przeglądać, pobierać i integrować z różnymi zadaniami, takimi jak generowanie tekstu, tłumaczenie, rozpoznawanie obrazów i inne.
* **Datasets:** obszerny **zbiór zestawów danych** używanych do trenowania i oceny modeli. Ułatwia dostęp do różnorodnych źródeł danych, dzięki czemu użytkownicy mogą znajdować i wykorzystywać dane na potrzeby swoich projektów uczenia maszynowego.
* **Spaces:** platforma do hostowania i udostępniania **interaktywnych aplikacji uczenia maszynowego** oraz demonstracji. Umożliwia programistom **prezentowanie** działania modeli, tworzenie przyjaznych dla użytkownika interfejsów i współpracę z innymi przez udostępnianie działających demonstracji.

#### Sprawdzanie publicznych logów środowiska uruchomieniowego Space

Kod repozytorium publicznego Space może ujawnić, jakie dane wejściowe i zmienne środowiskowe są rejestrowane przez aplikację. Podczas autoryzowanej oceny sprawdź strumień logów `run` jako osobny obszar, niezależny od interfejsu aplikacji. Hugging Face dokumentuje endpoint SSE logów Space; badania wykazały, że logi publicznych Space mogły być odczytywane przez innych użytkowników Hub, a czasem zawierały klucze API, prompty użytkowników lub token dostępu Dev Mode zapisany w adresie URL żądania. Token w logu ma znaczenie tylko wtedy, gdy odpowiadający mu tryb uprzywilejowany pozostaje włączony, a token jest nadal ważny.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Użyj tokena dla swojego autoryzowanego konta Hub; **nie** jest to prośba o sekret właściciela Space. Odpowiedź jest strumieniem SSE (wiersze `data:`). Powiąż ujawnione wartości z kodem Space i bieżącym środowiskiem uruchomieniowym, zamiast zakładać, że sama nazwa zmiennej dowodzi wycieku jej wartości. W przypadku [hostowanego samodzielnie endpointu Gradio lub model-runnera](AI-Exposed-Self-Hosted-AI-Services.md) postępuj zgodnie z instrukcjami na tamtej stronie.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **i** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** to repozytorium i biblioteka wielokrotnego użytku komponentów wytrenowanych modeli, zwłaszcza modułów używanych przez TensorFlow/Keras. **Kaggle** oferuje osobno notatniki, zbiory danych, konkursy i modele.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduły:** Ogromny zbiór wstępnie wytrenowanych modeli i komponentów modeli, które użytkownicy mogą przeglądać, pobierać i integrować na potrzeby zadań takich jak klasyfikacja obrazów, osadzanie tekstu i inne.
* **Samouczki:** Przewodniki i przykłady krok po kroku, które pomagają użytkownikom wdrażać i dostrajać modele przy użyciu TensorFlow Hub.
* **Dokumentacja:** Obszerne przewodniki i opisy API, które pomagają programistom efektywnie korzystać z zasobów repozytorium.

## [**Replicate**](https://replicate.com/home)

**Replicate** to hostowana platforma do uruchamiania spakowanych modeli uczenia maszynowego za pośrednictwem interfejsu internetowego lub API.<sup>[[8]](#references)</sup>

* **Modele:** Repozytorium modeli uczenia maszynowego udostępnionych przez społeczność, które użytkownicy mogą przeglądać, wypróbowywać i z niewielkim wysiłkiem integrować ze swoimi aplikacjami.
* **Dostęp przez API:** API umożliwiające wywoływanie modeli z aplikacji bez konieczności obsługi bazowej infrastruktury wnioskowania.

## Atakowanie wystawionych samodzielnie hostowanych usług AI

Aby przeprowadzić black-box fingerprinting i testowanie samodzielnie hostowanych model-runnerów, narzędzi do tworzenia agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych, zapoznaj się ze stroną [Wystawione samodzielnie hostowane usługi AI](AI-Exposed-Self-Hosted-AI-Services.md).



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
- [10] [Informacja o podatności na wstrzykiwanie podczas serializacji w LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Informacja o podatności związanej z niebezpiecznym odtwarzaniem obiektów w LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load i model zagrożeń LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API logów Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Twój Space to moja strefa: zagrożenia bezpieczeństwa aplikacji AI w hubach modeli](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
