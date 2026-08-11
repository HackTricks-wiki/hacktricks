# Тестування LLM

{{#include ../banners/hacktricks-training.md}}

## Запуск і навчання моделей локально

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers — це open-source бібліотека для завантаження, навчання та обслуговування попередньо навчених моделей для завдань, пов’язаних із текстом, зором, аудіо, відео та мультимодальністю. Розміщення моделей і датасетів надається окремо через Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain — це framework для створення застосунків і агентів, керованих моделями, із підтримкою побудови промптів, керування історією/станом розмов, tools, retrieval, інтеграцій із моделями, API та базами даних.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT надає зрозумілі реалізації та workflows командного рядка для попереднього навчання, fine-tuning, оцінювання та розгортання підтримуваних мовних моделей.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Опис:**\
LitServe — це framework від Lightning AI для надання inference API із підтримкою batching, streaming, acceleration і scaling hooks.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl — це open-source framework для post-training і fine-tuning, керований конфігурацією YAML. Він підтримує такі техніки, як повний fine-tuning, LoRA/QLoRA, оптимізація уподобань і навчання на кількох GPU; сам по собі він не є платформою для cloud deployment.<sup>[[5]](#references)</sup>

## Спробувати моделі онлайн

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** — це провідна платформа та спільнота для machine learning, особливо відома своєю роботою у сфері natural language processing (NLP). Вона надає tools, libraries і resources, які спрощують розробку, поширення та розгортання machine learning моделей.\
Hub пропонує кілька відповідних розділів:<sup>[[6]](#references)</sup>

* **Models**: Великий репозиторій **попередньо навчених machine learning моделей**, де користувачі можуть переглядати, завантажувати та інтегрувати моделі для різних завдань, таких як генерація тексту, переклад, розпізнавання зображень тощо.
* **Datasets:** Всеосяжна **колекція датасетів**, що використовуються для навчання й оцінювання моделей. Вона забезпечує простий доступ до різноманітних джерел даних, даючи користувачам змогу знаходити та використовувати дані для власних machine learning проєктів.
* **Spaces:** Платформа для розміщення та поширення **інтерактивних machine learning застосунків** і демо. Вона дає розробникам змогу **демонструвати** свої моделі в роботі, створювати зручні інтерфейси та співпрацювати з іншими, поширюючи live демо.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **і** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** — це репозиторій і бібліотека повторно використовуваних компонентів навчених моделей, особливо модулів, що використовуються через TensorFlow/Keras. **Kaggle** окремо надає notebooks, датасети, competitions і моделі.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Велика колекція попередньо навчених моделей і компонентів моделей, де користувачі можуть переглядати, завантажувати та інтегрувати модулі для таких завдань, як класифікація зображень, text embedding тощо.
* **Tutorials:** Покрокові посібники та приклади, які допомагають користувачам реалізовувати й fine-tune моделі за допомогою TensorFlow Hub.
* **Documentation:** Вичерпні посібники та API references, які допомагають розробникам ефективно використовувати ресурси репозиторію.

## [**Replicate**](https://replicate.com/home)

**Replicate** — це hosted платформа для запуску упакованих machine learning моделей через вебінтерфейс або API.<sup>[[8]](#references)</sup>

* **Models:** Репозиторій machine learning моделей, доданих спільнотою, де користувачі можуть переглядати, випробовувати та інтегрувати моделі у свої застосунки з мінімальними зусиллями.
* **API access:** API для виклику моделей із застосунків без необхідності керувати базовою inference інфраструктурою.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Документація Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Документація Replicate](https://replicate.com/docs)
- [9] [Документація Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
