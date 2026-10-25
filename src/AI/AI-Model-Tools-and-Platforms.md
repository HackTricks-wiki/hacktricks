# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## स्थानीय रूप से models चलाएँ और train करें

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers, text, vision, audio, video और multimodal tasks में pretrained models को load, train और serve करने के लिए एक open-source library है। Models और datasets की hosting अलग से Hugging Face Hub उपलब्ध कराता है।<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain, prompt निर्माण, conversation history/state management, tools, retrieval, model, API और database integrations के साथ model-driven applications और agents बनाने का एक framework है।<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT समर्थित language models को pretrain, fine-tune, evaluate और deploy करने के लिए आसानी से समझे जा सकने वाले implementations और command-line workflows उपलब्ध कराता है।<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**विवरण:**\
LitServe, Lightning AI का model-serving framework है, जो batching, streaming, acceleration और scaling hooks के साथ inference APIs उपलब्ध कराता है।<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML configuration पर आधारित एक open-source post-training और fine-tuning framework है। यह full fine-tuning, LoRA/QLoRA, preference optimization और multi-GPU training जैसी techniques का समर्थन करता है; यह स्वयं cloud deployment platform नहीं है।<sup>[[5]](#references)</sup>

## ऑनलाइन models आज़माएँ

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** machine learning के लिए एक अग्रणी platform और community है, जो विशेष रूप से natural language processing (NLP) में अपने काम के लिए जाना जाता है। यह ऐसे tools, libraries और resources उपलब्ध कराता है जिनसे machine learning models को develop, share और deploy करना आसान होता है।\
Hub में कई उपयोगी sections हैं:<sup>[[6]](#references)</sup>

* **Models**: **pre-trained machine learning models** का एक विशाल repository, जहाँ users text generation, translation, image recognition और अन्य tasks के लिए models खोज, download और integrate कर सकते हैं।
* **Datasets:** Models को train और evaluate करने के लिए उपयोग किए जाने वाले **datasets का व्यापक संग्रह**। यह विविध data sources तक आसान पहुँच देता है, जिससे users अपने machine learning projects के लिए data ढूँढ़ और उपयोग कर सकते हैं।
* **Spaces:** **Interactive machine learning applications** और demos को host और share करने का platform। यह developers को अपने models को काम करते हुए **दिखाने**, user-friendly interfaces बनाने और live demos share करके दूसरों के साथ सहयोग करने देता है।

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** reusable trained model components के लिए एक repository और library है, विशेष रूप से ऐसे modules के लिए जिनका उपयोग TensorFlow/Keras के ज़रिए किया जाता है। **Kaggle** अलग से notebooks, datasets, competitions और models उपलब्ध कराता है।<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Pre-trained models और model components का एक विशाल संग्रह, जहाँ users image classification, text embedding और अन्य tasks के लिए modules खोज, download और integrate कर सकते हैं।
* **Tutorials:** चरण-दर-चरण guides और examples, जो users को TensorFlow Hub का उपयोग करके models implement और fine-tune करने में मदद करते हैं।
* **Documentation:** विस्तृत guides और API references, जो developers को repository के resources का प्रभावी ढंग से उपयोग करने में मदद करते हैं।

## [**Replicate**](https://replicate.com/home)

**Replicate** एक hosted platform है, जहाँ web interface या API के ज़रिए packaged machine-learning models चलाए जा सकते हैं।<sup>[[8]](#references)</sup>

* **Models:** Community द्वारा उपलब्ध कराए गए machine learning models का एक repository, जहाँ users models खोज और आज़मा सकते हैं, और कम से कम मेहनत में उन्हें अपने applications में integrate कर सकते हैं।
* **API access:** ऐसे APIs जिनसे applications में models invoke किए जा सकते हैं, बिना underlying inference infrastructure को operate किए।

## उजागर self-hosted AI services पर हमला करना

Self-hosted model runners, agent builders, ML demo UIs, compute clusters और vector databases की black-box fingerprinting और testing के लिए [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) देखें।

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub दस्तावेज़](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate दस्तावेज़](https://replicate.com/docs)
- [9] [Kaggle दस्तावेज़](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
