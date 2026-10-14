# AI Model Tools और Platforms

{{#include ../banners/hacktricks-training.md}}

## Models को locally चलाएँ और train करें

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers, text, vision, audio, video और multimodal tasks में pretrained models को load करने, train करने और serve करने के लिए एक open-source library है। Models और datasets की hosting, Hugging Face Hub अलग से उपलब्ध कराता है।<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain, prompt construction, conversation-history/state management, tools, retrieval, model, API और database integrations के साथ model-driven applications और agents बनाने का framework है।<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, समर्थित language models को pretrain, fine-tune, evaluate और deploy करने के लिए आसानी से पढ़े जा सकने वाले implementations और command-line workflows प्रदान करता है।<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**विवरण:**\
LitServe, Lightning AI का model-serving framework है, जो batching, streaming, acceleration और scaling hooks के साथ inference APIs उपलब्ध कराता है।<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML configuration से संचालित एक open-source post-training और fine-tuning framework है। यह full fine-tuning, LoRA/QLoRA, preference optimization और multi-GPU training जैसी techniques का समर्थन करता है; यह स्वयं cloud deployment platform नहीं है।<sup>[[5]](#references)</sup>

## Models ऑनलाइन आज़माएँ

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** machine learning के लिए एक अग्रणी platform और community है, जो खास तौर पर natural language processing (NLP) में अपने काम के लिए जाना जाता है। यह ऐसे tools, libraries और resources प्रदान करता है जिनसे machine learning models को develop करना, share करना और deploy करना आसान होता है।\
Hub में कई प्रासंगिक sections हैं:<sup>[[6]](#references)</sup>

* **Models**: **Pretrained machine learning models** का एक विशाल repository, जहाँ users text generation, translation, image recognition और अन्य tasks के लिए models ब्राउज़, download और integrate कर सकते हैं।
* **Datasets:** Models को train और evaluate करने के लिए उपयोग किए जाने वाले **datasets का व्यापक संग्रह**। यह विविध data sources तक आसान पहुँच देता है, जिससे users अपने खास machine learning projects के लिए data ढूँढ और उपयोग कर सकते हैं।
* **Spaces:** **Interactive machine learning applications** और demos को host और share करने का platform। इससे developers अपने models को काम करते हुए **दिखा**, user-friendly interfaces बना और live demos साझा करके दूसरों के साथ सहयोग कर सकते हैं।

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **और** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** पुनः उपयोग किए जा सकने वाले trained model components का repository और library है, खासकर उन modules के लिए जिन्हें TensorFlow/Keras के ज़रिए उपयोग किया जाता है। **Kaggle** अलग से notebooks, datasets, competitions और models प्रदान करता है।<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Pretrained models और model components का एक विशाल संग्रह, जहाँ users image classification, text embedding और अन्य tasks के लिए modules ब्राउज़, download और integrate कर सकते हैं।
* **Tutorials:** Step-by-step guides और examples, जो users को TensorFlow Hub का उपयोग करके models implement और fine-tune करने में मदद करते हैं।
* **Documentation:** विस्तृत guides और API references, जो developers को repository के resources का प्रभावी ढंग से उपयोग करने में मदद करते हैं।

## [**Replicate**](https://replicate.com/home)

**Replicate** packaged machine-learning models को web interface या API के ज़रिए चलाने का एक hosted platform है।<sup>[[8]](#references)</sup>

* **Models:** Community द्वारा योगदान किए गए machine learning models का repository, जहाँ users models ब्राउज़ और आज़मा सकते हैं, और कम मेहनत में उन्हें अपने applications में integrate कर सकते हैं।
* **API access:** ऐसे APIs, जिनसे applications में models को invoke किया जा सकता है, बिना underlying inference infrastructure को संचालित किए।

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
