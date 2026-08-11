# LLMs का परीक्षण

{{#include ../banners/hacktricks-training.md}}

## Models को स्थानीय रूप से चलाना और train करना

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers एक open-source library है, जिसका उपयोग text, vision, audio, video और multimodal tasks के लिए pretrained models को load, train और serve करने के लिए किया जाता है। Model और dataset hosting Hugging Face Hub द्वारा अलग से प्रदान की जाती है।<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain model-driven applications और agents बनाने का एक framework है, जिसमें prompt construction, conversation-history/state management, tools, retrieval, model, API और database integrations शामिल हैं।<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT समर्थित language models के pretraining, fine-tuning, evaluation और deployment के लिए readable implementations और command-line workflows प्रदान करता है।<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**विवरण:**\
LitServe Lightning AI का model-serving framework है, जो batching, streaming, acceleration और scaling hooks के साथ inference APIs expose करता है।<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl YAML configuration द्वारा संचालित एक open-source post-training और fine-tuning framework है। यह full fine-tuning, LoRA/QLoRA, preference optimization और multi-GPU training जैसी techniques को support करता है; यह स्वयं कोई cloud deployment platform नहीं है।<sup>[[5]](#references)</sup>

## Models को online आज़माना

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** machine learning के लिए एक leading platform और community है, जो विशेष रूप से natural language processing (NLP) में अपने कार्य के लिए जाना जाता है। यह ऐसे tools, libraries और resources प्रदान करता है, जो machine learning models को develop, share और deploy करना आसान बनाते हैं।\
Hub में कई relevant sections उपलब्ध हैं:<sup>[[6]](#references)</sup>

* **Models**: **pre-trained machine learning models** का एक विशाल repository, जहां users text generation, translation, image recognition और अन्य tasks के लिए models को browse, download और integrate कर सकते हैं।
* **Datasets:** Models को train और evaluate करने के लिए उपयोग किए जाने वाले **datasets का व्यापक collection**। यह विभिन्न data sources तक आसान access प्रदान करता है, जिससे users अपने specific machine learning projects के लिए data खोज और उपयोग कर सकते हैं।
* **Spaces:** **interactive machine learning applications** और demos को host और share करने का एक platform। यह developers को अपने models को action में **showcase** करने, user-friendly interfaces बनाने और live demos share करके दूसरों के साथ collaborate करने की सुविधा देता है।

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** reusable trained model components के लिए एक repository और library है, विशेष रूप से TensorFlow/Keras के माध्यम से उपयोग किए जाने वाले modules के लिए। **Kaggle** अलग रूप से notebooks, datasets, competitions और models प्रदान करता है।<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** pre-trained models और model components का एक विशाल collection, जहां users image classification, text embedding और अन्य tasks के लिए modules को browse, download और integrate कर सकते हैं।
* **Tutorials:** step-by-step guides और examples, जो users को TensorFlow Hub का उपयोग करके models implement और fine-tune करने में सहायता करते हैं।
* **Documentation:** व्यापक guides और API references, जो developers को repository के resources का प्रभावी ढंग से उपयोग करने में सहायता करते हैं।

## [**Replicate**](https://replicate.com/home)

**Replicate** web interface या API के माध्यम से packaged machine-learning models चलाने का एक hosted platform है।<sup>[[8]](#references)</sup>

* **Models:** community द्वारा contribute किए गए machine learning models का एक repository, जहां users models को browse और try कर सकते हैं तथा उन्हें न्यूनतम effort के साथ अपने applications में integrate कर सकते हैं।
* **API access:** underlying inference infrastructure को operate किए बिना applications से models invoke करने के लिए APIs।

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub documentation](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate documentation](https://replicate.com/docs)
- [9] [Kaggle documentation](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
