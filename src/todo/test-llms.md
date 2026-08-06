# LLMs का परीक्षण

{{#include ../banners/hacktricks-training.md}}

## Models को स्थानीय रूप से चलाना और train करना

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers, GPT, BERT और कई अन्य LLMs का उपयोग, training और deployment करने के लिए सबसे लोकप्रिय open-source libraries में से एक है। यह एक व्यापक ecosystem प्रदान करता है, जिसमें pre-trained models, datasets और fine-tuning तथा deployment के लिए Hugging Face Hub के साथ seamless integration शामिल है।

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain, LLMs के साथ applications बनाने के लिए डिज़ाइन किया गया framework है। यह developers को language models को external data sources, APIs और databases से connect करने की सुविधा देता है। LangChain advanced prompt engineering, conversation history को manage करने और LLMs को complex workflows में integrate करने के लिए tools प्रदान करता है।

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, Lightning AI द्वारा विकसित एक project है, जो GPT-based models की training, fine-tuning और deployment को आसान बनाने के लिए Lightning framework का उपयोग करता है। यह अन्य Lightning AI tools के साथ seamlessly integrate होता है और बेहतर performance तथा scalability के साथ large-scale language models को handle करने के लिए optimized workflows प्रदान करता है।

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServe, Lightning AI का एक deployment tool है, जिसे AI models को तेज़ी और कुशलता से deploy करने के लिए डिज़ाइन किया गया है। यह scalable और optimized serving capabilities प्रदान करके real-time applications में LLMs के integration को सरल बनाता है।

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, LLMs सहित AI models के deployment, scaling और management को सरल बनाने के लिए डिज़ाइन किया गया एक cloud-based platform है। इसमें automated scaling, monitoring और विभिन्न cloud services के साथ integration जैसी features शामिल हैं, जिससे extensive infrastructure management के बिना production environments में models को deploy करना आसान हो जाता है।

## Models को online आज़माना

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, machine learning के लिए एक leading platform और community है, जो विशेष रूप से natural language processing (NLP) में अपने कार्य के लिए प्रसिद्ध है। यह tools, libraries और resources प्रदान करता है, जो machine learning models को develop, share और deploy करना आसान बनाते हैं।\
इसमें कई sections हैं, जैसे:

* **Models**: **pre-trained machine learning models** का एक विशाल repository, जहाँ users विभिन्न tasks जैसे text generation, translation, image recognition और अन्य कार्यों के लिए models को browse, download और integrate कर सकते हैं।
* **Datasets:** training और models के evaluation के लिए उपयोग किए जाने वाले **datasets का एक व्यापक collection**। यह विविध data sources तक आसान access प्रदान करता है, जिससे users अपने specific machine learning projects के लिए data खोज और उपयोग कर सकते हैं।
* **Spaces:** **interactive machine learning applications** और demos को host तथा share करने का एक platform। यह developers को अपने models को action में **showcase** करने, user-friendly interfaces बनाने और live demos share करके दूसरों के साथ collaborate करने की सुविधा देता है।

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**, Google द्वारा विकसित reusable machine learning modules का एक व्यापक repository है। इसका focus machine learning models, विशेष रूप से TensorFlow के साथ बनाए गए models, को share और deploy करने की सुविधा प्रदान करना है।

* **Modules:** pre-trained models और model components का एक विशाल collection, जहाँ users image classification, text embedding और अन्य tasks के लिए modules को browse, download और integrate कर सकते हैं।
* **Tutorials:** step-by-step guides और examples, जो users को TensorFlow Hub का उपयोग करके models को implement और fine-tune करने का तरीका समझने में सहायता करते हैं।
* **Documentation:** comprehensive guides और API references, जो developers को repository के resources का प्रभावी ढंग से उपयोग करने में सहायता करते हैं।

## [**Replicate**](https://replicate.com/home)

**Replicate**, एक ऐसा platform है जो developers को simple API के माध्यम से cloud में machine learning models चलाने की सुविधा देता है। इसका focus extensive infrastructure setup की आवश्यकता के बिना ML models को आसानी से accessible और deployable बनाना है।

* **Models:** community द्वारा contribute किए गए machine learning models का एक repository, जहाँ users models को browse और try कर सकते हैं तथा minimal effort के साथ उन्हें अपनी applications में integrate कर सकते हैं।
* **API Access:** models चलाने के लिए simple APIs, जो developers को अपनी applications के भीतर models को आसानी से deploy और scale करने की सुविधा देते हैं।

{{#include ../banners/hacktricks-training.md}}
