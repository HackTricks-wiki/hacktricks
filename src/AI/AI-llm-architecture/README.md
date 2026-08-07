# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**ये मेरे बहुत recommended book** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **से लिए गए notes हैं, जिनमें कुछ अतिरिक्त जानकारी भी शामिल है।**<sup>[[1]](#references)</sup>

## Basic Information

आपको कुछ basic concepts के लिए सबसे पहले यह post पढ़ना चाहिए, जिन्हें आपको जानना आवश्यक है:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> इस initial phase का goal बहुत सरल है: **Input को किसी ऐसे तरीके से tokens (ids) में divide करना जो अर्थपूर्ण हो।**


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> इस second phase का goal बहुत सरल है: **Input data को sample करना और उसे training phase के लिए तैयार करना, आमतौर पर dataset को एक निश्चित length वाले sentences में अलग करके और expected response भी generate करके।**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> इस third phase का goal बहुत सरल है: **Vocabulary में मौजूद पिछले प्रत्येक token को model की training के लिए इच्छित dimensions वाला एक vector assign करना।** Vocabulary में मौजूद प्रत्येक word, X dimensions वाले space में एक point होगा।\
> ध्यान दें कि शुरुआत में space में प्रत्येक word की position केवल "randomly" initialize की जाती है और ये positions trainable parameters होती हैं (training के दौरान इनमें सुधार किया जाएगा)।
>
> इसके अलावा, token embedding के दौरान **embeddings की एक अन्य layer बनाई जाती है**, जो (इस case में) training sentence में **word की absolute position** को represent करती है। इस तरह sentence में अलग-अलग positions पर मौजूद word का representation (meaning) अलग होगा।


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> इस fourth phase का goal बहुत सरल है: **कुछ attention mechanisms apply करना।** ये बहुत-सी **repeated layers** होंगी, जो **वर्तमान sentence में मौजूद किसी word और उसके neighbours के बीच के relation को capture करेंगी, जिसका उपयोग LLM को train करने के लिए किया जा रहा है।**\
> इसके लिए बहुत-सी layers का उपयोग किया जाता है, इसलिए बहुत-से trainable parameters इस information को capture करेंगे।


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> इस fifth phase का goal बहुत सरल है: **Full LLM की architecture develop करना।** हर चीज़ को एक साथ रखना, सभी layers apply करना और text generate करने या text को IDs में और IDs को वापस text में transform करने के लिए सभी functions create करना।
>
> इस architecture का उपयोग training और model के train होने के बाद text predict करने, दोनों के लिए किया जाएगा।


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> इस sixth phase का goal बहुत सरल है: **Model को scratch से train करना।** इसके लिए previous LLM architecture का उपयोग किया जाएगा, जिसमें defined loss functions और optimizer का उपयोग करके model के सभी parameters को train करने के लिए data sets पर loops चलाए जाएंगे।


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> **LoRA का उपयोग पहले से trained models को fine-tune करने के लिए आवश्यक computation को काफी कम करता है।**


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> इस section का goal यह दिखाना है कि पहले से pre-trained model को fine-tune कैसे किया जाए, ताकि नया text generate करने के बजाय LLM दिए गए **text के प्रत्येक category में categorized होने की probabilities** select करे (जैसे कि कोई text spam है या नहीं)।


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> इस section का goal यह दिखाना है कि पहले से pre-trained model को केवल text generate करने के बजाय **instructions follow करने के लिए fine-tune** कैसे किया जाए, उदाहरण के लिए, chat bot की तरह tasks का response देना।


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
