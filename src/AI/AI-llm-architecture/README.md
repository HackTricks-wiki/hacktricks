# LLM Training - Data Preparation

{{#include ../../banners/hacktricks-training.md}}

**ये मेरे नोट्स हैं इस अत्यंत अनुशंसित पुस्तक** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **से, साथ में कुछ अतिरिक्त जानकारी भी है।**<sup>[[1]](#references)</sup>

## Basic Information

आपको कुछ बुनियादी concepts के लिए सबसे पहले यह post पढ़नी चाहिए, जिन्हें आपको जानना चाहिए:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> इस phase का उद्देश्य **input को tokens में विभाजित करना और उन्हें token IDs से map करना** है।


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> इस phase का उद्देश्य चुनी गई context length वाली training sequences को उनके shifted prediction targets के साथ तैयार करना है।


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> इस तीसरे phase का उद्देश्य बहुत सरल है: **vocabulary में मौजूद पिछले प्रत्येक token को model को train करने के लिए इच्छित dimensions वाले एक vector से assign करना।** Vocabulary में मौजूद प्रत्येक word, X dimensions वाले space में एक point होगा।\
> ध्यान दें कि शुरुआत में space में प्रत्येक word की position केवल "randomly" initialize की जाती है और ये positions trainable parameters होती हैं (training के दौरान इनमें सुधार किया जाएगा)।
>
> इसके अतिरिक्त, token embedding के दौरान **एक अन्य embedding layer बनाई जाती है**, जो (इस मामले में) training sentence में **word की absolute position** को represent करती है। इस तरह, sentence में अलग-अलग positions पर मौजूद किसी word का representation अलग होता है।


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> इस चौथे phase का उद्देश्य बहुत सरल है: **कुछ attention mechanisms लागू करना**। इनमें बहुत-सी **repeated layers** होंगी, जो **LLM को train करने के लिए उपयोग किए जा रहे current sentence में vocabulary के किसी word और उसके neighbours के बीच के relation को capture करेंगी**।\
> इसके लिए बहुत-सी layers का उपयोग किया जाता है, इसलिए बहुत-से trainable parameters इस information को capture करेंगे।


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> इस पांचवें phase का उद्देश्य बहुत सरल है: **पूरे LLM की architecture develop करना**। हर चीज़ को एक साथ रखें, सभी layers लागू करें और text generate करने या text को IDs में बदलने तथा वापस text में transform करने के लिए सभी functions बनाएं।
>
> इस architecture का उपयोग training और training के बाद text predict करने, दोनों के लिए किया जाएगा।


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> इस छठे phase का उद्देश्य बहुत सरल है: **model को scratch से train करना**। इसके लिए पिछली LLM architecture का उपयोग किया जाएगा, जिसमें datasets पर loops चलाए जाएंगे और defined loss functions तथा optimizer का उपयोग करके model के सभी parameters को train किया जाएगा।


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> LoRA, pretrained model को fine-tune करने के लिए आवश्यक trainable parameters और optimizer state की संख्या को काफी कम करता है।


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> इस section का उद्देश्य यह दिखाना है कि पहले से pre-trained model को इस तरह fine-tune कैसे किया जाए कि नया text generate करने के बजाय LLM दिए गए text के प्रत्येक category में categorize किए जाने की **probabilities बताए** (जैसे कि कोई text spam है या नहीं)।


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> इस section का उद्देश्य यह दिखाना है कि पहले से pre-trained model को केवल text generate करने के बजाय **instructions follow करने के लिए fine-tune** कैसे किया जाए, उदाहरण के लिए, chat bot की तरह tasks का उत्तर देने के लिए।


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [एक Large Language Model बनाएं (शुरू से) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
