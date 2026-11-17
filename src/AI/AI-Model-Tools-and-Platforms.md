# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## मॉडल स्थानीय रूप से चलाएँ और ट्रेन करें

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers, text, vision, audio, video और multimodal tasks के लिए pretrained models लोड करने, ट्रेन करने और serve करने वाली open-source library है। Model और dataset hosting की सुविधा Hugging Face Hub अलग से देता है।<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain, prompt निर्माण, conversation history/state management, tools, retrieval, model, API और database integrations के साथ model-driven applications और agents बनाने का framework है।<sup>[[2]](#references)</sup>

#### LangChain serialized-object revival की जाँच करें

जब कोई application **structured** user input या model output स्वीकार करता है, तो देखें कि nested dictionaries `metadata`, `additional_kwargs`, `response_metadata`, saved chat history या run stream में बनी रहती हैं या नहीं। LangChain, serialized objects के लिए `lc`-tagged dictionaries का उपयोग करता है। प्रभावित `dumps()`/`dumpd()` → `load()`/`loads()` round trips में, attacker के नियंत्रण वाली dictionary को data बने रहने के बजाय framework object के रूप में revive किया जा सकता है। किसी untrusted manifest को सीधे load करना भी खतरनाक है; plain string input, जिसे कभी dictionary के रूप में parse नहीं किया जाता, इस पूर्वशर्त को पूरा नहीं करता।<sup>[[10]](#references)[[11]](#references)</sup>

अधिकृत test के लिए, constructor-जैसा harmless canary **nested JSON object के रूप में** भेजें, string के रूप में नहीं। फिर जाँचें कि downstream history या stream में original dictionary के बजाय `AIMessage` object मौजूद है या नहीं:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

जब इनका वास्तव में उपयोग किया जा रहा हो, तब `RunnableWithMessageHistory`, `astream_log()` और `astream_events(version="v1")` की जाँच करें। किसी object का सफल revival बाद के chat history को दूषित कर सकता है; व्यापक allowlists अन्य trusted classes को instantiate कर सकती हैं, जिनके constructors के side effects होते हैं। इसे unrestricted pickle execution के बराबर न मानें। मूल escaping flaw को `langchain-core` 0.3.81/1.2.5 में ठीक किया गया था, और बाद में व्यापक allowlist तथा secret-marker का fix 0.3.85/1.3.3 में जारी किया गया। Untrusted manifests के लिए, current release का उपयोग करें और `allowed_objects` को message classes या किसी स्पष्ट safe list तक सीमित रखें, साथ ही `secrets_from_env=False` सेट करें।<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> [agent trust-boundary mapping](AI-Agent-Security-Methodology.md) के लिए, इसे [model-file loading RCE](AI-Models-RCE.md) से अलग रखें।

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT, समर्थित language models को pretrain करने, fine-tune करने, evaluate करने और deploy करने के लिए आसानी से पढ़े जा सकने वाले implementations और command-line workflows प्रदान करता है।<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**विवरण:**\
LitServe, Lightning AI का model-serving framework है, जो batching, streaming, acceleration और scaling hooks के साथ inference APIs उपलब्ध कराता है।<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl, YAML configuration पर आधारित एक open-source post-training और fine-tuning framework है। यह full fine-tuning, LoRA/QLoRA, preference optimization और multi-GPU training जैसी तकनीकों का समर्थन करता है; यह स्वयं cloud deployment platform नहीं है।<sup>[[5]](#references)</sup>

## ऑनलाइन models आज़माएँ

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**, machine learning के लिए एक अग्रणी platform और community है, जो विशेष रूप से natural language processing (NLP) में अपने काम के लिए जाना जाता है। यह ऐसे tools, libraries और resources प्रदान करता है जिनसे machine learning models को develop, share और deploy करना आसान होता है।\
Hub में कई उपयोगी sections हैं:<sup>[[6]](#references)</sup>

* **Models**: **pre-trained machine learning models** का विशाल repository, जहाँ उपयोगकर्ता text generation, translation, image recognition और अन्य कार्यों के लिए models को browse, download और integrate कर सकते हैं।
* **Datasets:** Models को train और evaluate करने के लिए उपयोग किए जाने वाले **datasets का व्यापक संग्रह**। यह विभिन्न data sources तक आसान पहुँच प्रदान करता है, ताकि उपयोगकर्ता अपने विशिष्ट machine learning projects के लिए data खोज और उपयोग कर सकें।
* **Spaces:** **interactive machine learning applications** और demos को host और share करने का platform। यह developers को अपने models को काम करते हुए **दिखाने**, user-friendly interfaces बनाने और live demos साझा करके दूसरों के साथ सहयोग करने की सुविधा देता है।

#### सार्वजनिक Space के runtime logs की जाँच करें

किसी सार्वजनिक Space के repository code से पता चल सकता है कि उसका app कौन-से inputs और environment variables log करता है। अधिकृत assessment के दौरान, app UI से अलग surface के रूप में उसके **run** log stream की जाँच करें। Hugging Face, Space logs के SSE endpoint का दस्तावेज़ देता है; शोध में पाया गया कि अन्य Hub users सार्वजनिक Space logs पढ़ सकते थे और उनमें कभी-कभी API keys, user prompts या request URL में log किया गया Dev Mode access token शामिल होता था। Log में मौजूद token तभी मायने रखता है, जब संबंधित privileged mode अब भी enabled हो और token अभी भी valid हो।<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

अपने अधिकृत Hub account के लिए token का उपयोग करें; यह Space के मालिक का secret मांगने का अनुरोध **नहीं** है। Response एक SSE stream (`data:` lines) है। उजागर हुए values का Space code और मौजूदा runtime से मिलान करें; यह न मानें कि variable name से ही साबित हो जाता है कि उसकी value leak हुई है। [स्वयं होस्ट किए गए Gradio या model-runner endpoint](AI-Exposed-Self-Hosted-AI-Services.md) के लिए, इसके बजाय उस पेज का अनुसरण करें।<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** पुनः उपयोग किए जा सकने वाले प्रशिक्षित model components के लिए एक repository और library है, विशेष रूप से ऐसे modules के लिए जिन्हें TensorFlow/Keras के माध्यम से उपयोग किया जाता है। **Kaggle** अलग से notebooks, datasets, competitions और models उपलब्ध कराता है।<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** पहले से प्रशिक्षित models और model components का विशाल संग्रह, जहाँ उपयोगकर्ता image classification, text embedding और अन्य कार्यों के लिए modules ब्राउज़, डाउनलोड और एकीकृत कर सकते हैं।
* **Tutorials:** चरण-दर-चरण guides और उदाहरण, जो उपयोगकर्ताओं को TensorFlow Hub का उपयोग करके models लागू करने और fine-tune करने में मदद करते हैं।
* **Documentation:** विस्तृत guides और API references, जो developers को repository के संसाधनों का प्रभावी उपयोग करने में सहायता करते हैं।

## [**Replicate**](https://replicate.com/home)

**Replicate** एक होस्ट किया गया platform है, जहाँ web interface या API के माध्यम से पैकेज किए गए machine-learning models चलाए जा सकते हैं।<sup>[[8]](#references)</sup>

* **Models:** समुदाय द्वारा योगदान किए गए machine learning models की एक repository, जहाँ उपयोगकर्ता models ब्राउज़ और आज़मा सकते हैं, और न्यूनतम प्रयास से उन्हें अपने applications में एकीकृत कर सकते हैं।
* **API access:** ऐसे APIs, जिनकी मदद से underlying inference infrastructure संचालित किए बिना applications से models चलाए जा सकते हैं।

## उजागर self-hosted AI services पर हमला करना

Self-hosted model runners, agent builders, ML demo UIs, compute clusters और vector databases की black-box fingerprinting और testing के लिए, [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md) देखें।



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
- [10] [LangChain serialization injection advisory](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [LangChain unsafe object revival advisory](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChain load API and threat model](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging Face Spaces logs API](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Your Space is My Zone: Security risks of AI apps on model hubs](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
