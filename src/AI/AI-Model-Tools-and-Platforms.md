# Zana na Majukwaa ya Modeli za AI

{{#include ../banners/hacktricks-training.md}}

## Kuendesha na kufunza modeli ndani ya kifaa chako

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ni maktaba huria ya kupakia, kufunza na kutoa huduma kwa modeli zilizofunzwa awali katika kazi za maandishi, picha, sauti, video na za aina nyingi. Uwekaji wa modeli na seti za data hufanywa kando kupitia Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ni mfumo wa kujenga programu na mawakala wanaoendeshwa na modeli, wenye uwezo wa kuunda prompt, kusimamia historia/hali ya mazungumzo, kutumia zana, kufanya retrieval, na kuunganisha modeli, API na hifadhidata.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT hutoa utekelezaji unaosomeka na workflows za mstari wa amri za kufanya pretraining, fine-tuning, kutathmini na kupeleka modeli za lugha zinazotumika.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Maelezo:**\
LitServe ni mfumo wa Lightning AI wa kutoa huduma kwa modeli, unaowezesha kufichua API za inference zenye batching, streaming, uharakishaji na hooks za kuongeza uwezo.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ni mfumo huria wa post-training na fine-tuning unaotegemea usanidi wa YAML. Unaunga mkono mbinu kama vile fine-tuning kamili, LoRA/QLoRA, uboreshaji wa mapendeleo na mafunzo ya GPU nyingi; si jukwaa la kupeleka modeli kwenye cloud.<sup>[[5]](#references)</sup>

## Kujaribu modeli mtandaoni

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ni jukwaa na jumuiya maarufu ya machine learning, inayojulikana hasa kwa kazi yake katika uchakataji wa lugha asilia (NLP). Hutoa zana, maktaba na rasilimali zinazorahisisha kuunda, kushiriki na kupeleka modeli za machine learning.\
Hub ina sehemu kadhaa muhimu:<sup>[[6]](#references)</sup>

* **Modeli:** Hazina kubwa ya **modeli za machine learning zilizofunzwa awali** ambapo watumiaji wanaweza kuvinjari, kupakua na kuunganisha modeli kwa kazi mbalimbali kama vile kuzalisha maandishi, kutafsiri, kutambua picha na zaidi.
* **Seti za data:** **Mkusanyiko kamili wa seti za data** zinazotumika kufunza na kutathmini modeli. Huwezesha ufikiaji rahisi wa vyanzo mbalimbali vya data, na kuwawezesha watumiaji kupata na kutumia data kwa miradi yao mahususi ya machine learning.
* **Spaces:** Jukwaa la kupangisha na kushiriki **programu shirikishi za machine learning** na demo. Huwezesha wasanidi programu **kuonyesha** modeli zao zikifanya kazi, kuunda violesura vinavyofaa watumiaji na kushirikiana na wengine kwa kushiriki demo zinazotumika moja kwa moja.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **na** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ni hazina na maktaba ya vipengele vya modeli zilizofunzwa vinavyoweza kutumiwa tena, hasa moduli zinazotumiwa kupitia TensorFlow/Keras. **Kaggle** hutoa notebooks, seti za data, mashindano na modeli kando.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduli:** Mkusanyiko mkubwa wa modeli zilizofunzwa awali na vipengele vya modeli ambapo watumiaji wanaweza kuvinjari, kupakua na kuunganisha moduli kwa kazi kama vile uainishaji wa picha, uwekaji wa maandishi katika embeddings na zaidi.
* **Mafunzo elekezi:** Miongozo na mifano ya hatua kwa hatua inayowasaidia watumiaji kutekeleza na kufanya fine-tuning ya modeli kwa kutumia TensorFlow Hub.
* **Nyaraka:** Miongozo ya kina na marejeo ya API yanayowasaidia wasanidi programu kutumia rasilimali za hazina hiyo kwa ufanisi.

## [**Replicate**](https://replicate.com/home)

**Replicate** ni jukwaa linalopangisha modeli za machine learning zilizofungashwa ili ziendeshwe kupitia kiolesura cha wavuti au API.<sup>[[8]](#references)</sup>

* **Modeli:** Hazina ya modeli za machine learning zilizochangiwa na jumuiya, ambapo watumiaji wanaweza kuvinjari na kujaribu modeli hizo, na kuziunganisha katika programu zao kwa juhudi ndogo.
* **Ufikiaji wa API:** API za kuita modeli kutoka kwenye programu bila kuendesha miundombinu ya inference inayozitegemeza.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Nyaraka za Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Nyaraka za Replicate](https://replicate.com/docs)
- [9] [Nyaraka za Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
