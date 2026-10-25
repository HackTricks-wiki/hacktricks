# Zana na Majukwaa ya Modeli za AI

{{#include ../banners/hacktricks-training.md}}

## Kuendesha na kufundisha modeli ndani ya kifaa chako

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ni maktaba ya chanzo-wazi ya kupakia, kufundisha na kutoa modeli zilizofundishwa awali kwa kazi za maandishi, picha, sauti, video na kazi za multimodal. Ukaribishaji wa modeli na dataset hutolewa kando kupitia Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ni mfumo wa kujenga programu na mawakala wanaoendeshwa na modeli, wenye vipengele vya kuunda prompt, kudhibiti historia ya mazungumzo/hali, zana, retrieval, na miunganisho ya modeli, API na hifadhidata.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT hutoa utekelezaji unaosomeka na mtiririko wa kazi wa mstari wa amri kwa ajili ya kufundisha modeli zinazotumika kuanzia mwanzo, kuzifanyia fine-tuning, kuzitathmini na kuzisambaza.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Maelezo:**\
LitServe ni mfumo wa Lightning AI wa kutoa huduma za modeli kupitia inference APIs, ukiwa na uwezo wa batching, streaming, acceleration na scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ni mfumo wa chanzo-wazi wa post-training na fine-tuning unaoendeshwa kwa usanidi wa YAML. Unaunga mkono mbinu kama full fine-tuning, LoRA/QLoRA, preference optimization na training ya multi-GPU; wenyewe si jukwaa la kusambaza huduma kwenye cloud.<sup>[[5]](#references)</sup>

## Kujaribu modeli mtandaoni

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ni jukwaa na jumuiya inayoongoza katika machine learning, inayojulikana hasa kwa kazi yake katika usindikaji wa lugha asilia (NLP). Hutoa zana, maktaba na rasilimali zinazorahisisha kuunda, kushiriki na kusambaza modeli za machine learning.\
Hub ina sehemu kadhaa muhimu:<sup>[[6]](#references)</sup>

* **Models**: Hifadhi kubwa ya **modeli za machine learning zilizofundishwa awali** ambamo watumiaji wanaweza kuvinjari, kupakua na kuunganisha modeli kwa kazi mbalimbali kama vile utengenezaji wa maandishi, tafsiri, utambuzi wa picha na nyinginezo.
* **Datasets:** **Mkusanyiko wa dataset** unaotumika kufundisha na kutathmini modeli. Huwezesha ufikiaji rahisi wa vyanzo mbalimbali vya data, na kuwawezesha watumiaji kupata na kutumia data kwa miradi yao mahususi ya machine learning.
* **Spaces:** Jukwaa la kukaribisha na kushiriki **programu shirikishi za machine learning** na demo. Huwaruhusu watengenezaji **kuonyesha** modeli zao zikifanya kazi, kuunda violesura vinavyofaa kwa watumiaji na kushirikiana na wengine kwa kushiriki demo za moja kwa moja.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ni hifadhi na maktaba ya vipengele vya modeli vilivyofundishwa ambavyo vinaweza kutumika tena, hasa moduli zinazotumiwa kupitia TensorFlow/Keras. **Kaggle** hutoa kivyake notebooks, dataset, mashindano na modeli.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Mkusanyiko mkubwa wa modeli zilizofundishwa awali na vipengele vya modeli ambamo watumiaji wanaweza kuvinjari, kupakua na kuunganisha moduli kwa kazi kama vile uainishaji wa picha, uwekaji wa maandishi katika embedding na nyinginezo.
* **Tutorials:** Miongozo na mifano ya hatua kwa hatua inayowasaidia watumiaji kutekeleza na kufanya fine-tuning ya modeli kwa kutumia TensorFlow Hub.
* **Documentation:** Miongozo ya kina na marejeleo ya API yanayowasaidia watengenezaji kutumia rasilimali za hifadhi hii kwa ufanisi.

## [**Replicate**](https://replicate.com/home)

**Replicate** ni jukwaa linalokaribisha modeli za machine learning zilizofungashwa ili ziendeshwe kupitia kiolesura cha wavuti au API.<sup>[[8]](#references)</sup>

* **Models:** Hifadhi ya modeli za machine learning zilizochangiwa na jumuiya, ambamo watumiaji wanaweza kuvinjari na kujaribu modeli hizo, kisha kuziunganisha kwenye programu zao kwa juhudi ndogo.
* **API access:** APIs za kuita modeli kutoka kwenye programu bila kuendesha miundombinu ya inference yenyewe.

## Kushambulia huduma za AI zinazojiendesha zikiwa zimefichuliwa

Kwa fingerprinting na majaribio ya black-box ya mifumo ya kuendesha modeli inayojihostia, wajenzi wa mawakala, violesura vya demo za ML, makundi ya kompyuta na hifadhidata za vector, angalia [Huduma za AI Zinazojihostia Zilizofichuliwa](AI-Exposed-Self-Hosted-AI-Services.md).

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
