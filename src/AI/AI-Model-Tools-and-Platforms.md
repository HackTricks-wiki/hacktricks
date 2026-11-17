# Zana na Majukwaa ya Modeli za AI

{{#include ../banners/hacktricks-training.md}}

## Endesha na fundisha modeli kwenye mashine ya ndani

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ni maktaba ya chanzo huria ya kupakia, kufundisha na kutoa huduma kwa modeli zilizofundishwa awali katika kazi za maandishi, kuona, sauti, video na multimodal. Uhosting wa modeli na dataset hutolewa kando kupitia Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ni framework ya kuunda programu na agents zinazoendeshwa na modeli, yenye uwezo wa kuunda prompt, kudhibiti historia ya mazungumzo/hali, kutumia tools, retrieval, na kuunganisha modeli, API na database.<sup>[[2]](#references)</sup>

#### Jaribu ufufuaji wa object zilizoserialishwa za LangChain

Programu inapokubali ingizo la mtumiaji au matokeo ya modeli **yenye muundo**, fuatilia ikiwa dictionary zilizopachikwa zinabaki ndani ya `metadata`, `additional_kwargs`, `response_metadata`, historia ya mazungumzo iliyohifadhiwa, au mtiririko wa run. LangChain hutumia dictionary zenye tag ya `lc` kama object zilizoserialishwa. Katika mizunguko ya `dumps()`/`dumpd()` → `load()`/`loads()` iliyoathiriwa, dictionary inayodhibitiwa na mshambuliaji inaweza kufufuliwa kama object ya framework badala ya kubaki data. Kupakia manifest isiyoaminika moja kwa moja pia ni hatari; ingizo la string ya kawaida ambalo halichanganuliwi kamwe kama dictionary halitimizi sharti hili la awali.<sup>[[10]](#references)[[11]](#references)</sup>

Kwa jaribio lililoidhinishwa, wasilisha canary isiyo na madhara **kama object ya JSON iliyopachikwa**, si kama string, kisha angalia ikiwa historia au mtiririko wa chini unajumuisha object ya `AIMessage` badala ya dictionary ya awali:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Angalia `RunnableWithMessageHistory`, `astream_log()`, na `astream_events(version="v1")` zinapotumika kweli. Ufufuaji wa object uliofaulu unaweza kuchafua historia ya chat baadaye; allowlist pana zaidi zinaweza kuunda instances za class nyingine zinazoaminika ambazo constructors zake zina side effects. Usichukulie hili kuwa sawa na utekelezaji wa pickle usio na vizuizi. Kasoro ya awali ya escape ilirekebishwa katika `langchain-core` 0.3.81/1.2.5, na marekebisho ya baadaye ya allowlist pana na secret-marker yalijumuishwa katika 0.3.85/1.3.3. Kwa manifests zisizoaminika, tumia toleo la sasa na uweke `allowed_objects` kwenye message classes pekee au orodha salama iliyoainishwa wazi, ukiweka `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Kwa [agent trust-boundary mapping](AI-Agent-Security-Methodology.md), litofautishe hili na [model-file loading RCE](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT hutoa implementations zinazosomeka na workflows za command-line za kufanya pretraining, fine-tuning, kutathmini na ku-deploy language models zinazotumika.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServe ni framework ya model-serving kutoka Lightning AI ya kutoa inference APIs zenye hooks za batching, streaming, acceleration na scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ni framework ya open-source ya post-training na fine-tuning inayotumia usanidi wa YAML. Inatumia mbinu kama full fine-tuning, LoRA/QLoRA, preference optimization na multi-GPU training; yenyewe si platform ya cloud deployment.<sup>[[5]](#references)</sup>

## Jaribu modeli mtandaoni

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ni platform na jumuiya inayoongoza katika machine learning, inayojulikana hasa kwa kazi yake katika natural language processing (NLP). Hutoa zana, libraries na rasilimali zinazorahisisha kuunda, kushiriki na ku-deploy modeli za machine learning.\
Hub ina sehemu kadhaa zinazohusika:<sup>[[6]](#references)</sup>

* **Models**: Mkusanyiko mkubwa wa **modeli za machine learning zilizofanyiwa pre-training** ambapo watumiaji wanaweza kuvinjari, kupakua na kuunganisha modeli kwa kazi mbalimbali kama text generation, translation, image recognition na nyinginezo.
* **Datasets:** **Mkusanyiko wa datasets** unaotumika kufundishia na kutathmini modeli. Hurahisisha upatikanaji wa vyanzo mbalimbali vya data, na kuwawezesha watumiaji kupata na kutumia data kwa miradi yao mahususi ya machine learning.
* **Spaces:** Platform ya kuhifadhi na kushiriki **applications za machine learning zinazotumika kwa mwingiliano** na demos. Huwawezesha developers **kuonyesha** modeli zao zikifanya kazi, kuunda interfaces zilizo rahisi kutumia na kushirikiana na wengine kwa kushiriki demos za moja kwa moja.

#### Kagua logs za runtime za Space za umma

Code ya repository ya Space ya umma inaweza kufichua inputs na environment variables ambazo app yake huandika kwenye log. Wakati wa tathmini iliyoidhinishwa, kagua mkondo wa log wa **run** kama sehemu tofauti na app UI. Hugging Face huandika nyaraka za endpoint ya SSE ya logs za Space; utafiti ulibaini kuwa logs za Space za umma zingeweza kusomwa na watumiaji wengine wa Hub, na wakati mwingine zilikuwa na API keys, prompts za watumiaji au access token ya Dev Mode iliyoandikwa kwenye URL ya request. Tokeni iliyo kwenye log ina umuhimu tu ikiwa mode yenye ruhusa husika bado imewashwa na tokeni hiyo bado ni halali.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Tumia token ya akaunti yako ya Hub iliyoidhinishwa; **huu si** ombi la siri ya mmiliki wa Space. Jibu ni mtiririko wa SSE (mistari ya `data:`). Linganisha thamani zilizofichuka na msimbo wa Space na runtime ya sasa badala ya kudhani kwamba jina la kigezo linathibitisha kuwa thamani yake imevuja. Kwa [endpoint ya Gradio au model-runner inayojipangia mwenyewe](AI-Exposed-Self-Hosted-AI-Services.md), fuata ukurasa huo badala yake.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ni hazina na maktaba ya vipengele vya modeli vilivyofunzwa na vinavyoweza kutumiwa tena, hasa moduli zinazotumiwa kupitia TensorFlow/Keras. **Kaggle** hutoa madaftari, seti za data, mashindano na modeli kando.<sup>[[7]](#references)[[9]](#references)</sup>

* **Moduli:** Mkusanyiko mkubwa wa modeli na vipengele vya modeli vilivyofunzwa awali, ambapo watumiaji wanaweza kuvinjari, kupakua na kujumuisha moduli kwa kazi kama vile uainishaji wa picha, uwekaji wa maandishi katika embedding na mengineyo.
* **Mafunzo:** Miongozo na mifano ya hatua kwa hatua inayowasaidia watumiaji kutekeleza na kurekebisha modeli kwa kutumia TensorFlow Hub.
* **Nyaraka:** Miongozo ya kina na marejeleo ya API yanayowasaidia wasanidi programu kutumia rasilimali za hazina kwa ufanisi.

## [**Replicate**](https://replicate.com/home)

**Replicate** ni jukwaa la kupangisha modeli za machine learning zilizofungashwa ili ziendeshwe kupitia kiolesura cha wavuti au API.<sup>[[8]](#references)</sup>

* **Modeli:** Hazina ya modeli za machine learning zilizochangiwa na jumuiya, ambazo watumiaji wanaweza kuvinjari, kujaribu na kujumuisha kwenye programu zao kwa juhudi ndogo.
* **Ufikiaji wa API:** API za kuita modeli kutoka kwenye programu bila kuendesha miundombinu ya inference iliyo chini yake.

## Kushambulia huduma za AI zinazojipangia zenyewe zilizo wazi

Kwa black-box fingerprinting na majaribio ya model runner zinazojipangia zenyewe, wajenzi wa mawakala, UI za maonyesho ya ML, klasta za kompyuta na hifadhidata za vekta, angalia [Huduma za AI Zinazojipangia Zenyewe Zilizo Wazi](AI-Exposed-Self-Hosted-AI-Services.md).



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
- [10] [Ushauri wa usalama kuhusu serialization injection ya LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Ushauri wa usalama kuhusu urejeshaji usio salama wa object wa LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API ya load ya LangChain na modeli ya vitisho](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API ya kumbukumbu za Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Space Yako ni Eneo Langu: Hatari za usalama za programu za AI kwenye model hubs](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
