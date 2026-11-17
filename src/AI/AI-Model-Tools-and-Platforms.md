# AI-modelle en platforms

{{#include ../banners/hacktricks-training.md}}

## Modelle plaaslik uitvoer en oplei

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers is ’n oopbronbiblioteek om vooraf opgeleide modelle vir teks-, visie-, oudio-, video- en multimodale take te laai, op te lei en beskikbaar te stel. Model- en datastelhuisvesting word afsonderlik deur die Hugging Face Hub verskaf.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain is ’n raamwerk om modelgedrewe toepassings en agents te bou, met prompt-konstruksie, bestuur van gesprekgeskiedenis/-toestand, tools, herwinning, model-, API- en databasisintegrasies.<sup>[[2]](#references)</sup>

#### Toets die herstel van LangChain-geserialiseerde voorwerpe

Wanneer ’n toepassing **gestruktureerde** gebruikersinvoer of modeluitvoer aanvaar, spoor na of geneste woordeboeke behoue bly in `metadata`, `additional_kwargs`, `response_metadata`, gestoorde kletsgeskiedenis of ’n run-stroom. LangChain gebruik `lc`-gemerkte woordeboeke as geserialiseerde voorwerpe. In geraakte `dumps()`/`dumpd()` → `load()`/`loads()`-heen-en-weer-omskakelings kan ’n aanvallerbeheerde woordeboek as ’n raamwerkvoorwerp herstel word, eerder as om data te bly. Om ’n onbetroubare manifest direk te laai, is ook gevaarlik; ’n gewone stringinvoer wat nooit as ’n woordeboek ontleed word nie, voldoen nie aan hierdie voorvereiste nie.<sup>[[10]](#references)[[11]](#references)</sup>

Vir ’n gemagtigde toets, stuur ’n onskadelike konstruktorvormige canary **as ’n geneste JSON-objek**, nie as ’n string nie, en kyk of die daaropvolgende geskiedenis of stroom ’n `AIMessage`-objek bevat eerder as die oorspronklike woordeboek:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Kontroleer `RunnableWithMessageHistory`, `astream_log()` en `astream_events(version="v1")` wanneer hulle werklik gebruik word. ’n Suksesvolle objekherstel kan latere kletsgeskiedenis vergiftig; breër allowlists kan ander vertroude klasse instansieer waarvan die konstruktors newe-effekte het. Moenie dit gelykstel aan onbeperkte pickle-uitvoering nie. Die oorspronklike ontsnappingsfout is in `langchain-core` 0.3.81/1.2.5 reggestel, en ’n latere regstelling vir breë allowlists en geheimmerkers is in 0.3.85/1.3.3 ingesluit. Gebruik vir onvertroude manifests ’n huidige weergawe en beperk `allowed_objects` tot boodskapklasse of ’n uitdruklike veilige lys, met `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Vir [kartering van agent-vertrouensgrense](AI-Agent-Security-Methodology.md), hou dit onderskei van [RCE deur modelläailading](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT bied leesbare implementasies en opdragreëlwerkvloeie vir voorafopleiding, fyninstelling, evaluering en ontplooiing van ondersteunde taalmodelle.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Beskrywing:**\
LitServe is ’n modelbedieningsraamwerk van Lightning AI om afleidings-API’s beskikbaar te stel, met hooks vir batching, streaming, versnelling en skaalvergroting.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl is ’n oopbronraamwerk vir naverwerking en fyninstelling wat deur YAML-konfigurasie aangedryf word. Dit ondersteun tegnieke soos volledige fyninstelling, LoRA/QLoRA, voorkeuroptimering en multi-GPU-opleiding; dit is nie self ’n wolkontplooiingsplatform nie.<sup>[[5]](#references)</sup>

## Probeer modelle aanlyn

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** is ’n toonaangewende platform en gemeenskap vir masjienleer, veral bekend vir sy werk in natuurliketaalverwerking (NLP). Dit bied gereedskap, biblioteke en hulpbronne wat die ontwikkeling, deling en ontplooiing van masjienleermodelle vergemaklik.\
Die Hub bied verskeie toepaslike afdelings:<sup>[[6]](#references)</sup>

* **Models**: ’n Groot bewaarplek van **voorafopgeleide masjienleermodelle** waar gebruikers modelle vir verskeie take, soos teksgenerering, vertaling, beeldherkenning en meer, kan deursoek, aflaai en integreer.
* **Datasets:** ’n Omvattende **versameling datastelle** wat gebruik word om modelle op te lei en te evalueer. Dit vergemaklik toegang tot uiteenlopende databronne, sodat gebruikers data vir hul spesifieke masjienleerprojekte kan vind en gebruik.
* **Spaces:** ’n Platform vir die huisvesting en deling van **interaktiewe masjienleertoepassings** en demonstrasies. Dit stel ontwikkelaars in staat om hul modelle in werking te **demonstreer**, gebruikersvriendelike koppelvlakke te skep en met ander saam te werk deur lewendige demonstrasies te deel.

#### Inspekteer publieke Space-looptydlogboeke

Die bewaarplek se kode vir ’n publieke Space kan wys watter invoere en omgewingsveranderlikes die toepassing aanteken. Inspekteer tydens ’n gemagtigde assessering die **run**-logstroom as ’n afsonderlike oppervlak van die toepassing se UI. Hugging Face dokumenteer die Space-log-SSE-eindpunt; navorsing het bevind dat ander Hub-gebruikers publieke Space-logboeke kon lees en dat dit soms API-sleutels, gebruikersaanwysings of ’n Dev Mode-toegangstoken bevat het wat in ’n versoek-URL aangeteken is. ’n Token in ’n logboek is slegs van belang as die ooreenstemmende bevoorregte modus steeds geaktiveer is en die token nog geldig is.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Gebruik 'n token vir jou gemagtigde Hub-rekening; dit is **nie** 'n versoek om die Space-eienaar se geheim nie. Die antwoord is 'n SSE-stroom (`data:`-reëls). Korreleer blootgestelde waardes met die Space-kode en huidige runtime, eerder as om aan te neem dat 'n veranderlikenaam bewys dat die waarde daarvan uitgelek het. Volg eerder daardie bladsy vir 'n [self-hosted Gradio- of model-runner-eindpunt](AI-Exposed-Self-Hosted-AI-Services.md).<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** is 'n bewaarplek en biblioteek vir herbruikbare opgeleide modelkomponente, veral modules wat deur TensorFlow/Keras gebruik word. **Kaggle** bied afsonderlik notaboeke, datastelle, kompetisies en modelle.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** 'n Groot versameling voorafopgeleide modelle en modelkomponente waarin gebruikers modules kan deursoek, aflaai en integreer vir take soos beeldklassifikasie, teksinbedding en meer.
* **Tutoriaalhandleidings:** Stap-vir-stap-gidse en voorbeelde wat gebruikers help om modelle met TensorFlow Hub te implementeer en fyn in te stel.
* **Dokumentasie:** Omvattende gidse en API-verwysings wat ontwikkelaars help om die bewaarplek se hulpbronne doeltreffend te benut.

## [**Replicate**](https://replicate.com/home)

**Replicate** is 'n gehoste platform om verpakte masjienleermodelle deur 'n webkoppelvlak of API te laat loop.<sup>[[8]](#references)</sup>

* **Modelle:** 'n Bewaarplek van masjienleermodelle wat deur die gemeenskap bygedra word. Gebruikers kan modelle deursoek, uitprobeer en met minimale moeite in hul toepassings integreer.
* **API-toegang:** API's om modelle vanuit toepassings aan te roep sonder om die onderliggende inferensie-infrastruktuur te bedryf.

## Aanvalle op blootgestelde self-hosted AI-dienste

Vir black-box-vingerafdrukbepaling en toetsing van self-hosted model runners, agent-bouers, ML-demo-UI's, rekenaarklusters en vektordatabasisse, raadpleeg [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub-dokumentasie](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate-dokumentasie](https://replicate.com/docs)
- [9] [Kaggle-dokumentasie](https://www.kaggle.com/docs)
- [10] [LangChain-advies oor serialisasie-inspuiting](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [LangChain-advies oor onveilige objekherstel](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChain se load-API en bedreigingsmodel](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging Face Spaces se logs-API](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Your Space is My Zone: Sekuriteitsrisiko's van AI-toepassings op modelhubs](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
