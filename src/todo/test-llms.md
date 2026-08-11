# Test LLMs

{{#include ../banners/hacktricks-training.md}}

## Endesha na train models locally

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers ni library ya open-source ya kupakia, ku-train, na ku-serve models zilizofunzwa awali katika kazi za text, vision, audio, video, na multimodal. Uhostishaji wa models na datasets hutolewa kando na Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain ni framework ya kuunda applications na agents zinazoendeshwa na models, ikiwa na ujenzi wa prompts, usimamizi wa conversation-history/state, tools, retrieval, model, API, na database integrations.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT hutoa implementations zinazosomika na workflows za command-line kwa ajili ya pretraining, fine-tuning, evaluation, na deployment ya language models zinazotumika.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Maelezo:**\
LitServe ni framework ya model-serving kutoka Lightning AI kwa ajili ya kufichua inference APIs ikiwa na batching, streaming, acceleration, na scaling hooks.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl ni framework ya open-source ya post-training na fine-tuning inayoendeshwa na YAML configuration. Inatumia techniques kama full fine-tuning, LoRA/QLoRA, preference optimization, na multi-GPU training; yenyewe si cloud deployment platform.<sup>[[5]](#references)</sup>

## Jaribu models online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** ni platform na community inayoongoza katika machine learning, inayojulikana hasa kwa kazi yake katika natural language processing (NLP). Inatoa tools, libraries, na resources zinazorahisisha kuendeleza, kushiriki, na ku-deploy machine learning models.\
Hub inatoa sehemu kadhaa muhimu:<sup>[[6]](#references)</sup>

* **Models**: Repository kubwa ya **machine learning models zilizofunzwa awali**, ambapo watumiaji wanaweza kuvinjari, kupakua, na kuunganisha models kwa kazi mbalimbali kama text generation, translation, image recognition, na nyingine.
* **Datasets:** **Mkusanyiko mpana wa datasets** unaotumika kwa training na evaluation ya models. Unawezesha ufikiaji rahisi wa vyanzo mbalimbali vya data, na kuwawezesha watumiaji kupata na kutumia data kwa machine learning projects zao mahususi.
* **Spaces:** Platform ya kuhost na kushiriki **interactive machine learning applications** na demos. Inawawezesha developers **kuonyesha** models zao zikifanya kazi, kuunda interfaces zinazotumiwa kwa urahisi, na kushirikiana na wengine kwa kushiriki live demos.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** ni repository na library ya reusable trained model components, hasa modules zinazotumiwa kupitia TensorFlow/Keras. **Kaggle** kwa upande wake hutoa notebooks, datasets, competitions, na models.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Mkusanyiko mkubwa wa pre-trained models na model components, ambapo watumiaji wanaweza kuvinjari, kupakua, na kuunganisha modules kwa kazi kama image classification, text embedding, na nyingine.
* **Tutorials:** Miongozo na mifano ya hatua kwa hatua inayowasaidia watumiaji kuimplement na kufanya fine-tune ya models kwa kutumia TensorFlow Hub.
* **Documentation:** Miongozo kamili na marejeo ya API yanayowasaidia developers kutumia resources za repository kwa ufanisi.

## [**Replicate**](https://replicate.com/home)

**Replicate** ni platform iliyohostiwa kwa kuendesha packaged machine-learning models kupitia web interface au API.<sup>[[8]](#references)</sup>

* **Models:** Repository ya machine learning models zilizochangiwa na community, ambapo watumiaji wanaweza kuvinjari, kujaribu, na kuunganisha models katika applications zao kwa juhudi ndogo.
* **API access:** APIs za kuita models kutoka kwenye applications bila kuendesha underlying inference infrastructure.

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
