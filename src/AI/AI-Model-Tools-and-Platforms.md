# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## Run & train models locally

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers is an open-source library for loading, training, and serving pretrained models across text, vision, audio, video, and multimodal tasks. Model and dataset hosting are provided separately by the Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain is a framework for building model-driven applications and agents with prompt construction, conversation-history/state management, tools, retrieval, model, API, and database integrations.<sup>[[2]](#references)</sup>

#### Test LangChain serialized-object revival

When an application accepts **structured** user input or model output, trace whether nested dictionaries survive in `metadata`, `additional_kwargs`, `response_metadata`, saved chat history, or a run stream. LangChain uses `lc`-tagged dictionaries as serialized objects. In affected `dumps()`/`dumpd()` → `load()`/`loads()` round trips, an attacker-controlled dictionary could be revived as a framework object instead of remaining data. Directly loading an untrusted manifest is also dangerous; a plain string input that is never parsed as a dictionary does not meet this prerequisite.<sup>[[10]](#references)[[11]](#references)</sup>

For an authorized test, submit a harmless constructor-shaped canary **as a nested JSON object**, not as a string, and check whether the downstream history or stream contains an `AIMessage` object rather than the original dictionary:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Check `RunnableWithMessageHistory`, `astream_log()`, and `astream_events(version="v1")` when they are actually used. A successful object revival can poison later chat history; broader allowlists can instantiate other trusted classes whose constructors have side effects. Do not equate this with unrestricted pickle execution. The original escaping flaw was fixed in `langchain-core` 0.3.81/1.2.5, and a later broad-allowlist and secret-marker fix landed in 0.3.85/1.3.3. For untrusted manifests, use a current release and restrict `allowed_objects` to message classes or an explicit safe list, with `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> For [agent trust-boundary mapping](AI-Agent-Security-Methodology.md), keep this distinct from [model-file loading RCE](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT provides readable implementations and command-line workflows for pretraining, fine-tuning, evaluating, and deploying supported language models.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServe is a model-serving framework from Lightning AI for exposing inference APIs with batching, streaming, acceleration, and scaling hooks.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl is an open-source post-training and fine-tuning framework driven by YAML configuration. It supports techniques such as full fine-tuning, LoRA/QLoRA, preference optimization, and multi-GPU training; it is not itself a cloud deployment platform.<sup>[[5]](#references)</sup>

## Try models online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** is a leading platform and community for machine learning, particularly known for its work in natural language processing (NLP). It provides tools, libraries, and resources that make it easier to develop, share, and deploy machine learning models.\
The Hub offers several relevant sections:<sup>[[6]](#references)</sup>

* **Models**: A vast repository of **pre-trained machine learning models** where users can browse, download, and integrate models for various tasks like text generation, translation, image recognition, and more.
* **Datasets:** A comprehensive **collection of datasets** used for training and evaluating models. It facilitates easy access to diverse data sources, enabling users to find and utilize data for their specific machine learning projects.
* **Spaces:** A platform for hosting and sharing **interactive machine learning applications** and demos. It allows developers to **showcase** their models in action, create user-friendly interfaces, and collaborate with others by sharing live demos.

#### Inspect public Space runtime logs

A public Space's repository code may reveal which inputs and environment variables its app logs. On an authorized assessment, inspect its **run** log stream as a separate surface from the app UI. Hugging Face documents the Space log SSE endpoint; research found that public Space logs could be read by other Hub users and sometimes contained API keys, user prompts, or a Dev Mode access token logged in a request URL. A token in a log matters only if the corresponding privileged mode remains enabled and the token is still valid.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Use a token for your authorized Hub account; this is **not** a request for the Space owner's secret. The response is an SSE stream (`data:` lines). Correlate exposed values with the Space code and current runtime rather than assuming that a variable name proves its value leaked. For a [self-hosted Gradio or model-runner endpoint](AI-Exposed-Self-Hosted-AI-Services.md), follow that page instead.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** is a repository and library for reusable trained model components, especially modules consumed through TensorFlow/Keras. **Kaggle** separately provides notebooks, datasets, competitions, and models.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** A vast collection of pre-trained models and model components where users can browse, download, and integrate modules for tasks such as image classification, text embedding, and more.
* **Tutorials:** Step-by-step guides and examples that help users implement and fine-tune models using TensorFlow Hub.
* **Documentation:** Comprehensive guides and API references that assist developers in effectively utilizing the repository’s resources.

## [**Replicate**](https://replicate.com/home)

**Replicate** is a hosted platform for running packaged machine-learning models through a web interface or API.<sup>[[8]](#references)</sup>

* **Models:** A repository of machine learning models contributed by the community which users can browse, try, and integrate models into their applications with minimal effort.
* **API access:** APIs for invoking models from applications without operating the underlying inference infrastructure.

## Attacking exposed self-hosted AI services

For black-box fingerprinting and testing of self-hosted model runners, agent builders, ML demo UIs, compute clusters and vector databases, check [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).



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
