# Testar LLMs

{{#include ../banners/hacktricks-training.md}}

## Executar e treinar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers é uma biblioteca open-source para carregar, treinar e disponibilizar modelos pré-treinados para tarefas de texto, visão, áudio, vídeo e multimodais. A hospedagem de modelos e datasets é fornecida separadamente pelo Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain é um framework para criar aplicações e agentes orientados por modelos, com recursos de construção de prompts, gerenciamento do histórico/estado de conversas, ferramentas, retrieval, integrações com modelos, APIs e bancos de dados.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT fornece implementações legíveis e workflows de linha de comando para pretraining, fine-tuning, avaliação e implantação de modelos de linguagem compatíveis.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrição:**\
LitServe é um framework de model serving da Lightning AI para expor APIs de inferência com recursos de batching, streaming, aceleração e hooks de scaling.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl é um framework open-source de post-training e fine-tuning orientado por configuração YAML. Ele oferece suporte a técnicas como fine-tuning completo, LoRA/QLoRA, otimização de preferências e treinamento com múltiplas GPUs; não é, por si só, uma plataforma de cloud deployment.<sup>[[5]](#references)</sup>

## Experimentar modelos online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** é uma plataforma e comunidade líder em machine learning, particularmente conhecida por seu trabalho em processamento de linguagem natural (NLP). Ela fornece ferramentas, bibliotecas e recursos que facilitam o desenvolvimento, compartilhamento e deployment de modelos de machine learning.\
O Hub oferece várias seções relevantes:<sup>[[6]](#references)</sup>

* **Models**: Um vasto repositório de **modelos de machine learning pré-treinados**, no qual os usuários podem pesquisar, baixar e integrar modelos para várias tarefas, como geração de texto, tradução, reconhecimento de imagens e outras.
* **Datasets:** Uma **coleção abrangente de datasets** usada para treinar e avaliar modelos. Ela facilita o acesso a diversas fontes de dados, permitindo que os usuários encontrem e utilizem dados para seus projetos específicos de machine learning.
* **Spaces:** Uma plataforma para hospedar e compartilhar **aplicações interativas de machine learning** e demos. Ela permite que os desenvolvedores **apresentem** seus modelos em funcionamento, criem interfaces fáceis de usar e colaborem com outras pessoas compartilhando demos ao vivo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** é um repositório e uma biblioteca de componentes reutilizáveis de modelos treinados, especialmente módulos consumidos pelo TensorFlow/Keras. **Kaggle** fornece separadamente notebooks, datasets, competições e modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** Uma vasta coleção de modelos pré-treinados e componentes de modelos, na qual os usuários podem pesquisar, baixar e integrar módulos para tarefas como classificação de imagens, embeddings de texto e outras.
* **Tutorials:** Guias passo a passo e exemplos que ajudam os usuários a implementar e fazer fine-tuning de modelos usando o TensorFlow Hub.
* **Documentation:** Guias abrangentes e referências de API que auxiliam os desenvolvedores a utilizar efetivamente os recursos do repositório.

## [**Replicate**](https://replicate.com/home)

**Replicate** é uma plataforma hospedada para executar modelos de machine learning empacotados por meio de uma interface web ou API.<sup>[[8]](#references)</sup>

* **Models:** Um repositório de modelos de machine learning contribuídos pela comunidade, no qual os usuários podem pesquisar, experimentar e integrar modelos em suas aplicações com o mínimo de esforço.
* **API access:** APIs para invocar modelos a partir de aplicações sem operar a infraestrutura de inferência subjacente.

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Documentação do Hugging Face Hub](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Documentação do Replicate](https://replicate.com/docs)
- [9] [Documentação do Kaggle](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
