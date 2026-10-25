# Ferramentas e plataformas de modelos de IA

{{#include ../banners/hacktricks-training.md}}

## Executar e treinar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers é uma biblioteca de código aberto para carregar, treinar e disponibilizar modelos pré-treinados para tarefas de texto, visão, áudio, vídeo e multimodais. A hospedagem de modelos e conjuntos de dados é fornecida separadamente pelo Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain é um framework para criar aplicações e agentes orientados por modelos, com construção de prompts, gerenciamento do histórico e estado das conversas, ferramentas, recuperação de informações e integrações com modelos, APIs e bancos de dados.<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPT oferece implementações fáceis de ler e fluxos de trabalho de linha de comando para pré-treinar, ajustar, avaliar e implantar os modelos de linguagem compatíveis.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrição:**\
LitServe é um framework de disponibilização de modelos da Lightning AI para expor APIs de inferência com recursos de batching, streaming, aceleração e escalabilidade.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotl é um framework de código aberto para pós-treinamento e ajuste fino, configurado por YAML. Ele oferece suporte a técnicas como ajuste fino completo, LoRA/QLoRA, otimização de preferências e treinamento com várias GPUs; não é, por si só, uma plataforma de implantação na nuvem.<sup>[[5]](#references)</sup>

## Experimentar modelos online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** é uma plataforma e comunidade líder em machine learning, conhecida sobretudo por seu trabalho em processamento de linguagem natural (NLP). Ela oferece ferramentas, bibliotecas e recursos que facilitam o desenvolvimento, o compartilhamento e a implantação de modelos de machine learning.\
O Hub oferece várias seções relevantes:<sup>[[6]](#references)</sup>

* **Modelos**: Um vasto repositório de **modelos de machine learning pré-treinados** que os usuários podem explorar, baixar e integrar para diversas tarefas, como geração de texto, tradução, reconhecimento de imagens e muito mais.
* **Conjuntos de dados:** Uma abrangente **coleção de conjuntos de dados** usados para treinar e avaliar modelos. Ela facilita o acesso a diversas fontes de dados, permitindo que os usuários encontrem e utilizem dados para seus projetos específicos de machine learning.
* **Spaces:** Uma plataforma para hospedar e compartilhar **aplicações interativas de machine learning** e demonstrações. Ela permite que os desenvolvedores **apresentem** seus modelos em funcionamento, criem interfaces fáceis de usar e colaborem com outras pessoas compartilhando demonstrações ao vivo.

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **e** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** é um repositório e uma biblioteca de componentes reutilizáveis de modelos treinados, especialmente módulos usados pelo TensorFlow/Keras. **Kaggle**, por sua vez, oferece notebooks, conjuntos de dados, competições e modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Módulos:** Uma vasta coleção de modelos pré-treinados e componentes de modelos que os usuários podem explorar, baixar e integrar para tarefas como classificação de imagens, incorporação de texto e muito mais.
* **Tutoriais:** Guias e exemplos passo a passo que ajudam os usuários a implementar e ajustar modelos usando o TensorFlow Hub.
* **Documentação:** Guias abrangentes e referências de API que ajudam os desenvolvedores a utilizar os recursos do repositório com eficácia.

## [**Replicate**](https://replicate.com/home)

**Replicate** é uma plataforma hospedada para executar modelos de machine learning empacotados por meio de uma interface web ou API.<sup>[[8]](#references)</sup>

* **Modelos:** Um repositório de modelos de machine learning contribuídos pela comunidade, que os usuários podem explorar, testar e integrar em suas aplicações com o mínimo de esforço.
* **Acesso à API:** APIs para invocar modelos a partir de aplicações sem operar a infraestrutura de inferência subjacente.

## Atacando serviços de IA expostos e auto-hospedados

Para fingerprinting black-box e testes de executores de modelos auto-hospedados, criadores de agentes, interfaces de demonstração de ML, clusters de computação e bancos de dados vetoriais, consulte [Serviços de IA expostos e auto-hospedados](AI-Exposed-Self-Hosted-AI-Services.md).

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
