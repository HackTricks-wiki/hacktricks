# Ferramentas e plataformas de modelos de IA

{{#include ../banners/hacktricks-training.md}}

## Executar e treinar modelos localmente

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformers é uma biblioteca de código aberto para carregar, treinar e disponibilizar modelos pré-treinados para tarefas de texto, visão, áudio, vídeo e multimodais. A hospedagem de modelos e conjuntos de dados é fornecida separadamente pelo Hugging Face Hub.<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChain é uma framework para criar aplicações e agentes orientados por modelos, com recursos para construção de prompts, gerenciamento do histórico/estado das conversas, ferramentas, recuperação, integrações com modelos, APIs e bancos de dados.<sup>[[2]](#references)</sup>

#### Testar a reativação de objetos serializados do LangChain

Quando uma aplicação aceita entrada estruturada do usuário ou saída do modelo, verifique se dicionários aninhados são preservados em `metadata`, `additional_kwargs`, `response_metadata`, no histórico de chat salvo ou em um fluxo de execução. LangChain usa dicionários com a tag `lc` como objetos serializados. Em conversões de ida e volta afetadas por `dumps()`/`dumpd()` → `load()`/`loads()`, um dicionário controlado por um atacante poderia ser reativado como um objeto da framework, em vez de permanecer como dados. Carregar diretamente um manifesto não confiável também é perigoso; uma entrada de texto simples que nunca é analisada como dicionário não atende a esse pré-requisito.<sup>[[10]](#references)[[11]](#references)</sup>

Para um teste autorizado, envie um canário inofensivo no formato de um construtor **como um objeto JSON aninhado**, não como uma string, e verifique se o histórico ou fluxo subsequente contém um objeto `AIMessage` em vez do dicionário original:<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

Verifique `RunnableWithMessageHistory`, `astream_log()` e `astream_events(version="v1")` quando forem realmente usados. A recuperação bem-sucedida de um objeto pode envenenar o histórico de chat posteriormente; allowlists mais amplas podem instanciar outras classes confiáveis cujos construtores têm efeitos colaterais. Não equipare isso à execução irrestrita de pickle. A falha original de escape foi corrigida no `langchain-core` 0.3.81/1.2.5, e uma correção posterior para allowlists amplas e marcadores de segredo foi lançada nas versões 0.3.85/1.3.3. Para manifests não confiáveis, use uma versão atual e restrinja `allowed_objects` a classes de mensagens ou a uma lista segura explícita, com `secrets_from_env=False`.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> Para o [mapeamento de limites de confiança de agentes](AI-Agent-Security-Methodology.md), mantenha isso distinto de [RCE por carregamento de arquivos de modelos](AI-Models-RCE.md).

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

O LitGPT oferece implementações legíveis e fluxos de trabalho de linha de comando para pré-treinar, ajustar, avaliar e implantar modelos de linguagem compatíveis.<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Descrição:**\
O LitServe é um framework de disponibilização de modelos da Lightning AI para expor APIs de inferência com recursos de batching, streaming, aceleração e escalabilidade.<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

O Axolotl é um framework open source de pós-treinamento e ajuste fino baseado em configuração YAML. Ele oferece suporte a técnicas como ajuste fino completo, LoRA/QLoRA, otimização de preferências e treinamento em várias GPUs; não é, por si só, uma plataforma de implantação em nuvem.<sup>[[5]](#references)</sup>

## Experimente modelos online

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face** é uma plataforma e comunidade líder em machine learning, especialmente conhecida por seu trabalho em processamento de linguagem natural (NLP). Ela oferece ferramentas, bibliotecas e recursos que facilitam o desenvolvimento, o compartilhamento e a implantação de modelos de machine learning.\
O Hub oferece várias seções relevantes:<sup>[[6]](#references)</sup>

* **Models**: Um vasto repositório de **modelos de machine learning pré-treinados** em que os usuários podem explorar, baixar e integrar modelos para diversas tarefas, como geração de texto, tradução, reconhecimento de imagens e outras.
* **Datasets:** Uma abrangente **coleção de conjuntos de dados** usados para treinar e avaliar modelos. Ela facilita o acesso a diversas fontes de dados, permitindo que os usuários encontrem e utilizem dados em seus projetos específicos de machine learning.
* **Spaces:** Uma plataforma para hospedar e compartilhar **aplicações interativas de machine learning** e demos. Ela permite que os desenvolvedores **demonstrem** seus modelos em ação, criem interfaces fáceis de usar e colaborem com outras pessoas compartilhando demos ao vivo.

#### Inspecione os logs de execução de Spaces públicos

O código do repositório de um Space público pode revelar quais entradas e variáveis de ambiente o aplicativo registra. Em uma avaliação autorizada, inspecione o fluxo de logs de **run** como uma superfície separada da interface do aplicativo. A Hugging Face documenta o endpoint SSE dos logs de Spaces; pesquisas constataram que outros usuários do Hub podiam ler os logs de Spaces públicos e que, às vezes, eles continham chaves de API, prompts de usuários ou um token de acesso ao Dev Mode registrado em uma URL de solicitação. Um token em um log só é relevante se o modo privilegiado correspondente ainda estiver habilitado e o token ainda for válido.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

Use um token da sua conta autorizada do Hub; este **não** é um pedido pelo segredo do proprietário do Space. A resposta é um fluxo SSE (linhas `data:`). Correlacione os valores expostos com o código do Space e o runtime atual, em vez de presumir que o nome de uma variável prove que seu valor vazou. Para um [endpoint de Gradio ou model-runner auto-hospedado](AI-Exposed-Self-Hosted-AI-Services.md), siga as instruções daquela página.<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub** é um repositório e uma biblioteca de componentes de modelos treinados reutilizáveis, especialmente módulos usados pelo TensorFlow/Keras. **Kaggle** oferece separadamente notebooks, datasets, competições e modelos.<sup>[[7]](#references)[[9]](#references)</sup>

* **Módulos:** Uma vasta coleção de modelos pré-treinados e componentes de modelos que os usuários podem explorar, baixar e integrar para tarefas como classificação de imagens, embeddings de texto e muito mais.
* **Tutoriais:** Guias passo a passo e exemplos que ajudam os usuários a implementar e ajustar modelos usando TensorFlow Hub.
* **Documentação:** Guias abrangentes e referências de API que ajudam desenvolvedores a usar os recursos do repositório com eficiência.

## [**Replicate**](https://replicate.com/home)

**Replicate** é uma plataforma hospedada para executar modelos de machine learning empacotados por meio de uma interface web ou API.<sup>[[8]](#references)</sup>

* **Modelos:** Um repositório de modelos de machine learning contribuídos pela comunidade, que os usuários podem explorar, testar e integrar em seus aplicativos com o mínimo de esforço.
* **Acesso à API:** APIs para invocar modelos a partir de aplicativos sem operar a infraestrutura de inferência subjacente.

## Atacando serviços de AI auto-hospedados expostos

Para fingerprinting black-box e testes de model runners auto-hospedados, construtores de agentes, interfaces de demonstração de ML, clusters de computação e bancos de dados vetoriais, consulte [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).



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
- [10] [Aviso sobre injeção de serialização no LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [Aviso sobre recuperação insegura de objetos no LangChain](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [API load e modelo de ameaças do LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [API de logs do Hugging Face Spaces](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Your Space is My Zone: riscos de segurança de aplicativos de AI em hubs de modelos](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
