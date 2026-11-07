# Limites de confiança do gateway LLM

{{#include ../banners/hacktricks-training.md}}

Um gateway LLM gerencia o roteamento de modelos e costuma armazenar credenciais de provedores; portanto, os chamadores comuns da API não devem herdar autoridade sobre a configuração nem sobre os provedores. A avaliação do gateway LiteLLM na versão 1.77.7 ilustra dois limites separados: autorização de sessões da UI para configuração administrativa e configuração de roteamento fornecida pelo chamador para inferência. Os problemas relatados foram corrigidos na versão 1.83.9.<sup>[[1]](#references)</sup>

## Classificação de rotas da UI não é autorização

Na versão avaliada do LiteLLM, as chaves de login da UI pertenciam à equipe `litellm-dashboard`. A autorização classificava uma chave como token da UI com base no identificador dessa equipe, independentemente da função do usuário. Em seguida, a verificação de rotas da UI aceitava qualquer rota cujo início correspondesse a um prefixo permitido. Como resultado, a entrada `/config` também correspondia ao handler administrativo `/config/update`. Esse handler exigia autenticação genérica, mas não exigia `PROXY_ADMIN` de forma independente, permitindo que uma sessão de UI com privilégios inferiores obtivesse acesso de gravação à configuração.<sup>[[1]](#references)</sup>

Isso difere de uma incompatibilidade de normalização de caminho entre proxy e backend: o código de autorização e o handler discordam sobre a autoridade da *mesma* rota.<sup>[[1]](#references)</sup> Ao revisar um gateway, compare a classificação do token, a correspondência exata da rota e do método e a verificação de função feita pelo próprio handler.<sup>[[1]](#references)</sup> Consulte [autorização de API web](../pentesting-web/web-api-pentesting.md), [bypasses de 401/403](../pentesting-web/403-and-401-bypasses.md) e [isenções por prefixo no proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) para limites relacionados, mas distintos.

## Gravações de configuração alcançam mais do que o armazenamento de configuração

A mesma atualização de configuração do LiteLLM aceitava valores de variáveis de ambiente e os aplicava ao processo em execução. Um consumidor tratava `UI_LOGO_PATH` como um caminho local para um `FileResponse`, sem validar se ele apontava para um logotipo; outro lia `UI_USERNAME` e `UI_PASSWORD` durante o login sem SSO e atribuía `PROXY_ADMIN` quando os valores correspondiam. Assim, uma permissão de gravação de configuração poderia levar tanto à divulgação de arquivos locais quanto à alteração de uma identidade administrativa, dependendo do consumidor downstream. O tipo de mídia da resposta não comprova que o arquivo servido seja uma imagem.<sup>[[1]](#references)</sup>

A configuração do endpoint pass-through era outro destino downstream. A inicialização aceitava destinos de adaptadores remotos S3/GCS, baixava módulos Python e os importava usando `importlib`'s `exec_module`. A importação executa o código de nível superior antes que uma instância do adaptador seja usada; restringir apenas a invocação do adaptador não eliminaria esse limite de execução. Trate isso como carregamento de código controlado pela configuração, não como desserialização de arquivos de modelo.<sup>[[1]](#references)</sup> Para a primitiva separada de leitura de arquivos, consulte [inclusão de arquivos e traversal de caminhos](../pentesting-web/file-inclusion/).

## O roteamento de modelos por solicitação pode causar leak de credenciais do gateway

O recurso de credenciais do lado do cliente do LiteLLM aceitava um objeto `user_config` em uma solicitação LLM. A rota avaliada criava um `litellm.Router` temporário a partir desse objeto, incluindo sua lista de modelos e o `api_base` do provedor. Um destino de provedor controlado pelo chamador poderia receber a solicitação de conclusão de saída do gateway e os cabeçalhos de autenticação configurados do provedor. As restrições aos campos `api_base` ou `api_key` de nível superior não abrangiam esse caminho separado de configuração aninhada. Trata-se de um limite de SSRF com credenciais, não de um problema de prompt injection.<sup>[[1]](#references)</sup>

Em uma avaliação autorizada de gateway, compare todos os caminhos que podem construir um roteador ou cliente de provedor, incluindo a configuração por solicitação, com a política de destino e credenciais usada pela rota configurada normalmente.<sup>[[1]](#references)</sup> O [guia de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) aborda o controle geral de destinos no lado do servidor; a falha específica do gateway é permitir que um objeto de solicitação menos confiável selecione um destino enquanto reutiliza credenciais privilegiadas de saída.<sup>[[1]](#references)</sup>

## O registro de guardrails pode contornar um sandbox exclusivo da UI

O caminho de teste de código e o caminho de registro de código de um gateway podem ter validações diferentes. No LiteLLM anterior à v1.82.0, o teste de guardrail personalizado da UI rejeitava sintaxe perigosa e executava com `__builtins__ = {}`, mas `POST /guardrails` compilava o `custom_code` enviado com `exec(compile(...), exec_globals)`, sem nenhuma dessas verificações. O Python insere builtins em um dicionário global que não contém `__builtins__`, portanto importações e comandos no nível do módulo eram executados **quando o guardrail era registrado**, antes de qualquer chamada de inferência. O callback posterior `apply_guardrail` poderia expor um resultado armazenado por meio do motivo do bloqueio.<sup>[[2]](#references)[[3]](#references)</sup>

Em um teste autorizado, compare os handlers de teste e de registro em vez de presumir que um teste bem-sucedido no sandbox da UI comprova que o registro é seguro. O formato da solicitação relatada antes da correção era:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

O endpoint de registro também aceitava chaves de API comuns porque não tinha uma verificação de `PROXY_ADMIN`. Quando nenhuma chave mestra ou autenticação JWT/OAuth2 estava configurada, o handler de autenticação anterior à correção atribuía `PROXY_ADMIN` até mesmo a solicitações anônimas. A correção alterou a função sem autenticação para `INTERNAL_USER`, adicionou verificações de administrador nos guardrails e validou e restringiu os builtins durante o registro. Esses limites de função e execução de código são separados do [problema de fallback de token do MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Rotas de pass-through de administrador podem acessar metadados da cloud

O recurso de endpoint pass-through do LiteLLM permite que um administrador configure um destino HTTP e, opcionalmente, anexe subcaminhos. Ao contrário do problema de roteamento por `user_config` por solicitação acima, isso exige **autoridade para gravar configurações**; o próprio recurso foi projetado para confiar nos administradores. Na implantação relatada, o destino não era verificado para detectar endereços privados ou de link-local.<sup>[[2]](#references)[[4]](#references)</sup> Antes da v1.83.0, chaves autenticadas comuns também podiam acessar `/config/update` porque não havia uma verificação da função de administrador; consulte [classificação de rotas da UI](#ui-route-classification-is-not-authorization) para ver o limite relacionado de gravação de configurações.<sup>[[2]](#references)[[6]](#references)</sup>

Com essa autoridade e conectividade de rede do proxy aos metadados do EC2, uma rota como a seguinte expõe metadados pelo gateway. A flag `include_subpath` faz com que `/meta/meta-data/iam/security-credentials/` seja mapeado sob `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

O [guia de SSRF na cloud](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) aborda a troca de tokens do IMDSv2; essa rota deve permitir a solicitação `PUT` e retransmitir ambos os cabeçalhos de metadados.<sup>[[5]](#references)</sup> O tratamento genérico de cabeçalhos de pass-through do LiteLLM remove o prefixo `x-pass-` antes de encaminhá-los, então `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` e `x-pass-X-aws-ec2-metadata-token: <token>` podem fornecer esses cabeçalhos.<sup>[[2]](#references)[[7]](#references)</sup> O proxy deve conseguir acessar o IMDS, a resposta do token deve atravessar o limite de saltos configurado e a solicitação do token não deve incluir `X-Forwarded-For`.<sup>[[5]](#references)</sup> A variação específica do gateway é a **rota persistente controlada pelo administrador mais a retransmissão dos cabeçalhos da solicitação**.

## References

- [1] [Check Point Research — Quando os gateways de LLM dão errado: descobertas sobre o LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Desprevenido: invadindo o LiteLLM, da falha de autenticação ao comprometimento da cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — corrigir RCE não autenticado e escape do sandbox em guardrail de código personalizado](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Criar endpoints de pass-through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Como funciona a versão 2 do serviço de metadados de instância](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Aviso do LiteLLM — endpoint irrestrito de configuração do proxy](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implementação do encaminhamento de cabeçalhos de pass-through do LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
