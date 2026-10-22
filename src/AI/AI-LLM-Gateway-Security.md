# Limites de confiança de gateways LLM

{{#include ../banners/hacktricks-training.md}}

Um gateway LLM gerencia o roteamento de modelos e geralmente armazena credenciais de provedores, portanto, seus chamadores de API comuns não devem herdar autoridade de configuração nem de nível de provedor. A avaliação do gateway LiteLLM na versão 1.77.7 ilustra dois limites distintos: a autorização de sessões da UI para configurações administrativas e a configuração de roteamento fornecida pelo chamador para inferência. Os problemas relatados foram corrigidos na versão 1.83.9.<sup>[[1]](#references)</sup>

## A classificação de rotas da UI não é autorização

Na versão avaliada do LiteLLM, as chaves de login da UI pertenciam à equipe `litellm-dashboard`. A autorização classificava uma chave como token da UI com base no identificador dessa equipe, independentemente da função do usuário. A verificação de rota da UI aceitava qualquer rota que começasse com um prefixo permitido. Como resultado, a entrada `/config` também correspondia ao handler administrativo `/config/update`. Esse handler exigia autenticação genérica, mas não exigia `PROXY_ADMIN` de forma independente, permitindo que uma sessão da UI com menos privilégios obtivesse acesso de gravação à configuração.<sup>[[1]](#references)</sup>

Isso difere de uma divergência na normalização de caminhos entre proxy e backend: o código de autorização e o handler discordam sobre a autoridade da *mesma* rota.<sup>[[1]](#references)</sup> Ao revisar um gateway, compare a classificação do token, a correspondência exata de rota e método e a verificação de função feita pelo próprio handler.<sup>[[1]](#references)</sup> Consulte [autorização de API web](../pentesting-web/web-api-pentesting.md), [bypasses de 401/403](../pentesting-web/403-and-401-bypasses.md) e [isenções de prefixo em proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) para limites relacionados, porém distintos.

## As gravações de configuração afetam mais do que o armazenamento de configuração

A mesma atualização de configuração do LiteLLM aceitava valores de variáveis de ambiente e os aplicava ao processo em execução. Um consumidor tratava `UI_LOGO_PATH` como um caminho local para um `FileResponse`, sem validar se ele apontava para um logo; outro lia `UI_USERNAME` e `UI_PASSWORD` durante o login sem SSO e atribuía `PROXY_ADMIN` quando os valores correspondiam. Assim, a permissão de gravação na configuração podia resultar tanto em divulgação de arquivos locais quanto em alteração de identidade administrativa, dependendo do consumidor downstream. O tipo de mídia da resposta não comprova que o arquivo servido seja uma imagem.<sup>[[1]](#references)</sup>

A configuração do endpoint pass-through era outro destino downstream. A inicialização aceitava destinos de adaptadores remotos S3/GCS, baixava módulos Python e os importava usando `exec_module` do `importlib`. A importação executa o código de nível superior antes que uma instância do adaptador seja usada; restringir apenas a invocação do adaptador não eliminaria esse limite de execução. Trate isso como carregamento de código controlado por configuração, não como desserialização de arquivos de modelo.<sup>[[1]](#references)</sup> Para a primitiva separada de leitura de arquivos, consulte [inclusão de arquivos e traversal de caminhos](../pentesting-web/file-inclusion/).

## O roteamento de modelos por requisição pode causar leak de credenciais do gateway

O recurso de credenciais do lado do cliente do LiteLLM aceitava um objeto `user_config` em uma requisição LLM. A rota avaliada criava um `litellm.Router` temporário a partir desse objeto, incluindo sua lista de modelos e o `api_base` do provedor. Um destino de provedor controlado pelo chamador podia receber a requisição de conclusão de saída do gateway e os cabeçalhos de autenticação configurados do provedor. As restrições nos campos `api_base` ou `api_key` de nível superior não abrangiam esse caminho separado de configuração aninhada. Esse é um limite de SSRF com credenciais, não um problema de prompt injection.<sup>[[1]](#references)</sup>

Em uma avaliação autorizada de gateway, compare todos os caminhos que podem construir um roteador ou cliente de provedor, incluindo a configuração por requisição, com a política de destino e credenciais usada pela rota normalmente configurada.<sup>[[1]](#references)</sup> O [guia de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) aborda o controle geral de destinos no lado do servidor; a falha específica do gateway é permitir que um objeto de requisição menos confiável selecione um destino enquanto reutiliza credenciais privilegiadas de saída.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Quando os gateways LLM dão errado: descobertas do LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
