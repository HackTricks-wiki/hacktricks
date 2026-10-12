# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Tipos de payload do Intruder

O Burp Intruder inclui os seguintes geradores e transformações de payload integrados:<sup>[[1]](#references)</sup>

- **Lista simples:** Use uma lista configurada de strings como payloads.
- **Arquivo em tempo de execução:** Leia um payload por linha durante a execução. Isso é útil para listas grandes, pois o Burp não carrega o arquivo inteiro na memória.
- **Modificação de maiúsculas e minúsculas:** Gere o valor sem alterações, em letras minúsculas ou maiúsculas, no formato `Propername` (primeira letra maiúscula e o restante em minúsculas) ou `ProperName` (primeira letra maiúscula e os caracteres restantes sem alterações). O Burp descarta resultados duplicados.
- **Números:** Gere números sequenciais ou aleatórios dentro de um intervalo configurado.
- **Força bruta:** Gere todas as permutações para um conjunto de caracteres escolhido e um comprimento mínimo/máximo.

## Extensões e ferramentas complementares

- **Collabfiltrator** gera payloads que executam comandos e exfiltram a saída por meio de consultas DNS para o Burp Collaborator.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** exporta descobertas do Burp para uso em outros fluxos de trabalho de relatórios.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** converte requisições HTTP em scripts em várias linguagens.<sup>[[4]](#references)</sup>

## Testes de autorização com várias sessões usando o Session Switcher

[Session Switcher](https://github.com/doyensec/burp-session-switcher) é uma extensão Java para o Burp Suite `2025.5+` que armazena cookies e cabeçalhos incomuns como perfis de credenciais nomeados. Selecionar um perfil em um editor de requisições editável, incluindo Repeater ou uma requisição interceptada do Proxy, substitui os dados de autenticação da requisição. É um recurso para repetir requisições, **não um bypass de autorização**: use-o para enviar a mesma requisição como contas diferentes ao verificar acesso horizontal, limites entre funções, isolamento entre tenants e [IDOR/BOLA](../pentesting-web/idor.md) como parte da [metodologia de testes web](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Fluxo de trabalho repetível para comparar identidades

O fluxo de trabalho a seguir mantém o recurso/ação e a identidade usada como variáveis de teste separadas, reduzindo resultados falsos causados por tokens desatualizados ou pela sessão de navegador errada.<sup>[[5]](#references)[[8]](#references)</sup>

1. Autentique contas de teste que representem cada usuário, função e tenant relevante em perfis de navegador ou contêineres separados.
2. Abra uma requisição que contenha os cookies e cabeçalhos de uma identidade, selecione **Sessions > New** e dê ao perfil um nome claro, como `tenant-a-user` ou `tenant-b-admin`. Repita para cada identidade de teste.
3. Envie uma requisição candidata para o Repeater e repita-a sem alterar o método, endpoint, parâmetros ou identificador do objeto, mudando apenas a sessão selecionada. Compare os dados da resposta e as alterações de estado observáveis, não apenas os códigos de status.
4. Para verificações no nível do objeto, repita uma requisição para um objeto que se sabe pertencer à conta A usando o perfil da conta B. Para verificações no nível da função, repita a mesma ação privilegiada com perfis de menor privilégio.
5. Após uma nova autenticação ou rotação de token, use **Update** em uma requisição atual do navegador ou configure uma regra de Auto Update antes de repetir a comparação.

### Semântica de captura e injeção

Revise os modos de atualização/injeção antes dos testes, pois uma requisição híbrida contendo credenciais de duas identidades pode invalidar a comparação. Os padrões atuais espelham todos os cookies da requisição em um perfil, atualizam apenas cabeçalhos incomuns já armazenados, espelham os cookies do perfil selecionado na requisição de destino (removendo os cookies existentes) e adicionam os cabeçalhos do perfil. O seletor pode ser limitado a um subdomínio exato, ao domínio de nível superior do aplicativo (padrão) ou a todos os perfis salvos.<sup>[[7]](#references)</sup>

- **Mirror** é útil quando o conjunto completo de cookies define uma identidade e os cookies desatualizados da requisição de destino precisam ser removidos.
- **Update existing** acompanha valores rotativos sem aprender cookies ou cabeçalhos não relacionados do tráfego do navegador.
- **Add all** preserva valores adicionais já armazenados no perfil ou na requisição; verifique se isso não deixa dados de identificação da sessão anterior.
- **Do nothing** exclui cookies ou cabeçalhos das atualizações do perfil quando essa classe de credenciais não é relevante.

### Sincronização de sessões baseada no Proxy

As regras de Auto Update associam o tráfego do Proxy a um perfil salvo e atualizam seus cookies/cabeçalhos. Prefira um identificador estável, como um cabeçalho de requisição dedicado, um marcador `User-Agent` específico do perfil, um cookie identificador, `X-PwnFox-Color` ou uma claim JWT; combine-o com condições de escopo/domínio/caminho para que aplicativos não relacionados não possam atualizar o perfil. Todas as condições de uma regra são avaliadas como `AND` lógico, na ordem definida, então coloque primeiro as verificações mais restritivas; implemente `OR` criando várias regras direcionadas ao mesmo perfil. Também há suporte a correspondências negativas.<sup>[[6]](#references)</sup>

Para cada regra correspondente, escolha **Mirror request**, **Add all**, **Update existing** ou **Do nothing** de forma independente para cookies e cabeçalhos. Regras que avaliam apenas a requisição são executadas quando o Proxy recebe a requisição; adicionar uma condição de status da resposta, cabeçalho da resposta ou corpo da resposta adia a avaliação até a chegada da resposta. Uma cor de destaque pode marcar o tráfego correspondente, ajudando a verificar se cada identidade do navegador atualiza apenas o perfil pretendido.<sup>[[6]](#references)</sup>

Os perfis salvos ficam no projeto do Burp, e as exportações de dados do projeto em JSON incluem as sessões e, portanto, seus cookies e cabeçalhos. Trate ambos os arquivos como material de credenciais ativo, restrinja o acesso a eles e exclua os dados armazenados pela extensão após o engagement.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [Documentação da PortSwigger - Tipos de payload do Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Documentação de origem e uso do Session Switcher](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Regras de Auto Update do Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Configurações do Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Simplificando os testes de autorização com várias sessões no Burp Suite](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
