# Infraestrutura Ofensiva e Evasão de Atribuição

{{#include ../banners/hacktricks-training.md}}

Um operador raramente obtém anonimato significativo usando um único proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, os nós de trânsito ocultam esse nó da saída, os redirectors protegem o C2 real e nomes descartáveis apontam para a borda pública.

Use o [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) para obter uma visão normalizada de prós/contras, implantação e detecção de cada caminho. Esta página aprofunda a composição de infraestrutura adversária.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
O último endereço visto por um alvo é, portanto, evidência de um caminho, não prova de quem controlava o teclado. O MITRE mapeia os principais componentes para Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes de infraestrutura

| Classe | Por que um ator a utiliza | Exposição duradoura | Melhor pivot do defensor |
|---|---|---|---|
| VPS/cloud alugado | Rápido, previsível, roteável e fácil de reconstruir | tenant, faturamento, console, login de origem e histórico de imagens | eventos da conta/control plane e fingerprint repetido do servidor |
| VPN/Tor comercial | Grande conjunto de egress compartilhado; nenhuma administração de servidor | visibilidade do provedor/guard e timing de ponta a ponta | comportamento do destino, evidências do endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | registros do broker/cliente; comportamento de proxyware ou host infectado | deslocamento impossível, protocolos de proxy e churn de endereços por sessão |
| Servidor/roteador/IoT comprometido | Aproveita a reputação e a jurisdição da vítima | implant, fluxo de gerenciamento e controlador upstream recorrente | telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirector | Separa a borda pública do C2 de back-end | gramática TLS/HTTP, certificado, roteamento e artefatos da conta cloud | correlação entre borda e origem e agrupamento por formato de requisição |
| Web service legítimo | Mistura-se ao tráfego permitido do GitHub/cloud/social | token de API, identificadores de tenant/objeto e linhagem incomum de processos | processo do endpoint e semântica do service/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | registros de RF, operadora, assinante, dispositivo e localização | evidências de rádio/físicas combinadas com evidências de rede |

## Redes de relay box operacionais

Uma **rede ORB** é uma frota de proxies gerenciada e usada como serviço intermediário. A Mandiant as divide em redes provisionadas de servidores alugados, redes não provisionadas de roteadores/IoT comprometidos e redes híbridas. Uma topologia madura possui quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administração (ACOS):** mantém inventário, credenciais, integridade e política de roteamento.
2. **Nó de acesso/relay:** autentica clientes ou operadores; é a entrada estável para uma mesh em constante mudança.
3. **Nós de traversal:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Nó de saída/staging:** apresenta o endereço de origem final para reconnaissance, exploitation ou alvos de C2.

A mesh pode selecionar saídas por país, ASN, latência ou disponibilidade e alternar nós não saudáveis. Vários grupos de ameaças podem alugar a mesma rede. A Mandiant observou um endereço IPv4 permanecer associado a alguns ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade em evolução semelhante a um ator**, em vez de bloquear uma lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### O que isso proporciona — e o que vaza

- O alvo vê uma saída que pode estar geograficamente próxima e aparentemente ser residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma mesh gerenciada de forma independente pode manter o cliente separado das saídas, mas cria um poderoso registro da contraparte.
- Portas repetidas, ordem do handshake, banners de servidor, certificados, janelas de uptime e relacionamentos com controladores podem expor a frota mesmo enquanto os IPs alternam.
- Um roteador comprometido frequentemente não possui telemetria de endpoint, mas seu ISP ainda mantém dados de assinante e de fluxo; uma apreensão expõe artefatos do implant/configuração.

{% hint style="info" %}
Para um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos ou dispositivos de terceiros. O [guia do lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível ao defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxy residencial e móvel

Serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; proxies móveis fazem egress por pools de NAT de operadoras. O fornecimento pode vir de appliances inscritos explicitamente, SDK/proxyware integrado a aplicações de consumo, revendedores ou malware. Essas origens não são equivalentes: a falta de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- **rotação por requisição** produz descontinuidades rápidas de IP e ASN/geografia, enquanto a identidade de camada superior permanece estável;
- **sticky sessions** mantêm uma saída por minutos ou horas, assemelhando-se a um assinante comum;
- **backconnect gateways** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- **pools móveis** colocam muitos assinantes reais atrás de um pequeno conjunto de endereços NAT de operadoras, tornando um bloqueio de IP oneroso.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint de TLS/cliente, a ordenação HTTP, o cookie do dispositivo e o comportamento. Um login residencial supostamente local seguido por outro país, enquanto todos os recursos de camada superior permanecem idênticos, é um indicador mais forte do que a reputação isoladamente. Por outro lado, o compartilhamento de endereços e a troca de rede móvel geram churn legítimo; portanto, nunca trate a classificação residencial/proxy como um veredito.

## Cadeias de proxy com múltiplos saltos

O MITRE distingue proxies externos de **multi-hop proxies (T1090.003)**. A propriedade importante não é a quantidade de saltos, mas a separação de conhecimento e administração.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se uma única parte opera A e B, logs compartilhados ou a temporização do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode aumentar a latência, mas mantém evidências comuns de identidade, pagamento e temporização. Tor reduz esse problema com relays selecionados independentemente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode prometer resistência contra um observador que mede ambas as pontas.

Falhas comuns incluem bypass de DNS ou IPv6, aplicativos abrindo seus próprios sockets, tráfego de gerenciamento alcançando os relays diretamente, atividade sincronizada, chaves SSH reutilizadas e login em contas identificáveis. A verificação correta é um teste de falha: interrompa cada relay por vez e mostre que a carga de trabalho não pode recorrer a um caminho em claro.

## Camadas de redirector e modelagem de tráfego

Um **redirector** público aceita o tráfego que corresponde a uma gramática específica da operação e o encaminha para um servidor protegido da equipe. Todo o resto pode ser rejeitado ou receber conteúdo inofensivo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiplas camadas limitam a exposição: queimar um domínio público não precisa expor o servidor da equipe. CDNs adicionam capacidade anycast e um domínio externo de boa reputação, mas a conta da CDN e os logs de edge tornam-se pontos de atribuição. Impressões digitais de TLS, históricos de certificados, paths distintos/ordem de headers, tamanhos de respostas, comportamento de redirecionamento e allowlists de origem podem agrupar fronts supostamente não relacionados.

Para detecção, registre os campos do reverse proxy antes da normalização, compare SNI/Host/authority, inspecione combinações raras de headers, agrupe corpos de resposta e impressões digitais de TLS e pesquise nos logs de auditoria de cloud/CDN por sobreposição de configurações. Para red teams autorizados, evite copiar uma marca real ou colocar coleta de credenciais atrás de um terceiro não relacionado.

## Domain fronting and domainless fronting

Com o **domain fronting (T1090.004)** clássico, a conexão TLS anuncia um domínio front permitido no SNI, enquanto o `Host` HTTP criptografado ou `:authority` do HTTP/2 solicita um domínio de back-end diferente. Uma CDN colaboradora faz o roteamento com base no valor interno. Um observador de rede sem descriptografia TLS vê o front; a CDN vê ambos os valores e a origem. Nas variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma personificação mágica: funciona apenas quando o intermediário permite intencionalmente ou acidentalmente a divergência e sabe como rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) altera o que um observador no caminho pode ver, mas não elimina os registros da CDN, do endpoint ou da aplicação.

Os pontos de detecção incluem:

- ancestralidade do processo no endpoint e destino não esperado para aquela aplicação;
- divergência entre SNI e authority HTTP quando a inspeção TLS é legal e está disponível;
- logs da CDN mostrando um tenant/front roteando para outra authority/origin;
- sessões incomumente longas ou periódicas com um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados através de domínios front variáveis.

O lab seguro simula a divergência de roteamento em um reverse proxy próprio; ele não abusa de uma CDN pública.

## Dynamic resolution: DDNS, DGA and fast flux

A resolução dinâmica desacopla um serviço lógico da infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável após a alteração de seu endereço.
- **DGA:** tanto o endpoint quanto o controller derivam nomes de domínio candidatos a partir de uma seed de tempo/chave; o operador registra um pequeno subconjunto.
- **Fast flux:** um nome retorna um conjunto que muda rapidamente de endereços comprometidos/proxy, geralmente com TTLs baixos.
- **Double flux:** tanto os endereços do serviço quanto os endereços dos name servers autoritativos alternam, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alta contagem de endereços únicos, ampla dispersão de ASN/geográfica, curta vida dos nós, comportamento repetido da aplicação e histórico suspeito de registro. CDNs compartilham legitimamente várias dessas propriedades. O MITRE recomenda correlacionar o comportamento DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Um DGA pode ser detectado por meio de entropia lexical, padrões de consoantes/dígitos, explosões de NXDOMAIN, domínios sincronizados vistos pela primeira vez e contexto do processo. Wordlist DGAs e modelos generativos derrotam regras simples de entropia, tornando mais importante o agrupamento temporal em toda a frota e a linhagem do endpoint.

## Compromised domains and domain shadowing

Um ator pode sequestrar uma conta de registrar/DNS, assumir o controle de um subdomínio abandonado ou adicionar registros sob um domínio com boa reputação. **Domain shadowing** preserva o apex legítimo enquanto grandes quantidades de subdomínios controlados pelo atacante apontam para hosts de delivery ou C2 variáveis. Isso aproveita idade e reputação e pode escapar do bloqueio em todo o domínio.<sup>[[6]](#references)</sup>

Os defensores precisam de logs de auditoria do registrar e do DNS autoritativo, MFA, locks de registry/registrar, alertas para novas delegações/tokens de API/name servers, monitoramento de certificate transparency e um inventário dos recursos de cloud referenciados pelo DNS. Investigue a resolução e o histórico de certificados de um subdomínio independentemente da reputação do apex.

## Web services and dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual dentro de uma publicação, perfil, documento, repository, objeto de cloud ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviços.<sup>[[7]](#references)</sup>

Isso fornece resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repository, API e padrão de acesso. Os defensores devem associar:

1. o processo que contatou o serviço;
2. o path/objeto exato da API e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída logo depois; e
5. comportamento idêntico em outros pontos da frota.

Bloquear todo o GitHub, cloud storage ou social media raramente é viável. Uma política de egress com conhecimento do serviço e a correlação no nível do processo são superiores ao bloqueio baseado apenas em domínio.

## Personas, accounts and procurement compartments

O anonimato da infraestrutura falha quando uma persona, recovery email, telefone, pagamento, browser ou IP de admin conecta compartimentos. Operações vinculadas a Estados cultivaram perfis sociais, identidades de email e contas de cloud muito antes do uso; o ATT&CK registra isso como Establish Accounts (T1585), incluindo as sub-técnicas social, email e cloud.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horário de criação e primeiro login, localidade, fuso horário e agenda de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e instrumentos de pagamento;
- impressões digitais de browser/TLS e histórico da rede de origem;
- reutilização de avatar, procedência de imagens, estilo de escrita e crescimento do grafo social;
- registrant de domínio, name server, certificado, ID de analytics ou commit de repository compartilhado;
- ações no plano de gerenciamento que contornam a arquitetura pública de relay.

Para um red team autorizado, personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar personificar pessoas reais não envolvidas e ter uma retirada planejada. O SOC pode continuar sem visibilidade; a operação não pode se tornar sem responsabilização.

## Emerging compound patterns to threat-model

Os itens a seguir são **composições orientadas pelo defensor**, não afirmações de que um ator nomeado tenha implementado cada design exato. Eles combinam primitivas já observadas e são hipóteses úteis para purple team.

### Asymmetric one-way tasking

Os comandos chegam por uma fonte pública, de broadcast ou append-only, enquanto os resultados saem por um canal não relacionado após um atraso. Exemplos da primitiva incluem comunicação unidirecional por web service e dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de request/response.<sup>[[9]](#references)</sup>

**Detecção:** preserve leituras no nível do objeto e depois correlacione mudanças de estado do processo e transferências de saída posteriores em uma janela mais ampla. Procure um processo raro lendo o mesmo objeto público mesmo quando nenhuma resposta imediata ocorre.

### Multi-stage channel promotion

Um primeiro estágio discreto realiza inventário e promove apenas sistemas selecionados para um canal de segundo estágio não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar infraestrutura com o primeiro. Isso limita a exposição da infraestrutura capaz e é explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** associe `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; não encerre o incidente após bloquear o primeiro domínio.

### Cross-protocol relay translation

Hops diferentes traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de message queue, em vez de encaminhar pacotes de forma transparente. A tradução remove uma única impressão digital de protocolo ponta a ponta, mas cria gateways com temporização, buffering e conversão semântica distintos. Protocol tunneling (T1572) pode ser combinado com proxies e service impersonation.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts gateway que recebem um protocolo e iniciam outro com comportamento de bytes/tempo fortemente correlacionado; compare a intenção do endpoint com o protocolo realmente transportado.

### Passive activation on edge devices

Em vez de beaconing, um implant monitora o tráfego que já chega a um router/VPN e ativa somente diante de um valor mágico, padrão de source port ou token autenticado. O tráfego normal continua até o serviço real. O ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados de dispositivos de rede e APT.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivo, captura de pacotes brutos durante um hunt autorizado, filtros de socket inesperados e comportamento diferencial do serviço. A ausência de um beacon periódico não prova que um dispositivo edge esteja limpo.

### Serverless and ephemeral origin rotation

Um front mantém uma identidade lógica estável enquanto funções/containers de curta duração lidam com estágios individuais em várias regiões/contas. Isso reduz a vida útil em disco e os IPs de origem fixos, mas a criação no control plane, image/layer, role, secret, request ID e telemetria de billing tornam-se o grafo durável.

**Detecção:** retenha logs de auditoria e invocação de cloud fora do workload; agrupe templates de deployment, roles, chaves de ambiente e relações front-to-origin.

### Privacy-layer diversity

Uma operação pode evitar deliberadamente uma única cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, uma saída vem de um link celular de lab próprio e a administração usa uma rede separada da organização. Isso reduz o valor de comprometer um provedor, mas aumenta o risco de correlação temporal entre camadas e de erros operacionais.

**Detecção:** construa timelines da campanha entre sensores de identidade, DNS, SaaS, rede e cloud. Procure transições de estado sincronizadas, em vez de indicadores idênticos.

### Decentralized or transparency-log dead drops

Um ator pode colocar um pequeno ponteiro criptografado em qualquer sistema público durável e append-only, content-addressed store ou feed semelhante a transparency log. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de polling do cliente tornam-se identificadores estáveis.

**Detecção:** registre identificadores completos de API/objeto e hashes de resposta; alerte sobre processos não padrão fazendo polling de objetos imutáveis seguido de decodificação ou novas conexões.

### Delayed store-and-forward operations

C2 interativo cria forte correlação temporal. Um design store-and-forward agrupa jobs criptografados e retorna resultados minutos ou horas depois por outra queue ou transferência física. Ele sacrifica capacidade de resposta por uma temporização ponta a ponta mais fraca.

**Detecção:** aumente as janelas de correlação, modele o acesso periódico à queue e examine o staging no endpoint. O agrupamento move o sinal da temporização de pacotes para o comportamento agendado de processos/arquivos; ele não o elimina.

## Design review: think in observers

Para cada path, preencha esta tabela antes do deployment e após a coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Retenção/responsável legal |
|---|---:|---:|---:|---|---|
| rede local/carrier | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de traversal | | | | | |
| saída/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um único provedor comum puder preencher todas as colunas, a arquitetura fornece ocultação do alvo, mas não uma separação robusta. Se nenhum controller interno puder associar a atividade a um engagement, ela não é adequada para red teaming profissional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestrutura (T1583), Comprometer infraestrutura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestrutura: domínios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
