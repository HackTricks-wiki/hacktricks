# Infraestrutura Ofensiva e Evasão de Atribuição

{{#include ../banners/hacktricks-training.md}}

Um operador raramente obtém anonimato significativo usando um único proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, os nós de trânsito ocultam esse nó do nó de saída, os redirectors protegem o C2 real e nomes descartáveis apontam para a borda pública.

Use o [Catálogo de Técnicas de Acesso Anônimo à Internet](anonymous-internet-access-techniques.md) para obter uma visão normalizada de prós/contras, implantação e detecção de cada caminho. Esta página se aprofunda na composição de infraestrutura adversária.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
O último endereço visto por um alvo é, portanto, evidência de um caminho, não prova de quem controlava o teclado. O MITRE mapeia os principais componentes para Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes de infraestrutura

| Classe | Por que um ator a utiliza | Exposição duradoura | Melhor pivô do defensor |
|---|---|---|---|
| VPS/cloud alugado | Rápido, previsível, roteável e fácil de reconstruir | tenant, cobrança, console, login de origem e histórico de imagens | eventos da conta/control plane e fingerprint recorrente do servidor |
| VPN/Tor comercial | Grande conjunto de egress compartilhado; sem administração de servidor | visibilidade do provedor/guard e timing de ponta a ponta | comportamento do destino, evidências no endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | registros do broker/cliente; comportamento de proxyware ou host infectado | viagem impossível, protocolos de proxy e rotatividade de endereços por sessão |
| Servidor/roteador/IoT comprometido | Aproveita a reputação e a jurisdição da vítima | implant, fluxo de gerenciamento e controlador upstream recorrente | telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirector | Separa a edge pública do C2 de back-end | gramática TLS/HTTP, certificado, roteamento e artefatos da conta cloud | correlação edge-to-origin e agrupamento por formato de requisição |
| Web service legítimo | Mistura-se ao tráfego permitido do GitHub/cloud/social | token de API, identificadores de tenant/objeto e linhagem incomum de processos | processo do endpoint e semântica do serviço/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | registros de RF, operadora, assinante, dispositivo e localização | evidências de rádio/físicas e de rede combinadas |

## Redes de relay box operacionais

Uma **rede ORB** é uma frota de proxies gerenciada, utilizada como serviço intermediário. A Mandiant as divide em redes provisionadas de servidores alugados, redes não provisionadas de roteadores/IoT comprometidos e híbridas. Uma topologia madura possui quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** mantém inventário, credenciais, integridade e política de roteamento.
2. **Access/relay node:** autentica clientes ou operadores; é a entrada estável para uma mesh em constante mudança.
3. **Traversal nodes:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Exit/staging node:** apresenta o endereço de origem final para alvos de reconnaissance, exploitation ou C2.

A mesh pode selecionar saídas por país, ASN, latência ou disponibilidade e alternar nós não íntegros. Vários threat groups podem alugar a mesma rede. A Mandiant observou um endereço IPv4 permanecer associado a alguns ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade em evolução semelhante a um ator**, em vez de bloquear uma lista desatualizada de IPs.<sup>[[2]](#references)</sup>

### O que isso proporciona — e o que isso vaza

- O alvo vê uma saída que pode estar geograficamente próxima e aparentemente ser residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma mesh gerenciada de forma independente pode manter o cliente separado das saídas, mas cria um registro poderoso da contraparte.
- Portas recorrentes, ordem do handshake, banners de servidor, certificados, janelas de uptime e relações com controladores podem expor a frota mesmo enquanto os IPs rotacionam.
- Um roteador comprometido frequentemente não possui telemetria de endpoint, mas seu ISP ainda tem dados de assinante e de fluxo; uma apreensão expõe artefatos do implant/configuração.

{% hint style="info" %}
Para um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos ou dispositivos de terceiros. O [guia do laboratório](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível ao defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxy residencial e móvel

Os serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; os proxies móveis fazem egress por pools de NAT de operadoras. O fornecimento pode vir de appliances explicitamente inscritos, SDK/proxyware integrado a aplicações de consumo, revendedores ou malware. Essas origens não são equivalentes: a ausência de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- **rotação por requisição** produz descontinuidades rápidas de IP e ASN/geografia, enquanto a identidade nas camadas superiores permanece estável;
- **sticky sessions** mantêm uma saída por minutos ou horas, assemelhando-se a um assinante comum;
- **backconnect gateways** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- **mobile pools** colocam muitos assinantes genuínos atrás de um pequeno conjunto de endereços NAT de operadoras, tornando um bloqueio de IP custoso.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint de TLS/cliente, a ordenação HTTP, o cookie do dispositivo e o comportamento. Um login residencial supostamente local seguido por outro país, enquanto todos os recursos das camadas superiores permanecem idênticos, é um indicador mais forte do que a reputação isoladamente. Por outro lado, o compartilhamento de endereços e a transferência entre redes móveis geram rotatividade legítima; portanto, nunca trate a classificação residencial/proxy como um veredito.

### Control planes de proxyware e sobreposição de revendedores

Não modele um pool residencial como uma lista simples de saídas. A análise do ecossistema IPIDEA expôs um **control plane reutilizável em dois níveis**: um SDK incorporado primeiro reporta metadados do dispositivo/inscrição a um domínio Tier One e recebe agendamento, além de pares `connect`/`proxy` IP:port do Tier Two. O nó consulta periodicamente a porta de conexão do Tier Two em busca de uma tarefa codificada, abre uma segunda conexão com a porta proxy correspondente e retransmite os bytes fornecidos para o destino solicitado. SDKs e marcas de proxy nominalmente diferentes tinham domínios de descoberta separados, mas convergiam para uma infraestrutura compartilhada de Tier Two e pools de saída sobrepostos por meio de propriedade comum e relações com revendedores.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Isso produz pivôs de hunting mais duráveis do que um bloco de IP residencial:<sup>[[13]](#references)</sup>

- um processo inesperado de utility, VPN, game ou dispositivo embarcado envia um ID estável do dispositivo/chave do cliente e recebe uma lista de servidores variável;
- o endpoint consulta um IP direto em uma porta incomum e, em seguida, conecta-se a outra porta no mesmo endereço imediatamente antes de abrir um novo socket de destino;
- várias marcas aparentes compartilham endereços Tier Two, gramática de protocolo, código de SDK ou sobreposição de exit nodes;
- aplicações distintas que contatam diferentes domínios Tier One recebem endereços do mesmo pool Tier Two.

A sobreposição também limita a atribuição: ver um IP no pool anunciado por um vendor não estabelece qual reseller, cliente ou threat actor o utilizou no momento relevante. Preserve os timestamps dos fluxos, a linhagem dos processos, os corpos das respostas Tier One e os identificadores de tarefas Tier Two.<sup>[[13]](#references)</sup> Em um exercício autorizado, emule essa hierarquia somente com endpoints pertencentes à organização; nunca inscreva dispositivos de consumidores ou proxyware de terceiros.

## Cadeias de proxy multi-hop

O MITRE distingue proxies externos de **multi-hop proxies (T1090.003)**. A propriedade importante não é a quantidade de hops, mas a separação do conhecimento e da administração.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se uma das partes opera A e B, logs compartilhados ou o timing do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode acrescentar latência, mas mantém evidências comuns de identidade, pagamento e timing. Tor reduz esse problema com relays selecionados de forma independente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode prometer resistência contra um observador que mede ambas as pontas.

Falhas comuns são bypass de DNS ou IPv6, aplicações abrindo seus próprios sockets, tráfego de gerenciamento alcançando diretamente os relays, atividade sincronizada, chaves SSH reutilizadas e login em contas identificáveis. A verificação correta é um teste de falha: interrompa cada relay por vez e mostre que o workload não pode retornar a um caminho claro.

### Colapso do túnel e vazamento upstream

Uma arquitetura de relay costuma ser mais atribuível quando falha. A Unit 42 documentou um caminho de espionagem em múltiplas camadas usando VPSs voltados às vítimas, VPSs de relay, proxies residenciais, Tor e outros serviços de proxy; quando um túnel era omitido ou entrava em colapso, a infraestrutura upstream oculta conectava-se diretamente aos sistemas de relay e voltados às vítimas. A mesma investigação também usou um certificado X.509 brevemente exposto na infraestrutura upstream como pivô entre camadas.<sup>[[14]](#references)</sup>

Mantenha o **data plane** (`victim <-> exit`) separado do **control plane** (`operator/upstream -> relay administration`). Retenha logs de ingresso e autenticação em cada camada controlada, históricos de certificados e conexões curtas malsucedidas—not only sessões C2 bem-sucedidas. Uma fonte que aparece apenas durante interrupções dos relays ou administra diretamente vários nós voltados às vítimas é uma candidata upstream mais forte do que um exit comum, mas seu ASN/geolocalização ainda é uma hipótese, não uma prova da identidade do operador.

Um laboratório autorizado deve fazer o workload falhar de forma fechada. Para um workload isolado em um namespace de rede Linux, a primeira rota deve usar o túnel; depois de removê-lo, tanto a requisição quanto a consulta de rota devem falhar, em vez de selecionar o uplink físico:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Repita o teste para DNS e IPv6 e em cada limite de relay. Se alguma sonda for bem-sucedida, registre a interface/endereço de origem real antes de corrigir o roteamento baseado em políticas ou o firewall; essa observação é o attribution leak que um investigador veria.

## Camadas de redirector e modelagem de tráfego

Um **redirector** público aceita tráfego que corresponda a uma gramática específica da operação e o encaminha para um team server protegido. Todo o restante pode ser rejeitado ou receber conteúdo inofensivo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiplas camadas limitam a exposição: queimar um domínio público não precisa expor o team server. CDNs adicionam capacidade anycast e um domínio externo respeitável, mas a conta da CDN e os edge logs tornam-se pontos de atribuição. TLS fingerprints, históricos de certificados, paths distintos/ordem de headers, tamanhos de resposta, comportamento de redirects e allowlists de origem podem agrupar fronts supostamente não relacionados.

Para detecção, registre os campos do reverse proxy antes da normalização, compare SNI/Host/authority, inspecione combinações raras de headers, agrupe response bodies e TLS fingerprints e pesquise nos cloud/CDN audit logs por sobreposição de configuração. Em red teams autorizados, evite copiar uma marca real ou colocar coleta de credenciais atrás de um terceiro não relacionado.

## Domain fronting and domainless fronting

Com o **domain fronting (T1090.004)** clássico, a conexão TLS anuncia um domínio front permitido no SNI, enquanto o `Host` HTTP ou `:authority` do HTTP/2 criptografado solicita um domínio de back-end diferente. Uma CDN cooperante roteia com base no valor interno. Um observador de rede sem descriptografia TLS vê o front; a CDN vê ambos os valores e a origem. Nas variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma personificação mágica: funciona somente quando o intermediário permite intencionalmente ou acidentalmente a divergência e sabe como rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) altera o que um observador no caminho pode ver, mas não elimina os registros da CDN, do endpoint ou da aplicação.

Os pontos de detecção incluem:

- ancestralidade do processo no endpoint e destino não esperado para aquela aplicação;
- divergência entre SNI e autoridade HTTP quando a inspeção TLS é legal e está disponível;
- logs da CDN mostrando um tenant/front roteando para outra autoridade/origem;
- sessões incomumente longas ou periódicas com um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados através de front domains em mudança.

O laboratório seguro simula a divergência de roteamento em um reverse proxy próprio; ele não abusa de uma CDN pública.

## Dynamic resolution: DDNS, DGA and fast flux

A resolução dinâmica desacopla um serviço lógico da infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável depois que seu endereço muda.
- **DGA:** tanto o endpoint quanto o controller derivam nomes de domínio candidatos a partir de uma seed de tempo/chave; o operador registra um pequeno subconjunto.
- **Fast flux:** um nome retorna um conjunto que muda rapidamente de endereços comprometidos/de proxy, geralmente com TTLs baixos.
- **Double flux:** tanto os endereços dos serviços quanto os endereços dos name servers autoritativos são alternados, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alta contagem de endereços únicos, ampla dispersão de ASN/geografia, curta vida útil dos nós, comportamento repetido da aplicação e histórico suspeito de registro. CDNs compartilham legitimamente várias dessas propriedades. A MITRE recomenda correlacionar o comportamento DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Um DGA pode ser detectado por meio de entropia léxica, padrões de consoantes/dígitos, surtos de NXDOMAIN, domínios vistos pela primeira vez de forma sincronizada e contexto do processo. DGAs baseados em wordlists e modelos generativos derrotam regras simples de entropia, tornando mais importante o agrupamento temporal em toda a frota e a linhagem do endpoint.

## Compromised domains and domain shadowing

Um ator pode sequestrar uma conta de registrar/DNS, assumir um subdomínio abandonado ou adicionar registros sob um domínio que, de outra forma, seria respeitável. O **domain shadowing** preserva o apex legítimo enquanto grandes quantidades de subdomínios controlados pelo atacante apontam para hosts de delivery ou C2 em mudança. Isso aproveita idade e reputação e pode escapar do bloqueio em todo o domínio.<sup>[[6]](#references)</sup>

Os defensores precisam de registrar e authoritative-DNS audit logs, MFA, locks de registry/registrar, alertas para novas delegações/API tokens/name servers, monitoramento de certificate transparency e um inventário dos recursos cloud referenciados pelo DNS. Investigue a resolução e o histórico de certificados de um subdomínio independentemente da reputação do apex.

## Web services and dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual dentro de um post, perfil, documento, repository, objeto cloud ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviços.<sup>[[7]](#references)</sup>

Isso proporciona resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repository, API e padrão de acesso. Os defensores devem associar:

1. o processo que contatou o serviço;
2. o API path/objeto exato e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída logo depois; e
5. o comportamento idêntico em outros pontos da frota.

Bloquear todo o GitHub, cloud storage ou social media raramente é viável. Uma política de egress orientada ao serviço e a correlação no nível do processo superam o bloqueio baseado apenas em domínio.

## Personas, accounts and procurement compartments

O anonimato da infraestrutura falha quando uma persona, email de recuperação, telefone, pagamento, browser ou IP administrativo conecta compartments. Operações vinculadas a Estados cultivaram perfis sociais, identidades de email e contas cloud muito antes do uso; a ATT&CK registra isso como Establish Accounts (T1585), incluindo sub-técnicas sociais, de email e cloud.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horário de criação e primeiro login, localidade, fuso horário e agenda de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e instrumentos de pagamento;
- browser/TLS fingerprints e histórico da rede de origem;
- reutilização de avatar, procedência de imagens, estilo de escrita e crescimento do grafo social;
- registrant de domínio, name server, certificado, analytics ID ou commit de repository compartilhado;
- ações no management plane que contornam a arquitetura pública de relay.

Para um red team autorizado, personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar personificar pessoas reais não envolvidas e ter uma retirada planejada. O SOC pode continuar sem visibilidade; a operação não deve se tornar irresponsável.

## Emerging compound patterns to threat-model

Os itens a seguir são **composições orientadas pelo defensor**, não alegações de que um ator identificado tenha implementado cada design exato. Eles combinam primitivas já observadas e são hipóteses úteis para purple teams.

### Asymmetric one-way tasking

Comandos chegam por uma fonte pública, de broadcast ou append-only, enquanto os resultados saem por um canal não relacionado após um atraso. Exemplos da primitiva incluem comunicação one-way por web service e dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de request/response.<sup>[[9]](#references)</sup>

**Detecção:** preserve leituras no nível do objeto e depois correlacione mudanças de estado do processo e transferências de saída posteriores em uma janela mais ampla. Procure um processo raro lendo o mesmo objeto público mesmo quando não há resposta imediata.

### Multi-stage channel promotion

Um primeiro estágio silencioso realiza inventário e promove apenas sistemas selecionados para um canal de segundo estágio não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar infraestrutura com o primeiro. Isso limita a exposição da infraestrutura capaz e é explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** associe `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; não encerre o incidente depois de bloquear o primeiro domínio.

### Cross-protocol relay translation

Diferentes hops traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de message queue em vez de encaminhar pacotes de forma transparente. A tradução remove um único protocol fingerprint de ponta a ponta, mas cria gateways com timing, buffering e conversão semântica distintos. Protocol tunneling (T1572) pode ser combinado com proxies e service impersonation.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts gateway que recebem um protocolo e iniciam outro com comportamento de bytes/tempo fortemente acoplado; compare a intenção do endpoint com o protocolo realmente transportado.

### Passive activation on edge devices

Em vez de beaconing, um implant monitora o tráfego que já chega a um router/VPN e ativa somente diante de um valor mágico, padrão de source port ou token autenticado. O tráfego normal continua indo para o serviço real. A ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados em dispositivos de rede e APTs.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivos, captura de pacotes brutos durante um hunt autorizado, filtros de socket inesperados e comportamento diferencial do serviço. A ausência de um beacon periódico não prova que um edge device esteja limpo.

### Serverless and ephemeral origin rotation

Um front mantém uma identidade lógica estável enquanto funções/containers de curta duração lidam com estágios individuais em várias regiões/contas. Isso reduz a vida útil em disco e os IPs de origem fixos, mas a criação no control plane, image/layer, role, secret, request ID e telemetria de billing tornam-se o grafo durável.

**Detecção:** mantenha cloud audit e invocation logs fora do workload; agrupe templates de deployment, roles, environment keys e relações entre front e origem.

### Privacy-layer diversity

Uma operação pode evitar deliberadamente uma única cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, um exit vem de um link celular de laboratório próprio e a administração usa uma rede organizacional separada. Isso reduz o valor de comprometer um provedor, mas aumenta o risco de timing entre camadas e de erros operacionais.

**Detecção:** construa timelines da campanha entre sensores de identidade, DNS, SaaS, rede e cloud. Procure transições de estado sincronizadas em vez de indicadores idênticos.

### Decentralized or transparency-log dead drops

Um ator pode colocar um pequeno ponteiro criptografado em qualquer sistema público durável de append-only, armazenamento content-addressed ou feed semelhante a transparency log. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de polling do cliente tornam-se identificadores estáveis.

**Detecção:** registre identificadores completos de API/objeto e hashes de resposta; alerte sobre processos não padrão consultando objetos imutáveis, seguidos de decodificação ou novas conexões.

### Delayed store-and-forward operations

O C2 interativo cria uma forte correlação temporal. Um design store-and-forward agrupa jobs criptografados e retorna resultados minutos ou horas depois por meio de outra queue ou transferência física. Ele sacrifica capacidade de resposta em troca de um timing de ponta a ponta mais fraco.

**Detecção:** amplie as janelas de correlação, modele o acesso periódico a queues e examine o staging no endpoint. O batching transfere o sinal do timing dos pacotes para o comportamento agendado de processos/arquivos; ele não o elimina.

## Design review: think in observers

Para cada path, preencha esta tabela antes do deployment e depois da coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Responsável pela retenção/legal |
|---|---:|---:|---:|---|---|
| rede local/carrier | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autoritativo/registrar | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um provedor comum puder preencher todas as colunas, a arquitetura fornece ocultação em relação ao alvo, mas não uma separação robusta. Se nenhum controller interno puder associar a atividade a um engagement, ela é inadequada para red teaming profissional.

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
- [13] [Google Threat Intelligence Group — Interrompendo a maior rede de proxy residencial do mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — As campanhas Shadow: revelando a espionagem global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
