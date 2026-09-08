# Infraestrutura Ofensiva e Evasão de Atribuição

Um operador raramente obtém anonimato significativo usando um único proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, os nós de trânsito ocultam esse nó do exit, os redirectors protegem o C2 real e nomes descartáveis apontam para a borda pública.

Use o [Catálogo de Técnicas de Acesso Anônimo à Internet](anonymous-internet-access-techniques.md) para obter uma visão normalizada dos prós/contras, da implantação e da detecção de cada caminho. Esta página aprofunda a composição de infraestrutura adversária.
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
| VPN comercial/Tor | Grande conjunto de egress compartilhado; sem administração de servidores | visibilidade do provedor/guard e temporização de ponta a ponta | comportamento do destino, evidências no endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | registros do broker/cliente; comportamento de proxyware ou host infectado | deslocamento impossível, protocolos de proxy e rotatividade de endereços por sessão |
| Servidor/roteador/IoT comprometido | Toma emprestadas a reputação e a jurisdição da vítima | implant, fluxo de gerenciamento e controlador upstream recorrente | telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirector | Separa a edge pública do C2 de back-end | gramática TLS/HTTP, certificado, roteamento e artefatos da conta cloud | correlação edge-to-origin e agrupamento por formato das requisições |
| Serviço web legítimo | Mistura-se ao tráfego permitido do GitHub/cloud/social | token de API, identificadores de tenant/objeto e linhagem incomum de processos | processo do endpoint junto da semântica do serviço/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | registros de RF, operadora, assinante, dispositivo e localização | evidências de rádio/físicas e de rede combinadas |

## Redes de caixas de relay operacionais

Uma **rede ORB** é uma frota de proxies gerenciada, usada como serviço intermediário. A Mandiant as divide em redes provisionadas de servidores alugados, redes não provisionadas de roteadores/IoT comprometidos e híbridas. Uma topologia madura possui quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administração (ACOS):** mantém inventário, credenciais, integridade e política de roteamento.
2. **Nó de acesso/relay:** autentica clientes ou operadores; é a entrada estável para uma mesh em constante mudança.
3. **Nós de traversal:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Nó de saída/staging:** apresenta o endereço de origem final para reconhecimento, exploração ou alvos de C2.

A mesh pode selecionar saídas por país, ASN, latência ou disponibilidade e alternar nós que não estejam saudáveis. Vários grupos de ameaças podem alugar a mesma rede. A Mandiant observou um endereço IPv4 permanecer associado a alguns ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade em evolução semelhante a um ator**, em vez de bloquear uma lista obsoleta de IPs.<sup>[[2]](#references)</sup>

### O que isso proporciona — e o que isso vaza

- O alvo vê uma saída que pode estar geograficamente próxima e aparentemente ser residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma mesh gerenciada de forma independente pode manter o cliente separado das saídas, mas cria um registro poderoso da contraparte.
- Portas repetidas, ordem do handshake, banners de servidor, certificados, janelas de disponibilidade e relações com controladores podem expor a frota mesmo enquanto os IPs alternam.
- Um roteador comprometido frequentemente não possui telemetria do endpoint, mas seu ISP ainda tem dados do assinante e dos fluxos; uma apreensão expõe artefatos do implant/configuração.

{% hint style="info" %}
Para um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos nem dispositivos de terceiros. O [guia do laboratório](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível ao defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxies residenciais e móveis

Os serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; os proxies móveis fazem egress por pools de NAT de operadoras. A oferta pode vir de dispositivos expressamente inscritos, SDK/proxyware incorporado a aplicações de consumo, revendedores ou malware. Essas origens não são equivalentes: a falta de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- **rotação por requisição** produz rápidas descontinuidades de IP e ASN/geografia enquanto a identidade nas camadas superiores permanece estável;
- **sessões sticky** mantêm uma saída por minutos ou horas, parecendo um assinante comum;
- **gateways backconnect** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- **pools móveis** colocam muitos assinantes legítimos atrás de um pequeno conjunto de endereços NAT de operadora, tornando caro bloquear um IP.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint de TLS/cliente, a ordenação HTTP, o cookie do dispositivo e o comportamento. Um login residencial supostamente local seguido por outro país, enquanto todos os recursos das camadas superiores permanecem idênticos, é um indicador mais forte do que a reputação isolada. Por outro lado, o compartilhamento de endereços e a transferência entre torres móveis geram rotação legítima; portanto, nunca trate a classificação residencial/de proxy como um veredito.

## Cadeias de proxy multi-hop

O MITRE distingue proxies externos de **proxies multi-hop (T1090.003)**. A propriedade importante não é a quantidade de hops, mas a separação entre conhecimento e administração.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Se uma das partes opera A e B, logs compartilhados ou a temporização do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode aumentar a latência, mas ainda deixar evidências comuns de identidade, pagamento e temporização. Tor reduz esse problema com relays selecionados de forma independente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode prometer resistência contra um observador que mede ambas as extremidades.

Falhas comuns incluem bypass de DNS ou IPv6, aplicações abrindo seus próprios sockets, tráfego de gerenciamento chegando diretamente aos relays, atividade sincronizada, chaves SSH reutilizadas e login em contas identificáveis. A verificação correta é um teste de falha: pare cada relay, um por vez, e mostre que a carga de trabalho não pode recorrer a um caminho não protegido.

## Camadas de redirectors e modelagem de tráfego

Um **redirector** público aceita tráfego que corresponda a uma gramática específica da operação e o encaminha para um servidor protegido da equipe. Todo o restante pode ser rejeitado ou receber conteúdo inofensivo.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Múltiplas camadas limitam a exposição: queimar um domínio público não precisa expor o team server. CDNs adicionam capacidade anycast e um domínio externo respeitável, mas a conta da CDN e os logs de edge tornam-se pontos de atribuição. TLS fingerprints, históricos de certificados, paths distintos/ordem de headers, tamanhos de resposta, comportamento de redirecionamento e allowlists de origem podem agrupar fronts supostamente não relacionados.

Para detecção, registre os campos do reverse proxy antes da normalização, compare SNI/Host/authority, inspecione combinações raras de headers, agrupe corpos de resposta e TLS fingerprints, e pesquise nos logs de auditoria da cloud/CDN por sobreposição de configurações. Para red teams autorizados, evite copiar uma marca real ou colocar coleta de credenciais atrás de um terceiro não relacionado.

## Domain fronting e domainless fronting

Com o **domain fronting (T1090.004)** clássico, a conexão TLS anuncia um domínio front permitido no SNI, enquanto o `Host` HTTP criptografado ou `:authority` do HTTP/2 solicita um domínio de back-end diferente. Uma CDN cooperante roteia com base no valor interno. Um observador de rede sem descriptografia TLS vê o front; a CDN vê ambos os valores e a origem. Nas variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma personificação mágica: funciona somente quando o intermediário permite intencionalmente ou acidentalmente a divergência e sabe como rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) altera o que um observador no caminho pode ver, mas não elimina os registros da CDN, do endpoint ou da aplicação.

Os pontos de detecção incluem:

- ancestralidade do processo no endpoint e destino não esperado para aquela aplicação;
- divergência entre SNI e autoridade HTTP quando a inspeção TLS é legal e está disponível;
- logs da CDN mostrando um tenant/front roteando para outra autoridade/origem;
- sessões incomumente longas ou periódicas com um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados entre diferentes front domains.

O lab seguro simula a divergência de roteamento em um reverse proxy próprio; ele não abusa de uma CDN pública.

## Resolução dinâmica: DDNS, DGA e fast flux

A resolução dinâmica desacopla um serviço lógico da infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável depois que seu endereço muda.
- **DGA:** tanto o endpoint quanto o controller derivam nomes de domínio candidatos a partir de uma seed de tempo/chave; o operador registra um pequeno subconjunto.
- **Fast flux:** um nome retorna um conjunto que muda rapidamente de endereços comprometidos/proxy, geralmente com TTLs baixos.
- **Double flux:** tanto os endereços de serviço quanto os endereços dos name servers autoritativos sofrem rotação, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alta contagem de endereços únicos, ampla dispersão de ASN/geografia, vida útil curta dos nós, comportamento repetido da aplicação e histórico de registro suspeito. CDNs compartilham legitimamente várias dessas propriedades. A MITRE recomenda correlacionar o comportamento DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Um DGA pode ser detectado por meio de entropia léxica, padrões de consoantes/dígitos, rajadas de NXDOMAIN, domínios vistos pela primeira vez de forma sincronizada e contexto do processo. DGAs baseados em wordlists e modelos generativos derrotam regras simples de entropia, tornando mais importantes o agrupamento temporal em toda a frota e a linhagem do endpoint.

## Domínios comprometidos e domain shadowing

Um ator pode sequestrar uma conta de registrador/DNS, assumir o controle de um subdomínio abandonado ou adicionar registros sob um domínio que, de outra forma, seria respeitável. O **domain shadowing** preserva o apex legítimo enquanto grandes quantidades de subdomínios controlados pelo atacante apontam para hosts de delivery ou C2 em mudança. Ele aproveita idade e reputação e pode evitar bloqueios aplicados a todo o domínio.<sup>[[6]](#references)</sup>

Os defensores precisam de logs de auditoria do registrador e do DNS autoritativo, MFA, bloqueios de registry/registrar, alertas para novas delegações/tokens de API/name servers, monitoramento de certificate transparency e um inventário dos recursos de cloud referenciados pelo DNS. Investigue a resolução e o histórico de certificados de um subdomínio independentemente da reputação do apex.

## Web services e dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual dentro de uma postagem, perfil, documento, repository, objeto de cloud ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviços.<sup>[[7]](#references)</sup>

Isso oferece resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repository, API e padrão de acesso. Os defensores devem relacionar:

1. o processo que contatou o serviço;
2. o path exato da API/objeto e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída logo depois; e
5. o comportamento idêntico em outros pontos da frota.

Bloquear todo o GitHub, cloud storage ou redes sociais raramente é viável. A política de egress ciente do serviço e a correlação no nível do processo superam o bloqueio baseado apenas em domínio.

## Personas, contas e compartimentos de procurement

O anonimato da infraestrutura falha quando uma persona, email de recuperação, telefone, pagamento, browser ou IP de administração conecta compartimentos. Operações vinculadas a Estados cultivaram perfis sociais, identidades de email e contas de cloud muito antes do uso; a ATT&CK registra isso como Establish Accounts (T1585), incluindo as sub-técnicas social, email e cloud.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horário de criação e primeiro login, localidade, fuso horário e agenda de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e instrumentos de pagamento;
- TLS fingerprints do browser e histórico da rede de origem;
- reutilização de avatar, procedência de imagens, estilo de escrita e crescimento do grafo social;
- registrante de domínio, name server, certificado, ID de analytics ou commit de repository compartilhado;
- ações no plano de gerenciamento que contornam a arquitetura pública de relay.

Para um red team autorizado, personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar personificar pessoas reais não envolvidas e ter uma aposentadoria planejada. O SOC pode permanecer cego; a operação não deve se tornar sem responsabilização.

## Padrões compostos emergentes para modelar como ameaça

Os itens a seguir são **composições orientadas pelo defensor**, não afirmações de que um ator identificado tenha implantado cada design exato. Eles combinam primitivas já observadas e são hipóteses úteis para purple teams.

### Tasking assimétrico unidirecional

Os comandos chegam por uma fonte pública, de broadcast ou append-only, enquanto os resultados saem por um canal não relacionado após um atraso. Exemplos da primitiva incluem comunicação unidirecional por web service e dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de solicitação/resposta.<sup>[[9]](#references)</sup>

**Detecção:** preserve leituras no nível do objeto e correlacione alterações no estado do processo e transferências de saída posteriores em uma janela mais ampla. Procure um processo raro lendo o mesmo objeto público mesmo quando nenhuma resposta imediata ocorre.

### Promoção de canal em múltiplos estágios

Um primeiro estágio discreto realiza inventário e promove apenas sistemas selecionados para um segundo canal não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar nenhuma infraestrutura com o primeiro. Isso limita a exposição da infraestrutura capaz e é explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** relacione `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; não encerre o incidente depois de bloquear o primeiro domínio.

### Tradução de relay entre protocolos

Hops diferentes traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de message queue em vez de encaminhar pacotes de forma transparente. A tradução remove um único fingerprint de protocolo de ponta a ponta, mas cria gateways com timing, buffering e conversão semântica distintos. Protocol tunneling (T1572) pode ser combinado com proxies e service impersonation.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts gateway que recebem um protocolo e iniciam outro com comportamento de bytes/tempo fortemente acoplado; compare a intenção do endpoint com o protocolo realmente transportado.

### Ativação passiva em dispositivos edge

Em vez de beaconing, um implant monitora tráfego que já chega a um router/VPN e ativa somente diante de um valor mágico, padrão de porta de origem ou token autenticado. O tráfego normal continua para o serviço real. A ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados de dispositivos de rede e APTs.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivos, captura de pacotes brutos durante um hunt autorizado, filtros de socket inesperados e comportamento diferencial do serviço. A ausência de um beacon periódico não prova que um dispositivo edge esteja limpo.

### Rotação de origem serverless e efêmera

Um front mantém uma identidade lógica estável enquanto functions/containers de curta duração lidam com estágios individuais em várias regiões/contas. Isso reduz a vida útil em disco e os IPs de origem fixos, mas a criação no plano de controle, a imagem/layer, a role, o secret, o request ID e a telemetria de billing tornam-se o grafo durável.

**Detecção:** retenha logs de auditoria e invocação da cloud fora do workload; agrupe templates de deployment, roles, chaves de ambiente e relações entre front e origem.

### Diversidade de camadas de privacidade

Uma operação pode deliberadamente evitar uma cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, uma saída vem de um link celular próprio de lab e a administração usa uma rede separada da organização. Isso reduz o valor de comprometer um provedor, mas aumenta o risco de correlação temporal entre camadas e de erros operacionais.

**Detecção:** construa timelines da campanha entre sensores de identidade, DNS, SaaS, rede e cloud. Procure transições de estado sincronizadas, em vez de indicadores idênticos.

### Dead drops descentralizados ou em logs de transparência

Um ator pode colocar um pequeno ponteiro criptografado em qualquer sistema público durável append-only, armazenamento content-addressed ou feed semelhante a um log de transparência. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de polling do cliente tornam-se identificadores estáveis.

**Detecção:** registre identificadores completos de API/objeto e hashes de resposta; alerte sobre processos não padronizados fazendo polling de objetos imutáveis seguidos de decodificação ou novas conexões.

### Operações store-and-forward atrasadas

O C2 interativo cria uma forte correlação temporal. Um design store-and-forward agrupa jobs criptografados e retorna resultados minutos ou horas depois por meio de outra queue ou transferência física. Ele sacrifica capacidade de resposta para obter uma correlação temporal de ponta a ponta mais fraca.

**Detecção:** amplie as janelas de correlação, modele o acesso periódico à queue e examine o staging no endpoint. O batching desloca o sinal do timing de pacotes para o comportamento programado de processos/arquivos; ele não o elimina.

## Revisão de design: pense nos observadores

Para cada caminho, preencha esta tabela antes do deployment e depois da coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Responsável pela retenção/legal |
|---|---:|---:|---:|---|---|
| rede local/carrier | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de traversal | | | | | |
| exit/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um único provedor comum puder preencher todas as colunas, a arquitetura oferece ocultação em relação ao alvo, mas não uma separação robusta. Se nenhum controller interno puder relacionar a atividade a um engagement, ela é inadequada para red teaming profissional.

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
