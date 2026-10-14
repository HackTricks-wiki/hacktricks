# Infraestrutura Ofensiva e Evasão de Atribuição

{{#include ../banners/hacktricks-training.md}}

Um operador raramente consegue anonimato significativo usando apenas um proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, nós de trânsito ocultam esse nó do nó de saída, redirectors protegem o C2 real, e nomes descartáveis apontam para a borda pública.

Use o [Catálogo de Técnicas de Acesso Anônimo à Internet](anonymous-internet-access-techniques.md) para consultar uma visão normalizada de prós/contras/implantação/detecção de cada caminho. Esta página aprofunda a composição de infraestrutura adversarial.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

O último endereço visto por um alvo é, portanto, evidência de um caminho, não prova de quem controlava o teclado. O MITRE mapeia os principais componentes para Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes de infraestrutura

| Classe | Por que um ator a usa | Exposição duradoura | Melhor ponto de pivô para o defensor |
|---|---|---|---|
| VPS/cloud alugado | Rápido, previsível, roteável, fácil de reconstruir | histórico de tenant, cobrança, console, login de origem e imagens | eventos da conta/plano de controle e fingerprint recorrente do servidor |
| VPN comercial/Tor | Grande conjunto compartilhado de saídas; sem administração de servidores | visibilidade do provedor/guard e temporização de ponta a ponta | comportamento do destino, evidências do endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | registros de broker/cliente; comportamento de proxyware ou host infectado | deslocamento impossível, protocolos de proxy e mudança de endereço por sessão |
| Servidor/roteador/IoT comprometido | Aproveita a reputação e a jurisdição da vítima | implant, fluxo de gerenciamento e controlador upstream recorrente | telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirector | Separa o edge público do C2 de back-end | artefatos de TLS/gramática HTTP, certificado, roteamento e conta cloud | correlação entre edge e origem e agrupamento por formato de requisição |
| Serviço web legítimo | Mistura-se ao tráfego permitido de GitHub/cloud/social | token de API, identificadores de tenant/objeto e linhagem incomum de processos | processo no endpoint e semântica do serviço/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | registros de RF, operadora, assinante, dispositivo e localização | evidências de rádio/físicas e de rede combinadas |

## Redes operacionais de nós de retransmissão

Uma **rede ORB** é uma frota de proxies gerenciada e usada como serviço intermediário. A Mandiant as divide em redes provisionadas de servidores alugados, redes não provisionadas de roteadores/IoT comprometidos e redes híbridas. Uma topologia madura tem quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administração (ACOS):** mantém inventário, credenciais, integridade e política de roteamento.
2. **Nó de acesso/retransmissão:** autentica clientes ou operadores; é a entrada estável para uma malha em constante mudança.
3. **Nós de travessia:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Nó de saída/estágio:** apresenta o endereço de origem final para alvos de reconhecimento, exploração ou C2.

A malha pode selecionar saídas por país, ASN, latência ou disponibilidade e substituir nós com problemas. Vários grupos de ameaças podem alugar a mesma rede. A Mandiant observou que um endereço IPv4 permaneceu associado a algumas ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade em evolução, semelhante a um ator**, em vez de bloquear uma lista desatualizada de IPs.<sup>[[2]](#references)</sup>

### O que isso oferece — e o que isso revela

- O alvo vê uma saída que pode estar geograficamente próxima e parecer residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma malha gerenciada de forma independente pode manter o cliente separado das saídas, mas gera um registro poderoso nas mãos de terceiros.
- Portas recorrentes, ordem de handshake, banners de servidor, certificados, períodos de atividade e relações entre controladores podem revelar a frota mesmo quando os IPs mudam.
- Um roteador comprometido frequentemente não tem telemetria de endpoint, mas seu ISP ainda possui dados de assinante e de fluxo; uma apreensão revela artefatos de implant/configuração.

{% hint style="info" %}
Para um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos nem dispositivos de terceiros. O [guia do laboratório](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível para o defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxy residencial e móvel

Serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; proxies móveis fazem a saída por pools de NAT de operadoras. A oferta pode vir de dispositivos inscritos explicitamente, SDKs/proxyware incluídos em aplicativos de consumo, revendedores ou malware. Essas origens não são equivalentes: a falta de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- a **rotação por requisição** produz mudanças rápidas de IP e de ASN/localização geográfica enquanto a identidade de camadas superiores permanece estável;
- **sessões persistentes** mantêm uma saída por minutos ou horas, parecendo um assinante comum;
- **gateways de backconnect** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- **pools móveis** colocam muitos assinantes reais atrás de um pequeno conjunto de endereços NAT de operadoras, tornando custoso bloquear um IP.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint de TLS/cliente, a ordem HTTP, o cookie do dispositivo e o comportamento. Um login supostamente local e residencial, seguido por outro de um país diferente enquanto todos os recursos de camadas superiores permanecem idênticos, é um sinal mais forte do que a reputação isoladamente. Por outro lado, o compartilhamento de endereços e a troca de células móveis geram mudanças legítimas, portanto, nunca trate a classificação residencial/de proxy como uma conclusão definitiva.

### Planos de controle de proxyware e sobreposição de revendedores

Não modele um pool residencial como uma lista plana de saídas. A análise do ecossistema IPIDEA revelou um **plano de controle reutilizável em duas camadas**: um SDK incorporado primeiro informa metadados do dispositivo/inscrição a um domínio Tier One e recebe pares IP:porta de agendamento e `connect`/`proxy` da Tier Two. O nó consulta periodicamente a porta de conexão da Tier Two em busca de uma tarefa codificada, abre uma segunda conexão à porta de proxy correspondente e retransmite os bytes fornecidos ao destino solicitado. SDKs e marcas de proxy aparentemente distintos tinham domínios de descoberta separados, mas convergiam para uma infraestrutura compartilhada da Tier Two e pools de saída sobrepostos por meio de relações de propriedade comum e revenda.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Isso produz pivôs de hunting mais duráveis do que um bloco de IP residencial:<sup>[[13]](#references)</sup>

- um processo inesperado de utilitário, VPN, jogo ou dispositivo embarcado envia um ID estável do dispositivo/chave do cliente e recebe uma lista de servidores variável;
- o endpoint consulta um IP direto em uma porta incomum e, em seguida, conecta-se a outra porta no mesmo endereço imediatamente antes de abrir um novo socket de destino;
- várias marcas aparentes compartilham endereços Tier Two, gramática de protocolo, código de SDK ou sobreposição de nós de saída;
- aplicações distintas que contatam diferentes domínios Tier One recebem endereços do mesmo pool Tier Two.

Essa sobreposição também limita a atribuição: ver um IP no pool anunciado por um fornecedor não comprova qual revendedor, cliente ou threat actor o usou no momento relevante. Preserve os timestamps de fluxo, a linhagem dos processos, os corpos das respostas Tier One e os identificadores de tarefa Tier Two.<sup>[[13]](#references)</sup> Em um exercício autorizado, emule essa hierarquia apenas com endpoints pertencentes à organização; nunca inscreva dispositivos de consumidores ou proxyware de terceiros.

## Cadeias de proxy multi-hop

O MITRE distingue proxies externos de **proxies multi-hop (T1090.003)**. A propriedade importante não é o número de saltos, mas a separação de conhecimento e administração.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se uma das partes operar A e B, logs compartilhados ou o timing do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode aumentar a latência sem eliminar evidências comuns de identidade, pagamento e timing. Tor reduz esse problema com relays selecionados de forma independente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode garantir resistência contra um observador que mede as duas extremidades.

Falhas comuns incluem bypass de DNS ou IPv6, aplicações abrindo seus próprios sockets, tráfego de gerenciamento chegando diretamente aos relays, atividade sincronizada, chaves SSH reutilizadas e login em contas que permitem identificar o usuário. A verificação correta é um teste de falha: pare cada relay, um de cada vez, e confirme que a carga de trabalho não pode recorrer a um caminho sem criptografia.

### Colapso do túnel e vazamento upstream

Uma arquitetura de relays costuma ser mais fácil de atribuir quando falha. A Unit 42 documentou um caminho de espionagem multinível que usava VPSs voltados às vítimas, VPSs de relay, proxies residenciais, Tor e outros serviços de proxy; quando um túnel era omitido ou colapsava, a infraestrutura upstream oculta se conectava diretamente aos sistemas de relay e voltados às vítimas. A mesma investigação também usou um certificado X.509 brevemente exposto na infraestrutura upstream como pivô entre níveis.<sup>[[14]](#references)</sup>

Mantenha o **plano de dados** (`victim <-> exit`) separado do **plano de controle** (`operator/upstream -> relay administration`). Retenha logs de entrada e autenticação em cada nível sob seu controle, históricos de certificados e conexões malsucedidas de curta duração — não apenas sessões C2 bem-sucedidas. Uma origem que aparece apenas durante interrupções dos relays ou administra diretamente vários nós voltados às vítimas é uma candidata upstream mais provável do que um exit comum, mas seu ASN/geolocalização continua sendo uma hipótese, não uma prova da identidade do operador.

Um laboratório autorizado deve fazer a carga de trabalho falhar de forma fechada. Para uma carga de trabalho isolada em um namespace de rede Linux, a primeira rota deve usar o túnel; depois de removê-lo, tanto a solicitação quanto a consulta de rota devem falhar, em vez de selecionar a conexão física:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repita o teste para DNS e IPv6 e em cada limite entre relays. Se alguma sondagem for bem-sucedida, registre a interface/endereço de origem real antes de corrigir o roteamento por política ou o firewall; essa observação é o leak de atribuição que um investigador veria.

## Camadas de redirectors e modelagem de tráfego

Um **redirector** público aceita o tráfego que corresponde a uma gramática específica da operação e o encaminha para um team server protegido. Todo o restante pode ser rejeitado ou receber conteúdo inofensivo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Múltiplas camadas limitam a exposição: queimar um domínio público não precisa expor o servidor da equipe. CDNs adicionam capacidade anycast e um domínio externo confiável, mas a conta da CDN e os logs de borda tornam-se pontos de atribuição. Fingerprints TLS, históricos de certificados, caminhos distintos/ordem de cabeçalhos, tamanhos de resposta, comportamento de redirecionamento e listas de permissões da origem podem agrupar front-ends supostamente não relacionados.

Para detecção, registre os campos do proxy reverso antes da normalização, compare SNI/Host/authority, inspecione combinações incomuns de cabeçalhos, agrupe corpos de resposta e fingerprints TLS e pesquise sobreposições de configuração nos logs de auditoria de cloud/CDN. Em red teams autorizados, evite copiar uma marca real ou colocar a coleta de credenciais atrás de um terceiro sem relação com a operação.

## Domain fronting e domainless fronting

No **domain fronting (T1090.004)** clássico, a conexão TLS anuncia um domínio frontal permitido no SNI, enquanto o `Host` HTTP ou `:authority` HTTP/2 criptografado solicita um domínio de back-end diferente. Uma CDN cooperante roteia com base no valor interno. Um observador de rede sem descriptografia TLS vê o domínio frontal; a CDN vê ambos os valores e a origem. Em variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma imitação mágica: só funciona quando o intermediário permite intencionalmente ou por acidente a incompatibilidade e sabe rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) muda o que um observador no caminho pode ver, mas não apaga os registros da CDN, do endpoint ou da aplicação.

Os pontos de detecção incluem:

- ancestralidade dos processos do endpoint e destino inesperado para aquela aplicação;
- incompatibilidade entre SNI e authority HTTP, quando a inspeção TLS é legal e está disponível;
- logs da CDN que mostram um tenant/front roteando para outra authority/origem;
- sessões incomumente longas ou periódicas com um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados em diferentes domínios frontais.

O laboratório seguro simula a incompatibilidade de roteamento em um proxy reverso próprio; não abusa de uma CDN pública.

## Resolução dinâmica: DDNS, DGA e fast flux

A resolução dinâmica desvincula um serviço lógico de uma infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável quando seu endereço muda.
- **DGA:** tanto o endpoint quanto o controlador derivam possíveis nomes de domínio a partir de uma seed temporal/chave; o operador registra uma pequena parte deles.
- **Fast flux:** um nome retorna um conjunto que muda rapidamente de endereços comprometidos/de proxy, geralmente com TTLs baixos.
- **Double flux:** tanto os endereços do serviço quanto os endereços dos servidores de nomes autoritativos são alternados, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alto número de endereços únicos, grande dispersão de ASN/geográfica, curta duração dos nós, comportamento repetido da aplicação e histórico de registro suspeito. CDNs apresentam legitimamente várias dessas características. A MITRE recomenda correlacionar o comportamento DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Um DGA pode ser detectado por entropia lexical, padrões de consoantes/dígitos, picos de NXDOMAIN, domínios vistos pela primeira vez de forma sincronizada e contexto do processo. DGAs baseados em listas de palavras e modelos generativos contornam regras simples de entropia, tornando mais importantes o agrupamento temporal em toda a frota e a linhagem do endpoint.

## Domínios comprometidos e domain shadowing

Um agente pode sequestrar uma conta de registrador/DNS, assumir um subdomínio abandonado ou adicionar registros sob um domínio que, de outro modo, seria confiável. **Domain shadowing** mantém o domínio apex legítimo enquanto aponta grandes quantidades de subdomínios controlados pelo atacante para hosts de entrega ou C2 que mudam. Isso aproveita a idade e a reputação do domínio e pode escapar de bloqueios aplicados ao domínio inteiro.<sup>[[6]](#references)</sup>

Os defensores precisam de logs de auditoria do registrador e do DNS autoritativo, MFA, bloqueios de registry/registrar, alertas para novas delegações/tokens de API/servidores de nomes, monitoramento de Certificate Transparency e um inventário dos recursos de cloud referenciados pelo DNS. Investigue a resolução e o histórico de certificados de um subdomínio separadamente da reputação do domínio apex.

## Web services e dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual em uma publicação, perfil, documento, repositório, objeto de cloud ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviço.<sup>[[7]](#references)</sup>

Uma variação específica de resolver do GitHub usa a API de busca de Issues somente quando um canal autenticado do repositório falha. O cliente busca issues que correspondam à data atual, ao repositório e ao tipo de issue, segue a URL dos comentários de cada issue e extrai o texto cifrado entre os marcadores `<!--` e `-->`. Após a descriptografia derivada da data e específica de cada host, campos como `Owner`, `LicRepo` e `LicToken` substituem o proprietário, o caminho e o token do repositório principal. Isso permite que o operador alterne credenciais e endpoints sem substituir o cliente; o comentário da issue funciona como resolver, enquanto os arquivos do repositório continuam sendo o canal de tasking.<sup>[[15]](#references)</sup>

Isso aumenta a resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repositório, API e padrões de acesso. Os defensores devem correlacionar:

1. o processo que contatou o serviço;
2. o caminho exato da API/objeto e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída pouco depois; e
5. o mesmo comportamento em outros pontos da frota.

Bloquear todo o GitHub, armazenamento em cloud ou redes sociais raramente é viável. Políticas de saída com reconhecimento do serviço e correlação no nível do processo são mais eficazes do que bloqueios baseados apenas em domínio.

## Personas, contas e compartimentos de aquisição

O anonimato da infraestrutura falha quando uma persona, e-mail de recuperação, telefone, pagamento, navegador ou IP de administração conecta compartimentos. Operações ligadas a Estados cultivaram perfis sociais, identidades de e-mail e contas de cloud muito antes de usá-los; a ATT&CK registra isso como Establish Accounts (T1585), incluindo sub-técnicas de redes sociais, e-mail e cloud.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horário de criação e primeiro login, localidade, fuso horário e rotina de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e meios de pagamento;
- fingerprints de navegador/TLS e histórico da rede de origem;
- reutilização de avatares, origem de imagens, estilo de escrita e crescimento do grafo social;
- registrante de domínio, servidor de nomes, certificado, ID de analytics ou commit de repositório compartilhados;
- ações no plano de gerenciamento que contornam a arquitetura de retransmissão pública.

Para um red team autorizado, as personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar se passar por pessoas reais sem relação com a operação e ter uma retirada planejada. O SOC pode permanecer sem saber; a operação não pode deixar de ser responsabilizável.

## Padrões compostos emergentes para modelagem de ameaças

As composições a seguir são **combinações orientadas à defesa**, não afirmações de que um agente identificado tenha implantado cada projeto exato. Elas combinam primitivas já observadas e são hipóteses úteis para purple teams.

### Tasking assimétrico unidirecional

Os comandos chegam por uma fonte pública, de transmissão ou somente de acréscimo, enquanto os resultados saem por um canal não relacionado após um atraso. Entre os exemplos dessa primitiva estão a comunicação unidirecional por web service e os dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de solicitação/resposta.<sup>[[9]](#references)</sup>

**Detecção:** preserve leituras no nível do objeto e, em seguida, correlacione alterações de estado do processo e transferências de saída posteriores em uma janela de tempo mais ampla. Procure um processo incomum lendo o mesmo objeto público, mesmo quando não houver resposta imediata.

### Promoção de canal em múltiplos estágios

Um primeiro estágio discreto faz inventário e só promove sistemas selecionados para um canal de segundo estágio não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar infraestrutura alguma com o primeiro. Isso limita a exposição da infraestrutura mais sofisticada e é explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** correlacione `primeiro processo de rede -> estado baixado/configurado -> novo processo ou injeção -> destino não relacionado`; não encerre o incidente depois de bloquear o primeiro domínio.

### Tradução de retransmissão entre protocolos

Saltos diferentes traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de fila de mensagens, em vez de encaminhar pacotes de forma transparente. A tradução remove um único fingerprint de protocolo ponta a ponta, mas cria gateways com temporização, buffering e conversão semântica distintos. O protocol tunneling (T1572) pode ser combinado com proxies e impersonação de serviços.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts de gateway que recebem um protocolo e iniciam outro com comportamento de bytes/tempo fortemente correlacionado; compare a intenção do endpoint com o protocolo efetivamente transportado.

### Ativação passiva em dispositivos de borda

Em vez de enviar beacons, um implante monitora o tráfego que já chega a um roteador/VPN e é ativado apenas por um valor mágico, padrão de porta de origem ou token autenticado. O tráfego normal continua chegando ao serviço real. A ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados em dispositivos de rede e APTs.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivos, captura bruta de pacotes durante uma investigação autorizada, filtros de socket inesperados e comportamento diferencial do serviço. A ausência de um beacon periódico não prova que um dispositivo de borda esteja limpo.

### Rotação de origem serverless e efêmera

Um front mantém uma identidade lógica estável enquanto funções/contêineres de curta duração processam estágios individuais em várias regiões/contas. Isso reduz o tempo de permanência em disco e o uso de IPs de origem fixos, mas a criação no plano de controle, imagem/camada, função, segredo, ID de solicitação e telemetria de cobrança tornam-se o grafo duradouro.

**Detecção:** retenha os logs de auditoria e de invocação da cloud fora da workload; agrupe templates de implantação, funções, chaves de ambiente e relações entre front e origem.

### Diversidade de camadas de privacidade

Uma operação pode evitar deliberadamente uma única cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, uma saída usa um link celular de laboratório próprio e a administração usa uma rede separada da organização. Isso reduz o valor de comprometer um único provedor, mas aumenta o risco de correlação temporal entre camadas e de erros operacionais.

**Detecção:** crie cronologias da campanha a partir de sensores de identidade, DNS, SaaS, rede e cloud. Procure transições de estado sincronizadas, em vez de indicadores idênticos.

### Dead drops descentralizados ou em logs de transparência

Um agente pode colocar um pequeno ponteiro criptografado em qualquer sistema público durável de acréscimo somente, armazenamento endereçável por conteúdo ou feed semelhante a um log de transparência. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de consulta do cliente tornam-se identificadores estáveis.

**Detecção:** registre identificadores completos de API/objeto e hashes de resposta; gere alertas quando processos não convencionais consultarem objetos imutáveis e, em seguida, decodificarem dados ou iniciarem novas conexões.

### Operações adiadas de store-and-forward

O C2 interativo cria uma forte correlação temporal. Um projeto store-and-forward agrupa tarefas criptografadas e retorna resultados minutos ou horas depois, por meio de outra fila ou transferência física. Sacrifica a capacidade de resposta em favor de uma correlação temporal ponta a ponta mais fraca.

**Detecção:** amplie as janelas de correlação, modele o acesso periódico às filas e examine o staging no endpoint. O agrupamento transfere o sinal da temporização dos pacotes para o comportamento agendado de processos/arquivos; não o elimina.

## Revisão de projeto: pense nos observadores

Para cada caminho, preencha esta tabela antes da implantação e depois da coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Retenção/responsável legal |
|---|---:|---:|---:|---|---|
| rede local/operadora | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de trânsito | | | | | |
| saída/redirecionador/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um provedor comum puder preencher todas as colunas, a arquitetura oculta a atividade do alvo, mas não oferece uma separação robusta. Se nenhum controlador interno puder vincular a atividade a um exercício, a arquitetura não é adequada para red teaming profissional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestrutura (T1583), Comprometer infraestrutura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-hop (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestrutura: domínios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Estabelecer contas (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicação unidirecional (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canais multiestágio (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Tunelamento de protocolo (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Sinalização de tráfego (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulando a maior rede de proxy residencial do mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — As campanhas Shadow: revelando a espionagem global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Campanha Blinder Tunnel tem como alvo a infraestrutura do Iraque](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
{{#include ../banners/hacktricks-training.md}}
