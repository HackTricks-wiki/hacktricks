# Infraestrutura ofensiva e evasão de atribuição

{{#include ../banners/hacktricks-training.md}}

Um operador raramente obtém anonimato significativo usando apenas um proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, nós de trânsito ocultam esse nó da saída, redirectors protegem o C2 real e nomes descartáveis apontam para a borda pública.

Use o [Catálogo de técnicas de acesso anônimo à Internet](anonymous-internet-access-techniques.md) para uma visão padronizada dos prós, contras, implantação e detecção de cada caminho. Esta página aprofunda a composição de infraestrutura adversarial.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

O último endereço visto por um alvo é, portanto, evidência de um caminho, não prova de quem controlava o teclado. O MITRE mapeia os principais componentes para Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes de infraestrutura

| Classe | Por que um agente a usa | Exposição persistente | Melhor ponto de investigação para o defensor |
|---|---|---|---|
| VPS/cloud alugado | Rápido, previsível, roteável, fácil de reconstruir | histórico de locatário, cobrança, console, logins de origem e imagens | eventos da conta/plano de controle e fingerprint recorrente do servidor |
| VPN comercial/Tor | Grande conjunto compartilhado de saídas; sem administração de servidores | visibilidade do provedor/guard e timing ponta a ponta | comportamento do destino, evidências do endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | registros do broker/cliente; comportamento de proxyware ou host infectado | deslocamentos impossíveis, protocolos de proxy e mudança de endereço por sessão |
| Servidor/roteador/IoT comprometido | Aproveita a reputação e a jurisdição da vítima | implante, fluxo de gerenciamento e controlador upstream recorrente | telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirecionador | Separa a borda pública do C2 de back-end | gramática TLS/HTTP, certificado, roteamento e artefatos da conta cloud | correlação entre borda e origem e agrupamento por formato de requisição |
| Serviço web legítimo | Mistura-se ao tráfego permitido do GitHub/cloud/redes sociais | token de API, identificadores de locatário/objeto e linhagem de processos incomum | processo no endpoint e semântica do serviço/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | registros de RF, operadora, assinante, dispositivo e localização | evidências de rádio/físicas e de rede combinadas |

## Redes operacionais de caixas de retransmissão

Uma **rede ORB** é uma frota de proxies gerenciada e usada como serviço intermediário. A Mandiant as divide em redes provisionadas, compostas por servidores alugados, redes não provisionadas, compostas por roteadores/IoT comprometidos, e redes híbridas. Uma topologia madura tem quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administração (ACOS):** mantém inventário, credenciais, integridade e política de roteamento.
2. **Nó de acesso/retransmissão:** autentica clientes ou operadores; é a entrada estável para uma malha em constante mudança.
3. **Nós de travessia:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Nó de saída/estágio:** apresenta o endereço de origem final para alvos de reconhecimento, exploração ou C2.

A malha pode selecionar saídas por país, ASN, latência ou disponibilidade e substituir nós não saudáveis. Vários grupos de ameaças podem alugar a mesma rede. A Mandiant observou que um endereço IPv4 permaneceu associado a algumas ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade em evolução, semelhante a um agente**, em vez de bloquear uma lista desatualizada de IPs.<sup>[[2]](#references)</sup>

### O que isso oferece — e o que isso leaks

- O alvo vê uma saída que pode estar geograficamente próxima e aparentemente ser residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma malha gerenciada de forma independente pode manter o cliente separado das saídas, mas cria um registro poderoso nas mãos de terceiros.
- Portas recorrentes, ordem dos handshakes, banners de servidor, certificados, períodos de atividade e relações entre controladores podem expor a frota mesmo quando os IPs são rotacionados.
- Um roteador comprometido frequentemente não tem telemetria de endpoint, mas seu ISP ainda tem dados de assinante e de fluxo; uma apreensão revela artefatos de implante/configuração.

{% hint style="info" %}
Para um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos nem dispositivos de terceiros. O [guia de laboratório](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível para o defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxy residencial e móvel

Serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; proxies móveis saem por pools de NAT de operadoras. A oferta pode vir de aparelhos inscritos expressamente, SDKs/proxyware incluídos em aplicativos de consumo, revendedores ou malware. Essas origens não são equivalentes: a falta de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- **rotação por requisição** produz descontinuidades rápidas de IP e ASN/geografia, enquanto a identidade nas camadas superiores permanece estável;
- **sessões persistentes** mantêm uma saída por minutos ou horas, parecendo um assinante comum;
- **gateways de backconnect** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- **pools móveis** colocam muitos assinantes reais atrás de um pequeno conjunto de endereços NAT de operadoras, tornando caro bloquear um IP.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint TLS/cliente, a ordem HTTP, o cookie do dispositivo e o comportamento. Um login residencial supostamente local, seguido por outro país enquanto todos os recursos das camadas superiores permanecem idênticos, é um sinal mais forte do que a reputação isoladamente. Por outro lado, o compartilhamento de endereços e a alternância entre torres móveis geram mudanças legítimas, portanto nunca trate a classificação residencial/de proxy como um veredito.

### Planos de controle de proxyware e sobreposição de revendedores

Não modele um pool residencial como uma lista plana de saídas. A análise do ecossistema IPIDEA revelou um **plano de controle reutilizável de dois níveis**: um SDK incorporado primeiro reporta metadados do dispositivo/inscrição a um domínio Tier One e recebe pares de IP:porta para agendamento e `connect`/`proxy` de Tier Two. O nó consulta periodicamente a porta connect de Tier Two em busca de uma tarefa codificada, abre uma segunda conexão à porta proxy correspondente e retransmite os bytes fornecidos para o destino solicitado. SDKs e marcas de proxy nominalmente diferentes tinham domínios de descoberta separados, mas convergiam na infraestrutura compartilhada de Tier Two e em pools de saída sobrepostos, por meio de relações de propriedade comum e revenda.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Isso produz pivôs de hunting mais duradouros do que um bloco de IP residencial:<sup>[[13]](#references)</sup>

- um processo inesperado de utilitário, VPN, jogo ou dispositivo integrado envia um ID de dispositivo/chave de cliente estável e recebe uma lista de servidores variável;
- o endpoint consulta um IP direto em uma porta incomum e, em seguida, conecta-se imediatamente a outra porta no mesmo endereço antes de abrir um socket para um novo destino;
- várias marcas aparentes compartilham endereços Tier Two, gramática de protocolo, código de SDK ou sobreposição de nós de saída;
- aplicativos distintos que contatam domínios Tier One diferentes recebem endereços do mesmo pool Tier Two.

A sobreposição também limita a atribuição: encontrar um IP no pool anunciado por um fornecedor não estabelece qual revendedor, cliente ou agente de ameaça o usou naquele momento. Preserve os timestamps dos fluxos, a linhagem dos processos, os corpos das respostas Tier One e os identificadores de tarefa Tier Two.<sup>[[13]](#references)</sup> Em um exercício autorizado, simule essa hierarquia apenas com endpoints pertencentes à organização; nunca inscreva dispositivos de consumidores nem proxyware de terceiros.

## Cadeias de proxy multi-hop

O MITRE distingue proxies externos de **multi-hop proxies (T1090.003)**. A propriedade importante não é o número de saltos, mas a separação de conhecimento e administração.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se uma única parte opera A e B, logs compartilhados ou a temporização do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode aumentar a latência, mas mantém evidências comuns de identidade, pagamento e temporização. Tor reduz esse problema com relays selecionados independentemente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode prometer resistência a um observador que mede as duas extremidades.

Falhas comuns incluem bypass de DNS ou IPv6, aplicações que abrem seus próprios sockets, tráfego de gerenciamento que chega diretamente aos relays, atividade sincronizada, chaves SSH reutilizadas e login em contas que identificam o usuário. A verificação correta é um teste de falha: pare cada relay, um por vez, e demonstre que a carga de trabalho não consegue recorrer a uma rota sem criptografia.

### Colapso do túnel e vazamento upstream

Uma arquitetura de relay costuma ser mais fácil de atribuir quando falha. A Unit 42 documentou um caminho de espionagem em várias camadas que usava VPSs voltados às vítimas, VPSs de relay, proxies residenciais, Tor e outros serviços de proxy; quando um túnel era omitido ou colapsava, a infraestrutura upstream oculta se conectava diretamente aos sistemas de relay e aos voltados às vítimas. A mesma investigação também usou um certificado X.509 brevemente exposto na infraestrutura upstream como pivô entre camadas.<sup>[[14]](#references)</sup>

Mantenha o **data plane** (`victim <-> exit`) separado do **control plane** (`operator/upstream -> relay administration`). Retenha logs de entrada e autenticação em cada camada sob seu controle, históricos de certificados e conexões curtas malsucedidas — não apenas sessões de C2 bem-sucedidas. Uma fonte que aparece apenas durante interrupções do relay ou administra diretamente vários nós voltados às vítimas é uma candidata upstream mais forte do que um exit comum, mas seu ASN/geolocalização continua sendo uma hipótese, não uma prova da identidade do operador.

Um laboratório autorizado deve fazer a carga de trabalho falhar de forma segura. Para uma carga de trabalho isolada em um namespace de rede Linux, a primeira rota deve usar o túnel; depois de removê-lo, tanto a solicitação quanto a consulta de rota devem falhar, em vez de selecionar a conexão física upstream:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repita o teste para DNS e IPv6 e em cada limite entre relays. Se alguma sonda for bem-sucedida, registre a interface/endereço de origem real antes de corrigir o roteamento por política ou o firewall; essa observação é o leak de atribuição que um investigador veria.

## Camadas de redirectors e modelagem de tráfego

Um **redirector** público aceita o tráfego que corresponde a uma gramática específica da operação e o encaminha para um team server protegido. Todo o resto pode ser rejeitado ou receber conteúdo inofensivo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Múltiplas camadas limitam a exposição: queimar um domínio público não precisa expor o servidor de equipe. CDNs adicionam capacidade anycast e um domínio externo confiável, mas a conta da CDN e os logs de edge tornam-se pontos de atribuição. Fingerprints TLS, históricos de certificados, caminhos distintos/ordem dos headers, tamanhos de resposta, comportamento de redirecionamento e allowlists de origem podem agrupar fronts supostamente não relacionados.

Para detectar, registre os campos do reverse proxy antes da normalização, compare SNI/Host/authority, inspecione combinações raras de headers, agrupe corpos de resposta e fingerprints TLS e pesquise sobreposições de configuração nos logs de auditoria da nuvem/CDN. Em red teams autorizados, evite copiar uma marca real ou coletar credenciais por meio de terceiros não relacionados.

## Domain fronting e domainless fronting

Com o **domain fronting clássico (T1090.004)**, a conexão TLS anuncia um domínio front permitido no SNI, enquanto o `Host` HTTP criptografado ou `:authority` do HTTP/2 solicita um domínio de back-end diferente. Uma CDN cooperante roteia com base no valor interno. Um observador de rede sem descriptografia TLS vê o front; a CDN vê ambos os valores e a origem. Em variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma imitação mágica: funciona apenas quando o intermediário permite intencionalmente ou por acidente a incompatibilidade e sabe rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) muda o que um observador no caminho consegue ver, mas não apaga os registros da CDN, do endpoint ou da aplicação.

Pontos de detecção incluem:

- ancestralidade do processo no endpoint e destino inesperado para aquela aplicação;
- incompatibilidade entre SNI e HTTP authority, quando a inspeção TLS é legal e disponível;
- logs da CDN mostrando um tenant/front roteando para outra authority/origem;
- sessões incomumente longas ou periódicas com um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados entre diferentes domínios front.

O laboratório seguro simula a incompatibilidade de roteamento em um reverse proxy próprio; não abusa de uma CDN pública.

## Resolução dinâmica: DDNS, DGA e fast flux

A resolução dinâmica desvincula um serviço lógico de uma infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável após a mudança de seu endereço.
- **DGA:** tanto o endpoint quanto o controlador derivam nomes de domínio candidatos a partir de uma seed de tempo/chave; o operador registra um pequeno subconjunto.
- **Fast flux:** um nome retorna um conjunto de endereços comprometidos/de proxy que muda rapidamente, geralmente com TTLs baixos.
- **Double flux:** tanto os endereços do serviço quanto os endereços dos servidores de nomes autoritativos são alternados, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alta quantidade de endereços únicos, ampla dispersão entre ASNs/regiões geográficas, curta duração dos nós, comportamento repetido da aplicação e histórico de registro suspeito. CDNs compartilham legitimamente várias dessas propriedades. A MITRE recomenda correlacionar o comportamento do DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Um DGA pode ser detectado por meio de entropia lexical, padrões de consoantes/dígitos, rajadas de NXDOMAIN, domínios sincronizados vistos pela primeira vez e contexto do processo. DGAs baseados em listas de palavras e modelos generativos frustram regras simples de entropia, tornando mais importantes o agrupamento temporal em toda a frota e a linhagem dos endpoints.

## Domínios comprometidos e domain shadowing

Um ator pode sequestrar uma conta de registrador/DNS, assumir o controle de um subdomínio órfão ou adicionar registros sob um domínio que, de resto, tem boa reputação. **Domain shadowing** mantém o domínio apex legítimo enquanto grandes quantidades de subdomínios controlados pelo atacante apontam para hosts de delivery ou C2 que mudam. Isso aproveita a idade e a reputação do domínio e pode escapar de bloqueios aplicados ao domínio inteiro.<sup>[[6]](#references)</sup>

Os defensores precisam de logs de auditoria do registrador e do DNS autoritativo, MFA, bloqueios de registry/registrar, alertas para novas delegações/tokens de API/servidores de nomes, monitoramento de Certificate Transparency e um inventário dos recursos de nuvem referenciados pelo DNS. Investigue a resolução e o histórico de certificados de um subdomínio independentemente da reputação do domínio apex.

## Web services e dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual dentro de uma publicação, perfil, documento, repositório, objeto na nuvem ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviço.<sup>[[7]](#references)</sup>

Uma variação específica de resolver do GitHub usa a API Issues Search apenas quando um canal autenticado do repositório falha. O cliente pesquisa issues que correspondam à data atual, ao repositório e ao tipo de issue, segue a URL de comentários de cada issue e extrai o texto cifrado entre os marcadores `<!--` e `-->`. Após a descriptografia derivada do host e da data, campos como `Owner`, `LicRepo` e `LicToken` substituem o proprietário, o caminho e o token do repositório principal. Isso permite que o operador alterne credenciais e endpoints sem substituir o cliente; o comentário da issue funciona como resolver, enquanto os arquivos do repositório continuam sendo o canal de tasking.<sup>[[15]](#references)</sup>

Uma variante para Android seleciona uma de duas páginas públicas do Telegram na inicialização e extrai o texto cifrado entre duas ocorrências de um marcador incorporado ao APK. Ela decodifica o valor em Base64URL e o descriptografa com AES-128-CBC: os primeiros 16 bytes de `SHA-256(marker)` são a chave e os 16 bytes restantes são o IV. O texto simples é a URL base real do C2, não a URL da página do Telegram. Preserve o conteúdo da página e o marcador exato ao reproduzir a resolução; alterar a página pública alterna o endpoint sem reconstruir o APK.<sup>[[16]](#references)</sup>

Isso oferece resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repositório, API e padrões de acesso. Os defensores devem correlacionar:

1. o processo que contatou o serviço;
2. o caminho exato da API/objeto e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída logo depois; e
5. o mesmo comportamento em outros pontos da frota.

Bloquear todo o GitHub, armazenamento em nuvem ou redes sociais raramente é viável. Políticas de saída que levam em conta o serviço e a correlação no nível do processo são mais eficazes do que bloqueios baseados apenas em domínio.

## Personas, contas e compartimentos de aquisição

O anonimato da infraestrutura falha quando uma persona, e-mail de recuperação, telefone, forma de pagamento, navegador ou IP de administrador conecta compartimentos. Operações ligadas a Estados cultivaram perfis sociais, identidades de e-mail e contas na nuvem muito antes de usá-los; a ATT&CK registra isso como Establish Accounts (T1585), incluindo sub-técnicas de redes sociais, e-mail e nuvem.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horário de criação e primeiro login, localidade, fuso horário e rotina de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e instrumentos de pagamento;
- fingerprints de navegador/TLS e histórico da rede de origem;
- reutilização de avatar, proveniência de imagens, estilo de escrita e crescimento do grafo social;
- registrante de domínio, servidor de nomes, certificado, ID de analytics ou commit de repositório compartilhados;
- ações no plano de gerenciamento que contornam a arquitetura de relay público.

Para um red team autorizado, personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar se passar por pessoas reais não envolvidas e ter um plano de desativação. O SOC pode continuar sem saber; a operação não pode ficar sem responsabilização.

## Padrões compostos emergentes para modelagem de ameaças

Os exemplos a seguir são **composições orientadas à defesa**, não afirmações de que um ator identificado implantou cada projeto exato. Eles combinam primitivas já observadas e são hipóteses úteis para purple team.

### Tasking unidirecional assimétrico

Os comandos chegam por uma fonte pública, de broadcast ou append-only, enquanto os resultados saem por um canal não relacionado após um atraso. Entre os exemplos da primitiva estão a comunicação unidirecional por web service e os dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de solicitação/resposta.<sup>[[9]](#references)</sup>

**Detecção:** preserve as leituras no nível do objeto e, em seguida, correlacione mudanças de estado do processo e transferências de saída posteriores em uma janela mais ampla. Procure um processo raro que leia o mesmo objeto público, mesmo quando não há resposta imediata.

### Promoção de canal em múltiplos estágios

Um primeiro estágio discreto realiza inventário e só promove sistemas selecionados para um segundo estágio em um canal não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar nenhuma infraestrutura com o primeiro. Isso limita a exposição da infraestrutura de alto potencial e está explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** correlacione `primeiro processo de rede -> estado baixado/configurado -> novo processo ou injeção -> destino não relacionado`; não encerre o incidente após bloquear o primeiro domínio.

### Tradução de relay entre protocolos

Diferentes saltos traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de fila de mensagens, em vez de encaminhar pacotes de forma transparente. A tradução remove um único fingerprint de protocolo ponta a ponta, mas cria gateways com temporização, buffering e conversão semântica distintos. Protocol tunneling (T1572) pode ser combinado com proxies e imitação de serviços.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts gateway que recebem um protocolo e iniciam outro, com comportamento de bytes/tempo fortemente correlacionado; compare a finalidade do endpoint com o protocolo efetivamente transportado.

### Ativação passiva em dispositivos de edge

Em vez de enviar beacons, um implante monitora o tráfego que já chega a um roteador/VPN e é ativado apenas por um valor mágico, padrão de porta de origem ou token autenticado. O tráfego normal continua até o serviço real. A ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados em dispositivos de rede e APTs.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivos, captura de pacotes brutos durante uma investigação autorizada, filtros de socket inesperados e comportamento diferencial do serviço. A ausência de um beacon periódico não prova que um dispositivo de edge esteja limpo.

### Rotação de origem serverless e efêmera

Um front mantém uma identidade lógica estável enquanto funções/contêineres de curta duração processam estágios individuais em várias regiões/contas. Isso reduz a duração dos dados em disco e o uso de IPs de origem fixos, mas os dados de telemetria de criação no plano de controle, imagem/camada, função, segredo, ID de solicitação e faturamento tornam-se o grafo persistente.

**Detecção:** mantenha os logs de auditoria e de invocação da nuvem fora da workload; agrupe templates de deployment, funções, chaves de ambiente e relações entre front e origem.

### Diversidade de camadas de privacidade

Uma operação pode evitar deliberadamente uma cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, uma saída vem de um link celular de laboratório próprio e a administração usa uma rede organizacional separada. Isso reduz o valor de comprometer um único provedor, mas aumenta o risco de correlação temporal entre camadas e de erros operacionais.

**Detecção:** construa linhas do tempo da campanha entre sensores de identidade, DNS, SaaS, rede e nuvem. Procure transições de estado sincronizadas em vez de indicadores idênticos.

### Dead drops descentralizados ou em logs de transparência

Um ator pode inserir um pequeno ponteiro criptografado em qualquer sistema público durável append-only, armazenamento endereçado por conteúdo ou feed semelhante a um de transparência. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de polling do cliente tornam-se identificadores estáveis.

**Detecção:** registre identificadores completos de API/objeto e hashes das respostas; gere alertas para processos não convencionais que consultem objetos imutáveis e, em seguida, executem decodificação ou novas conexões.

### Operações store-and-forward com atraso

O C2 interativo cria forte correlação temporal. Um projeto store-and-forward agrupa tarefas criptografadas e retorna resultados minutos ou horas depois por meio de outra fila ou transferência física. Isso sacrifica a capacidade de resposta em troca de uma correlação temporal ponta a ponta mais fraca.

**Detecção:** amplie as janelas de correlação, modele o acesso periódico às filas e examine o staging nos endpoints. O agrupamento desloca o sinal da temporização dos pacotes para o comportamento agendado de processos/arquivos; não o apaga.

## Revisão de projeto: pense em observadores

Para cada caminho, preencha esta tabela antes da implantação e após a coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Responsável pela retenção/questões legais |
|---|---:|---:|---:|---|---|
| rede local/operadora | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de traversal | | | | | |
| saída/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um único provedor comum puder preencher todas as colunas, a arquitetura oferece ocultação em relação ao alvo, mas não uma separação robusta. Se nenhum controlador interno puder relacionar a atividade a um exercício, a arquitetura não é adequada para red teaming profissional.

## References

- [1] [MITRE ATT&CK — Adquirir infraestrutura (T1583), Comprometer infraestrutura (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Proxy multi-hop (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Comprometer infraestrutura: domínios (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Criar contas (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: comunicação unidirecional (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Canais multiestágio (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulando a maior rede de proxy residencial do mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — As campanhas Shadow: revelando a espionagem global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Campanha Blinder Tunnel tem como alvo a infraestrutura iraquiana](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: a IA criou as sobreposições. As vítimas perdem seus PINs](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
{{#include ../banners/hacktricks-training.md}}
