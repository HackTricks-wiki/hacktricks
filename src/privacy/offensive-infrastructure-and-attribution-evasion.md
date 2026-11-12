# Infraestrutura Ofensiva e Evasão de Atribuição

{{#include ../banners/hacktricks-training.md}}

Raramente um operador obtém anonimato significativo com um único proxy. Campanhas reais constroem um **grafo de separação**: o operador alcança um nó de acesso, nós de trânsito ocultam esse nó da saída, redirectors protegem o C2 real e nomes descartáveis apontam para a borda pública.

Use o [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) para uma visão normalizada dos prós, contras, implantação e detecção de cada caminho. Esta página aprofunda a composição de infraestrutura adversarial.

```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
                |                 |                |
          account/provider   relay operator   target telemetry
```

O último endereço visto pelo alvo é, portanto, evidência de um caminho, não prova de quem controlava o teclado. A MITRE mapeia os principais componentes para Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) e Web Service (T1102).<sup>[[1]](#references)</sup>

## Classes de infraestrutura

| Classe | Por que um agente a usa | Exposição duradoura | Melhor ponto de pivô para o defensor |
|---|---|---|---|
| VPS/cloud alugado | Rápido, previsível, roteável e fácil de recriar | Histórico de tenant, cobrança, console, logins de origem e imagens | Eventos da conta/plano de controle e fingerprint recorrente do servidor |
| VPN comercial/Tor | Grande conjunto compartilhado de saídas; dispensa administração de servidor | Visibilidade do provedor/guard e temporização de ponta a ponta | Comportamento no destino, evidências no endpoint e correlação de fluxos |
| Proxy residencial/móvel | ASN de consumidor e plausibilidade geográfica | Registros do broker/cliente; comportamento de proxyware ou de host infectado | Deslocamento impossível, protocolos de proxy e mudança de endereços por sessão |
| Servidor/roteador/IoT comprometido | Aproveita a reputação e a jurisdição da vítima | Implant, fluxo de gerenciamento e controlador upstream recorrente | Telemetria do dispositivo e topologia ORB, não um único IP de saída |
| CDN/redirecionador | Separa a edge pública do C2 de back-end | Gramática de TLS/HTTP, certificado, roteamento e artefatos da conta cloud | Correlação entre edge e origem e agrupamento por formato de requisição |
| Serviço web legítimo | Mistura-se ao tráfego permitido do GitHub/cloud/redes sociais | Token de API, identificadores de tenant/objeto e linhagem incomum de processos | Processo no endpoint e semântica do serviço/API |
| Caminho físico/celular/satélite | Altera a origem física aparente | Registros de RF, operadora, assinante, dispositivo e localização | Evidências combinadas de rádio/físicas e de rede |

## Redes operacionais de caixas de retransmissão

Uma **rede ORB** é uma frota gerenciada de proxies usada como serviço intermediário. A Mandiant as divide em redes provisionadas, formadas por servidores alugados, redes não provisionadas, formadas por roteadores/IoT comprometidos, e híbridas. Uma topologia madura tem quatro funções lógicas:<sup>[[2]](#references)</sup>

1. **Servidor de administração (ACOS):** mantém inventário, credenciais, integridade e políticas de roteamento.
2. **Nó de acesso/retransmissão:** autentica clientes ou operadores; é a entrada estável para uma malha em constante mudança.
3. **Nós de travessia:** um ou mais sistemas alugados ou comprometidos retransmitem conexões opacas.
4. **Nó de saída/preparação:** apresenta o endereço de origem final a alvos de reconhecimento, exploração ou C2.

A malha pode selecionar saídas por país, ASN, latência ou disponibilidade e substituir nós com problemas. Vários grupos de ameaças podem alugar a mesma rede. A Mandiant observou que um endereço IPv4 permaneceu associado a algumas ORBs por apenas 31 dias; por isso, recomenda tratar a **rede como uma entidade evolutiva semelhante a um agente**, em vez de bloquear uma lista desatualizada de IPs.<sup>[[2]](#references)</sup>

### O que isso oferece — e quais leaks gera

- O alvo vê uma saída que pode estar geograficamente próxima e parecer residencial.
- A saída vê o alvo e o salto anterior, mas não necessariamente o operador.
- O serviço de acesso vê o cliente e a solicitação de rota. Uma malha gerenciada de forma independente pode manter o cliente separado das saídas, mas gera um registro poderoso para a contraparte.
- Portas recorrentes, ordem de handshake, banners de servidor, certificados, períodos de atividade e relações entre controladores podem expor a frota mesmo quando os IPs mudam.
- Um roteador comprometido frequentemente não tem telemetria de endpoint, mas seu ISP ainda possui dados de assinante e de fluxo; uma apreensão revela artefatos do implant/configuração.

{% hint style="info" %}
Em um exercício autorizado, reproduza a topologia com VMs ou roteadores pertencentes à organização e mantenha o mapa de atribuição do controlador. Não recrute proxies abertos nem dispositivos de terceiros. O [guia do laboratório](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) cria a mesma estrutura de saltos visível ao defensor sem vitimizar um intermediário.
{% endhint %}

## Redes de proxy residencial e móvel

Serviços de proxy residencial atribuem sessões a endereços de banda larga de consumidores; proxies móveis saem por conjuntos de NAT de operadoras. A oferta pode vir de dispositivos inscritos explicitamente, SDKs/proxyware incluídos em aplicativos de consumo, revendedores ou malware. Essas origens não são equivalentes: a falta de consentimento informado transforma um serviço de privacidade em infraestrutura comprometida.

Os modos de rotação afetam a detecção:

- a **rotação por requisição** produz descontinuidades rápidas de IP e ASN/geografia, enquanto a identidade das camadas superiores permanece estável;
- as **sessões persistentes** mantêm uma saída por minutos ou horas, parecendo um assinante comum;
- os **gateways backconnect** expõem um endpoint de broker ao cliente e escolhem as saídas internamente;
- os **conjuntos móveis** colocam muitos assinantes legítimos atrás de um pequeno conjunto de endereços NAT de operadoras, tornando custoso bloquear um IP.

Os defensores devem correlacionar o IP com a sessão autenticada, o fingerprint de TLS/cliente, a ordem HTTP, o cookie do dispositivo e o comportamento. Um login residencial supostamente local, seguido por outro país enquanto todos os recursos das camadas superiores permanecem idênticos, é um indício mais forte do que apenas a reputação. Por outro lado, o compartilhamento de endereços e a alternância entre redes móveis geram mudanças legítimas; portanto, nunca trate a classificação residencial/de proxy como um veredito.

### Planos de controle de proxyware e sobreposição de revendedores

Não modele um conjunto residencial como uma lista simples de saídas. A análise do ecossistema IPIDEA revelou um **plano de controle reutilizável de dois níveis**: um SDK integrado primeiro reporta metadados do dispositivo/inscrição a um domínio Tier One e recebe pares de IP:porta para agendamento e `connect`/`proxy` Tier Two. O nó consulta periodicamente a porta de conexão Tier Two em busca de uma tarefa codificada, abre uma segunda conexão com a porta proxy correspondente e retransmite os bytes fornecidos ao destino solicitado. SDKs e marcas de proxy nominalmente distintos tinham domínios de descoberta separados, mas convergiam para uma infraestrutura Tier Two compartilhada e conjuntos de saídas sobrepostos, por meio de relações de propriedade comum e revenda.<sup>[[13]](#references)</sup>

```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```

Isso gera pivôs de hunting mais duráveis do que um bloco de IP residencial:<sup>[[13]](#references)</sup>

- um processo inesperado de utilitário, VPN, jogo ou dispositivo incorporado envia um ID de dispositivo/chave de cliente estável e recebe uma lista de servidores variável;
- o endpoint consulta um IP direto em uma porta incomum e, em seguida, conecta-se a outra porta no mesmo endereço imediatamente antes de abrir um socket para um novo destino;
- várias marcas aparentes compartilham endereços Tier Two, gramática de protocolo, código de SDK ou sobreposição de nós de saída;
- aplicações distintas que contatam domínios Tier One diferentes recebem endereços do mesmo pool Tier Two.

A sobreposição também limita a atribuição: ver um IP no pool anunciado por um fornecedor não comprova qual revendedor, cliente ou agente de ameaça o utilizou no momento relevante. Preserve os timestamps dos fluxos, a linhagem dos processos, os corpos das respostas Tier One e os identificadores de tarefas Tier Two.<sup>[[13]](#references)</sup> Em um exercício autorizado, emule essa hierarquia apenas com endpoints pertencentes à organização; nunca inscreva dispositivos de consumidores nem proxyware de terceiros.

## Cadeias de proxy multi-hop

O MITRE diferencia proxies externos de **proxies multi-hop (T1090.003)**. A propriedade importante não é o número de hops, mas a separação de conhecimento e administração.<sup>[[3]](#references)</sup>

```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
              sees source                         sees destination
```

Se uma parte opera A e B, os logs compartilhados ou o timing do fluxo podem reconstruir o circuito. Adicionar VPNs comerciais sequenciais a partir do mesmo endpoint/conta pode aumentar a latência, mas mantém evidências comuns de identidade, pagamento e timing. O Tor reduz esse problema com relays selecionados independentemente e um design de cliente compartilhado, mas uma rede interativa de baixa latência não pode prometer resistência a um observador que mede ambas as pontas.

Falhas comuns incluem bypass de DNS ou IPv6, aplicativos que abrem seus próprios sockets, tráfego de gerenciamento que chega diretamente aos relays, atividade sincronizada, chaves SSH reutilizadas e login em contas que identificam o usuário. A verificação correta é um teste de falha: interrompa cada relay, um por vez, e confirme que o workload não consegue recorrer a um caminho sem criptografia.

### Colapso do túnel e leak upstream

Uma arquitetura de relays costuma ser mais fácil de atribuir quando falha. A Unit 42 documentou um caminho de espionagem em várias camadas que usava VPSs voltados para as vítimas, VPSs de relay, proxies residenciais, Tor e outros serviços de proxy; quando um túnel era omitido ou entrava em colapso, a infraestrutura upstream oculta se conectava diretamente aos sistemas de relay e aos voltados para as vítimas. A mesma investigação também usou um certificado X.509 brevemente exposto na infraestrutura upstream como pivot entre camadas.<sup>[[14]](#references)</sup>

Mantenha o **plano de dados** (`victim <-> exit`) separado do **plano de controle** (`operator/upstream -> relay administration`). Retenha logs de entrada e autenticação em cada camada sob seu controle, históricos de certificados e conexões malsucedidas de curta duração — não apenas sessões C2 bem-sucedidas. Uma origem que aparece somente durante interrupções de relays ou administra diretamente vários nós voltados para as vítimas é uma candidata upstream mais provável do que um exit comum, mas o ASN/geolocalização continua sendo uma hipótese, não uma prova da identidade de um operador.

Um lab autorizado deve fazer o workload falhar de forma fechada. Para um workload isolado em um namespace de rede Linux, a primeira rota deve usar o túnel; após removê-lo, tanto a requisição quanto a consulta de rota devem falhar, em vez de selecionar a conexão física de saída:

```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
  --resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```

Repita o teste para DNS e IPv6 e em cada limite entre relays. Se alguma sonda for bem-sucedida, registre a interface/endereço de origem real antes de corrigir o roteamento por política ou o firewall; essa observação é o leak de atribuição que um investigador veria.

## Camadas de redirector e modelagem de tráfego

Um **redirector** público aceita o tráfego que corresponde a uma gramática específica da operação e o encaminha para um servidor de equipe protegido. Todo o resto pode ser rejeitado ou receber conteúdo inofensivo.

```text
implant/browser -> CDN or redirector -> relay -> team server
                       |
                 request policy
           host + path + method + header + time
```

Várias camadas limitam a exposição: queimar um domínio público não precisa expor o servidor da equipe. CDNs adicionam capacidade anycast e um domínio externo confiável, mas a conta da CDN e os logs de edge tornam-se pontos de atribuição. Fingerprints de TLS, históricos de certificados, caminhos distintos/ordem dos headers, tamanhos de resposta, comportamento de redirecionamento e allowlists de origem podem agrupar fronts supostamente não relacionados.

Para detectar isso, registre os campos do reverse proxy antes da normalização, compare SNI/Host/authority, inspecione combinações raras de headers, agrupe corpos de resposta e fingerprints de TLS, e pesquise nos logs de auditoria da cloud/CDN por configurações sobrepostas. Para red teams autorizadas, evite copiar uma marca real ou coletar credenciais por meio de um terceiro não relacionado.

## Domain fronting e domainless fronting

Com o **domain fronting (T1090.004)** clássico, a conexão TLS anuncia um domínio front permitido em SNI, enquanto o `Host` HTTP criptografado ou `:authority` do HTTP/2 solicita um domínio de back-end diferente. Uma CDN cooperante roteia com base no valor interno. Um observador de rede sem descriptografia de TLS vê o front; a CDN vê ambos os valores e a origem. Nas variantes domainless, o SNI pode estar vazio enquanto outro campo de roteamento seleciona o destino.<sup>[[4]](#references)</sup>

Isso não é uma imitação mágica: só funciona quando o intermediário permite a incompatibilidade intencionalmente ou por acidente e sabe como rotear o nome interno. Os principais provedores restringiram o fronting entre contas. O Encrypted ClientHello (ECH) altera o que um observador no caminho pode ver, mas não apaga os registros da CDN, do endpoint ou da aplicação.

Os pontos de detecção incluem:

- ancestralidade do processo no endpoint e destino inesperado para aquela aplicação;
- incompatibilidade entre SNI e authority HTTP, quando a inspeção de TLS é legal e está disponível;
- logs da CDN mostrando um tenant/front roteando para outra authority/origem;
- sessões incomumente longas ou periódicas para um serviço normalmente interativo;
- tamanhos e cadência estáveis de fluxos criptografados entre domínios front variáveis.

O laboratório seguro simula a incompatibilidade de roteamento em um reverse proxy próprio; ele não abusa de uma CDN pública.

## Resolução dinâmica: DDNS, DGA e fast flux

A resolução dinâmica desvincula um serviço lógico de uma infraestrutura fixa:

- **DDNS:** um cliente autenticado atualiza um nome estável após a mudança de seu endereço.
- **DGA:** o endpoint deriva nomes de domínio a partir de uma seed, muitas vezes baseada em tempo ou em uma chave, mas às vezes em conteúdo público mutável; o operador configura o DNS para o nome ativo.<sup>[[17]](#references)</sup>
- **Fast flux:** um nome retorna um conjunto de endereços comprometidos/de proxy que muda rapidamente, muitas vezes com TTLs baixos.
- **Double flux:** tanto os endereços dos serviços quanto os dos servidores de nomes autoritativos mudam, ocultando também a camada de controle.

Fast flux é um padrão de distribuição de carga usado de forma adversarial, não apenas “muitas respostas DNS”. Evidências mais fortes combinam TTL baixo, alta contagem de endereços únicos, ampla dispersão de ASN/geográfica, curta vida útil dos nós, comportamento repetido da aplicação e histórico de registro suspeito. CDNs compartilham legitimamente várias dessas propriedades. A MITRE recomenda correlacionar o comportamento de DNS com o processo e as conexões subsequentes.<sup>[[5]](#references)</sup>

Uma DGA pode ser detectada por meio de entropia lexical, padrões de consoantes/dígitos, picos de NXDOMAIN, domínios sincronizados vistos pela primeira vez e contexto do processo. DGAs baseadas em wordlists e modelos generativos burlam regras simples de entropia, tornando mais importantes o agrupamento temporal em toda a frota e a linhagem do endpoint.

### Seed de imagem mutável para uma DGA baseada em wordlist

Uma DGA não precisa depender do tempo. Um loader busca a página de um canal público do Telegram, lê o `src` do elemento `tgme_page_photo_image`, baixa a imagem do perfil e calcula o hash dos **últimos 50 bytes do arquivo**, em vez dos pixels decodificados. Quatro seeds de hash selecionam um adjetivo, um substantivo, um verbo e um número. Alterar a imagem muda o nome DNS derivado sem distribuir um novo cliente. Mantenha os bytes exatos da imagem baixada e a mesma ordem das wordlists em ambos os lados; recodificar a imagem ou reordenar uma lista produz nomes diferentes.<sup>[[17]](#references)</sup>

Com as wordlists recuperadas do cliente, isso reproduz a etapa de seleção do nome. O hash byte a byte da fonte usa um acumulador de 64 bits, o multiplicador `0x1000193` e seeds separadas para cada componente:<sup>[[17]](#references)</sup>

<details>
<summary>Reproduzir a seleção de nome da wordlist baseada em seed de imagem</summary>

```python
def wordlist_domain(image: bytes, adjectives: list[str], nouns: list[str], verbs: list[str], suffix: str) -> str:
    if len(image) < 50:
        raise ValueError("Image must contain at least 50 bytes")
    tail = image[-50:]
    def hashed(seed: int) -> int:
        value = seed
        for byte in tail:
            value = ((value ^ byte) * 0x1000193) & 0xFFFFFFFFFFFFFFFF
        return value
    a = adjectives[hashed(0x811C9DC5) % len(adjectives)]
    n = nouns[hashed(0xAF0154A5) % len(nouns)]
    v = verbs[hashed(0xFE5439E4) % len(verbs)]
    digit = hashed(0xFFA7471A) % 1000
    return f"{a}-{n}-{v}-{digit}.{suffix}"
```

</details>

Ao contrário de um [dead-drop resolver](#web-services-and-dead-drop-resolvers), que publica o próprio endpoint, o objeto público aqui fornece apenas uma seed mutável; o cliente deriva o endpoint localmente.

O nome gerado é então consultado em busca de um registro DNS TXT por meio de `https://dns.google/resolve?name=<domain>&type=TXT`. O cliente decodifica em Base64 o campo `data` da resposta JSON, verifica uma assinatura Ed25519 com sua chave pública incorporada e só então descriptografa o comando com AES-ECB. O texto simples observado começa com um seletor de método e uma URL para um payload criptografado. A verificação da assinatura significa que um registro TXT resolvível, por si só, não pode fornecer tasking aceito.<sup>[[17]](#references)</sup>

## Domínios comprometidos e Domain shadowing

Um ator pode sequestrar uma conta de registrador/DNS, assumir um subdomínio abandonado ou adicionar registros sob um domínio que, de resto, tenha boa reputação. **Domain shadowing** preserva o domínio apex legítimo enquanto grandes quantidades de subdomínios controlados pelo atacante apontam para hosts de entrega ou C2 que mudam ao longo do tempo. Isso aproveita a antiguidade e a reputação do domínio e pode escapar de bloqueios aplicados ao domínio inteiro.<sup>[[6]](#references)</sup>

Os defensores precisam de logs de auditoria do registrador e do DNS autoritativo, MFA, bloqueios de registro/registrador, alertas para novas delegações/tokens de API/servidores de nomes, monitoramento de Certificate Transparency e um inventário dos recursos de cloud referenciados pelo DNS. Investigue o histórico de resolução e de certificados de um subdomínio independentemente da reputação do domínio apex.

## Web services e dead-drop resolvers

Um **dead-drop resolver (T1102.001)** armazena um ponteiro codificado para o C2 atual em uma publicação, perfil, documento, repositório, objeto de cloud ou campo de blockchain legítimo. O malware busca o objeto público, decodifica um domínio/IP e contata o próximo estágio. Variantes bidirecionais trocam comandos ou arquivos por meio de APIs de serviços.<sup>[[7]](#references)</sup>

Uma variação específica de resolver do GitHub usa a API de busca de Issues somente quando um canal autenticado do repositório falha. O cliente busca issues que correspondam à data atual, ao repositório e ao tipo de issue, segue a URL dos comentários de cada issue e extrai o texto cifrado entre os marcadores `<!--` e `-->`. Após a descriptografia derivada do host e da data, campos como `Owner`, `LicRepo` e `LicToken` substituem o proprietário, o caminho e o token do repositório principal. Isso permite ao operador alternar credenciais e endpoints sem substituir o cliente; o comentário da issue funciona como resolver, enquanto os arquivos do repositório continuam sendo o canal de tasking.<sup>[[15]](#references)</sup>

Uma variante para Android seleciona uma de duas páginas públicas do Telegram na inicialização e extrai o texto cifrado entre duas ocorrências de um marcador incorporado ao APK. Ela decodifica o valor com Base64URL e o descriptografa com AES-128-CBC: os primeiros 16 bytes de `SHA-256(marker)` são a chave, e os 16 bytes restantes são o IV. O texto simples é a URL base real do C2, não a URL da página do Telegram. Preserve o conteúdo da página e o marcador exato ao reproduzir a resolução; alterar a página pública alterna o endpoint sem precisar reconstruir o APK.<sup>[[16]](#references)</sup>

Isso proporciona resiliência e oculta o C2 de back-end da análise estática do binário. Também cria identificadores estáveis de objeto, tenant, repositório, API e padrão de acesso. Os defensores devem correlacionar:

1. o processo que contatou o serviço;
2. o caminho exato da API/objeto e o hash da resposta;
3. a atividade de decodificação ou processamento de strings;
4. a nova conexão de saída pouco depois; e
5. o mesmo comportamento em outros pontos da frota.

Bloquear todo o GitHub, armazenamento em cloud ou redes sociais raramente é viável. Políticas de saída que considerem os serviços e a correlação no nível do processo são mais eficazes do que o bloqueio baseado apenas em domínio.

## Personas, contas e compartimentos de aquisição

O anonimato da infraestrutura falha quando uma persona, e-mail de recuperação, telefone, pagamento, navegador ou IP administrativo conecta compartimentos. Operações ligadas a Estados cultivaram perfis sociais, identidades de e-mail e contas de cloud muito antes de usá-los; o ATT&CK registra isso como Establish Accounts (T1585), incluindo as subtécnicas social, email e cloud.<sup>[[8]](#references)</sup>

Um defensor ou investigador constrói um grafo a partir de:

- horários de criação e primeiro login, localidade, fuso horário e horário de trabalho;
- campos de recuperação, dispositivos MFA, documentos de identidade e instrumentos de pagamento;
- fingerprints de navegador/TLS e histórico da rede de origem;
- reutilização de avatar, origem de imagens, estilo de escrita e crescimento do grafo social;
- registrante de domínio, servidor de nomes, certificado, ID de analytics ou commit de repositório compartilhados;
- ações no plano de gerenciamento que contornam a arquitetura de relay público.

Em uma red team autorizada, as personas sintéticas devem ser documentadas para o controlador do exercício, usar canais de recuperação/pagamento pertencentes à organização, evitar se passar por pessoas reais não envolvidas e ter um plano de encerramento. O SOC pode continuar sem saber; a operação não pode ficar sem prestação de contas.

## Padrões compostos emergentes a modelar em ameaças

Os itens a seguir são **composições orientadas à defesa**, não afirmações de que um ator identificado tenha implantado cada projeto exato. Eles combinam primitivas já observadas e são hipóteses úteis para purple team.

### Tasking unidirecional assimétrico

Os comandos chegam por uma fonte pública, de broadcast ou append-only, enquanto os resultados saem por um canal não relacionado após um atraso. Entre os exemplos dessa primitiva estão a comunicação unidirecional por web service e os dead drops. A separação impede que um único fluxo pareça bidirecional e dificulta a correlação simples de solicitação/resposta.<sup>[[9]](#references)</sup>

**Detecção:** preserve as leituras de objetos e, depois, correlacione mudanças de estado do processo com transferências de saída posteriores em uma janela mais ampla. Procure processos raros que leem o mesmo objeto público, mesmo quando não há resposta imediata.

### Promoção de canal em múltiplos estágios

Um primeiro estágio discreto faz o inventário e só promove sistemas selecionados para um segundo canal não relacionado. O segundo endpoint, protocolo e processo podem não compartilhar nenhuma infraestrutura com o primeiro. Isso limita a exposição da infraestrutura mais sofisticada e é explicitamente modelado como ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detecção:** correlacione `processo de rede inicial -> estado baixado/configurado -> novo processo ou injeção -> destino não relacionado`; não encerre o incidente após bloquear o primeiro domínio.

### Tradução de relay entre protocolos

Diferentes saltos traduzem HTTPS, QUIC, WebSocket, DNS, SSH ou uma API de message queue, em vez de encaminhar pacotes de forma transparente. A tradução remove uma única fingerprint de protocolo ponta a ponta, mas cria gateways com padrões distintos de temporização, buffering e conversão semântica. Protocol tunneling (T1572) pode ser combinado com proxies e imitação de serviços.<sup>[[11]](#references)</sup>

**Detecção:** procure hosts gateway que recebem um protocolo e iniciam outro com comportamento de bytes/tempo fortemente correlacionado; compare a intenção do endpoint com o protocolo realmente transportado.

### Ativação passiva em dispositivos de borda

Em vez de enviar beacons, um implante monitora o tráfego que já chega a um roteador/VPN e só é ativado por um valor mágico, padrão de porta de origem ou token autenticado. O tráfego normal continua até o serviço real. O ATT&CK chama isso de Traffic Signaling (T1205), com exemplos documentados envolvendo dispositivos de rede e APTs.<sup>[[12]](#references)</sup>

**Detecção:** integridade de firmware/arquivos, captura de pacotes brutos durante uma investigação autorizada, filtros de socket inesperados e comportamento diferente do serviço. A ausência de um beacon periódico não prova que um dispositivo de borda esteja limpo.

### Rotação de origens serverless e efêmeras

Um front mantém uma identidade lógica estável enquanto funções/contêineres de curta duração lidam com estágios individuais em várias regiões/contas. Isso reduz o tempo de vida em disco e o uso de IPs de origem fixos, mas os dados de telemetria do plano de controle — criação, imagem/camada, função, segredo, ID da solicitação e faturamento — tornam-se o grafo duradouro.

**Detecção:** retenha logs de auditoria e de invocação da cloud fora da carga de trabalho; agrupe modelos de implantação, funções, chaves de ambiente e relações entre front e origem.

### Diversidade de camadas de privacidade

Uma operação pode evitar deliberadamente uma cadeia homogênea: por exemplo, um canal usa um relay alugado, o tasking usa um objeto público, uma saída vem de um link celular de laboratório próprio e a administração usa uma rede separada da organização. Isso reduz o valor de comprometer um único provedor, mas aumenta o risco de correlação temporal entre camadas e de erros operacionais.

**Detecção:** construa linhas do tempo da campanha a partir de sensores de identidade, DNS, SaaS, rede e cloud. Procure transições de estado sincronizadas, em vez de indicadores idênticos.

### Dead drops descentralizados ou em logs de transparência

Um ator pode colocar um pequeno ponteiro criptografado em qualquer sistema público append-only durável, armazenamento endereçado por conteúdo ou feed semelhante a um log de transparência. O objeto público é resiliente, mas seu índice/hash de conteúdo exato e o comportamento de polling do cliente tornam-se identificadores estáveis.

**Detecção:** registre os identificadores completos de API/objeto e os hashes das respostas; gere alertas para processos fora do padrão que consultam objetos imutáveis e depois os decodificam ou iniciam novas conexões.

### Operações atrasadas de store-and-forward

O C2 interativo cria fortes correlações temporais. Um projeto de store-and-forward agrupa tarefas criptografadas e devolve os resultados minutos ou horas depois por meio de uma fila diferente ou transferência física. Isso sacrifica a capacidade de resposta em favor de uma correlação temporal ponta a ponta mais fraca.

**Detecção:** amplie as janelas de correlação, modele o acesso periódico às filas e examine o staging nos endpoints. O agrupamento desloca o sinal do timing dos pacotes para o comportamento programado de processos/arquivos; não o elimina.

## Revisão de projeto: pense em observadores

Para cada caminho, preencha esta tabela antes da implantação e após a coleta:

| Camada | Vê a origem? | Vê o destino? | Vê o conteúdo? | Identificadores estáveis | Retenção/responsável legal |
|---|---:|---:|---:|---|---|
| rede local/operadora | | | | | |
| serviço de entrada/acesso | | | | | |
| operador(es) de traversal | | | | | |
| saída/redirector/CDN | | | | | |
| DNS autoritativo/registrador | | | | | |
| alvo | | | | | |
| provedor de conta/pagamento | | | | | |

Se um único provedor comum puder preencher todas as colunas, a arquitetura oferece ocultação em relação ao alvo, mas não uma separação robusta. Se nenhum controlador interno puder relacionar a atividade a um engagement, a arquitetura não é adequada para red teaming profissional.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584) e Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
- [13] [Google Threat Intelligence Group — Desarticulando a maior rede de proxy residencial do mundo](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — As campanhas Shadow: revelando a espionagem global](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
- [15] [Unit 42 - Campanha Blinder Tunnel tem como alvo a infraestrutura iraquiana](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [16] [RemControl: a IA criou as sobreposições. As vítimas perdem seus PINs](https://www.group-ib.com/blog/remcontrol-android-banking-trojan/)
- [17] [Check Point Research — Truques do passado implantados por meio de binários assinados do ChatGPT e Claude](https://research.checkpoint.com/2026/tricks-from-the-past-deployed-via-signed-chatgpt-and-claude-binaries/)
{{#include ../banners/hacktricks-training.md}}
