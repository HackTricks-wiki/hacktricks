# Arquiteturas avançadas de privacidade de rede

A complexidade só é útil quando remove um observador específico ou um modo de falha específico. Uma stack de túneis exclusiva, um formato de pacote personalizado, um user agent raro ou uma infraestrutura que muda frequentemente podem se tornar uma impressão digital mais forte do que uma configuração padrão usada por milhares de pessoas.

O [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fornece o schema comum `Pros`/`Cons`/`Procedure`/`Detection`. Esta página amplia as arquiteturas e os limites de confiança mais complexos.

O objetivo avançado é, portanto, a **separação do conhecimento**: nenhum componente comum deve possuir simultaneamente a identidade do usuário, o destino, o texto não criptografado e o histórico de atividades de longo prazo. Isso não é invisibilidade, e conluio, processo legal, comprometimento do endpoint ou correlação de tráfego de ponta a ponta ainda podem reconstruir o caminho.

## Seleção da arquitetura

| Padrão | Propriedade obtida | Nova confiança/falha | Uso adequado |
|---|---|---|---|
| Standard Tor Browser | Impressão digital compartilhada do navegador e caminho com múltiplos relays | A baixa latência permite a correlação de tráfego | Navegação web anônima geral |
| Tor bridge + pluggable transport | Torna mais difícil o bloqueio/classificação direta do Tor | Bridge/transport ainda pode ser detectado; a bridge aprende a origem | Redes censuradas |
| Onion service | Oculta o IP do serviço; evita o exit; autentica a identidade onion | A chave onion e o endpoint do servidor tornam-se ativos críticos | Publicação privada, recebimento ou administração |
| Independent ingress + egress relays | Nenhum relay normalmente vê a origem e o destino | Operadores podem conspirar; o timing atravessa ambos | Aplicações compatíveis de alto desempenho |
| Oblivious HTTP | Separa o IP de origem da solicitação HTTP stateless criptografada | Requer suporte da aplicação, do relay e do gateway | Telemetria, consultas e envios sem estado de sessão |
| VPN-only workload namespace | Ausência de uma rota para rede clara imposta pelo kernel | A VPN ainda vê ambas as pontas; host/root continua confiável | Ferramentas de engagements autorizados e egress fixo |
| Disposable remote browser | O destino é isolado do navegador/endpoint local | O provedor do Workspace vê a atividade e a identidade de login | Sites/arquivos não confiáveis e pesquisa controlada |
| I2P internal service | Túneis overlay separados de entrada/saída; sem exits oficiais | Ecossistema menor/diferente; comportamento de peers de longa duração | Serviços nativos do I2P, não substituição da web comum |
| Mixnet/asynchronous delivery | Atraso, agrupamento e cover traffic resistem à análise de timing | Alta latência, aplicações limitadas e menor maturidade | Mensagens/tarefas que não precisam de interação |

## Relays com conhecimento dividido

Um padrão de relay operado por dois operadores pode superar uma única VPN para uma aplicação específica:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Apple Private Relay é um exemplo implantado: a Apple opera a entrada, enquanto um provedor de conteúdo diferente opera a saída, portanto nenhum dos dois normalmente vê simultaneamente o IP do cliente e o destino da navegação.<sup>[[1]](#references)</sup> Trata-se de um serviço de privacidade específico do produto Safari/DNS, não de uma rede de anonimato para todos os dispositivos, e ele preserva deliberadamente uma região aproximada.

Oblivious HTTP (OHTTP) padroniza um padrão de aplicação mais restrito. O relay vê o cliente e o tráfego criptografado até o gateway; o gateway descriptografa a mensagem HTTP, mas vê o relay, não o cliente. A RFC 9458 alerta que ele requer suporte voluntário do relay/gateway, é mais adequado para requisições sem cookies/autenticação/estado de sessão e exclui a análise de tráfego de suas garantias.<sup>[[2]](#references)</sup>

### Checklist de design

1. Defina as mensagens exatas da aplicação a serem protegidas; não faça proxy silenciosamente de sessões web autenticadas arbitrárias.
2. Use organizações de entrada e saída operadas independentemente, com administração, credenciais, logging e controle jurídico separados sempre que possível.
3. Criptografe a requisição da aplicação para o gateway, para que a entrada não possa lê-la.
4. Remova headers de encaminhamento derivados do cliente, identificadores TLS e tokens estáveis por usuário na camada apropriada.
5. Evite chaves, cookies ou campos de payload exclusivos que permitam ao gateway religar requisições apesar da separação de transporte.
6. Agregue, minimize e expire os logs em ambos os lados; documente o risco de conluio e de divulgação compulsória.
7. Faça padding ou batching somente de acordo com um protocolo revisado. Traffic shaping improvisado pode criar uma assinatura exclusiva sem impedir a correlação.
8. Teste com requisições canário controladas e compare o que o cliente, a entrada, o gateway e o alvo registram.

Para navegação interativa comum, use Tor Browser em vez de inventar um proxy OHTTP privado. OHTTP protege uma transação de aplicação compatível, não uma identidade completa de navegador.

## Aplique a rota por workload

Um kill switch baseado apenas em rotas de host mutáveis pode falhar durante a renovação do DHCP, suspensão/retomada, alterações de IPv6 ou uma falha do tunnel. Um padrão Linux mais forte fornece a um container ou network namespace apenas uma interface de loopback e uma interface de tunnel. A documentação do WireGuard informa que uma interface pode ser criada em um namespace físico, movida para um namespace de workload e manter seu socket UDP criptografado no namespace original.<sup>[[3]](#references)</sup>

### Padrão de deployment

1. Primeiro, crie isso em um host descartável/com console local; erros no namespace podem remover o acesso remoto.
2. Coloque a interface Ethernet/Wi-Fi física e o DHCP/supplicant em um namespace **físico**.
3. Crie a interface WireGuard nesse local para que seu socket de transporte criptografado tenha acesso à rede física.
4. Mova apenas a interface WireGuard para o namespace **workload** e torne-a a única rota padrão.
5. Forneça ao workload um resolver específico do namespace, alcançável apenas pelo tunnel. Considere explicitamente o IPv6.
6. Execute o container de browser/tool nesse namespace, sem host networking, capability privilegiada, diretório compartilhado de browser ou agente de credenciais pessoais.
7. Pare o tunnel e verifique se o workload não consegue resolver nem se conectar a um endpoint IPv4 ou IPv6 controlado.
8. Teste roaming de endpoint, renovação do DHCP, suspensão/retomada e tratamento de captive portal fora do namespace do workload.
9. Registre o hash da configuração de namespace/tunnel e o endereço de saída aprovado para fins de accountability do engagement.

Isso fornece **enforcement de rota**, não anonimato perante o VPN ou o bastion do engagement. Um host/root comprometido pode inspecionar ou alterar namespaces.

## Bridges Tor e pluggable transports

Bridges são relays de entrada Tor não públicos. Pluggable transports alteram o tráfego do primeiro salto para dificultar bloqueios simples ou a classificação de protocolo. Eles não adicionam camadas de relay anônimo após a entrada e não derrotam um observador capaz de realizar uma correlação temporal mais ampla.

| Transport | Abordagem do primeiro salto | Tradeoff prático |
|---|---|---|
| **obfs4** | Faz o tráfego parecer aleatório e resiste a sondagem ativa | Um endereço de bridge conhecido ainda pode ser bloqueado |
| **Snowflake** | Usa proxies WebRTC voluntários de curta duração para alcançar uma bridge | O desempenho varia; existem padrões de broker/STUN/WebRTC |
| **WebTunnel** | Transporta o tráfego da bridge em um tunnel WebSocket semelhante a HTTPS | Depende de um front web alcançável e ainda pode ser classificado |

O Tor Project descreve Snowflake e WebTunnel como transports de contorno de censura, não como indistinguibilidade perfeita.<sup>[[4]](#references)</sup>

### Workflow seguro

1. Comece com a conexão direta do Tor Browser. Adicione uma bridge somente quando o bloqueio ou a visibilidade no modelo de observador local justificar isso.
2. Use transports integrados ou linhas de bridge obtidas por canais do Tor Project. Não baixe binários de transport aleatórios nem listas públicas de bridges de fóruns.
3. Tente a opção compatível menos complexa que conecte de forma confiável; registre o motivo da escolha.
4. Mantenha o Tor Browser padrão no restante. Uma bridge não torna extensões personalizadas, logins de conta ou configurações incomuns do browser seguros.
5. Teste a reconexão e a correção do relógio. Não alterne repetidamente os transports de modo a enviar uma sequência distinta ao mesmo observador local.
6. Reavalie se o censor ou a política de rede mudar; o uso pode ser sensível ou restrito em alguns locais.

## Onion services como rendezvous privado

Um onion service cria circuits Tor de saída para introduction points e relays de rendezvous, portanto não precisa de uma porta pública de entrada e não expõe o IP do servidor por meio do protocolo onion. O tráfego entre cliente e serviço permanece dentro do Tor, e o endereço onion autentica a chave do serviço.<sup>[[5]](#references)</sup>

Para um portal de recebimento legítimo, repositório privado, interface administrativa ou depósito de evidências de engagement:

1. Execute a aplicação em um host/VM dedicado e faça bind ao loopback ou a um Unix socket isolado.
2. Instale o Tor a partir de seu repositório oficial e siga a configuração oficial de onion service v3; nunca use instruções obsoletas de v2.
3. Proteja a chave privada do onion service como uma chave TLS/de assinatura. Faça backup apenas se uma identidade estável for necessária.
4. Adicione autorização de cliente do onion service para um grupo fechado e entregue as credenciais por um canal autenticado independentemente.<sup>[[6]](#references)</sup>
5. Impeça que a origem busque fontes de terceiros, analytics, updates ou webhooks que revelem seu IP público ou a conta do operador.
6. Inclua autenticação e autorização também na aplicação; possuir o endereço onion não é controle de acesso.
7. Aplique patches, rate-limit e monitore o serviço sem incorporar telemetria de terceiros.
8. A partir de um contexto de teste separado, confirme que DNS, email, páginas de erro, metadados de arquivos e headers de resposta não divulgam a origem.
9. Para uso em red team, liste o serviço, proprietário, finalidade e horário de desligamento no ROE. Não o use para ocultar C2 fora do escopo.

## Browser remoto e workspace descartável

Um browser remoto move a renderização e o conteúdo arriscado para longe do endpoint local e pode apresentar uma saída cloud específica do engagement. Ele protege o dispositivo local contra parte do conteúdo e da persistência; não torna o operador anônimo perante o provedor do workspace. A AWS, por exemplo, documenta a coleta de dados de portal, identidade, política, preferências e logs de sessão, embora a instância descartável de browser seja eliminada ao final da sessão.<sup>[[7]](#references)</sup>

Use um workspace controlado pela organização por engagement, restrinja downloads/uploads/clipboard, desative provedores de identidade pessoais, envie sua saída fixa pelo bastion aprovado e expire o workspace após a exportação das evidências. Considere o console do provedor, o IdP e o administrador como observadores.

## I2P e overlays internos

O I2P cria tunnels de entrada e saída unidirecionais separados e não possui exits oficiais em nível de rede; ele é destinado principalmente a serviços dentro do I2P.<sup>[[8]](#references)</sup> Não é uma forma mais rápida, pronta para uso, de navegar na Internet pública. Outproxies introduzem um ponto de confiança, e o modelo oficial de ameaças solicita mais pesquisa e não afirma anonimato perfeito.

Use I2P somente quando ambas as extremidades o suportarem intencionalmente, isole seu router de longa duração das aplicações pessoais e entenda que peers/redes locais podem observar a participação no I2P. Não aumente a quantidade de hops nem ajuste a seleção de peers sem evidências: configurações incomuns podem reduzir o desempenho e o anonymity set.

## Operações resistentes à correlação

- Prefira uma configuração de cliente comum e compatível a um build exclusivo.
- Separe as identidades no endpoint; nenhuma topologia de roteamento corrige reutilização de conta, pagamento, recuperação ou conteúdo.
- Para tarefas não interativas, prefira um protocolo assíncrono/mixnet revisado a adicionar manualmente sleeps ou tráfego falso.
- Evite operar identidades supostamente separadas em um padrão sincronizado a partir do mesmo contexto físico.
- Use um gate de exportação unidirecional: conteúdo não confiável entra em um renderer descartável; somente um resultado revisado e sanitizado sai.
- Mantenha os relógios corretos para a segurança do protocolo, mas remova timestamps precisos desnecessários dos artefatos publicados.
- Minimize a duração das sessões e a infraestrutura obsoleta sem rotação rápida de “fast-flux”, que é conspícua e prejudica a accountability.

## Técnicas que não podem usar terceiros não envolvidos

Estas são técnicas genuínas de adversário, não técnicas imaginárias ou irrelevantes. Sua mecânica e detecção são abordadas em [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) e nos [estudos de caso de APT](government-and-apt-case-studies.md). Durante um exercício autorizado, reproduza seu comportamento observável com substitutos próprios:

- modele a churn de saída residencial/móvel com pools de relays controlados, nunca com mercados de consentimento incerto;
- modele open proxies, routers comprometidos e botnets com VMs/routers próprios;
- modele contas cloud roubadas com um tenant de exercício designado e uma identidade de vítima sintética;
- modele domain fronting em um reverse proxy próprio, e não em uma CDN que não consentiu;
- modele Wi-Fi de terceiros com dois APs isolados pertencentes ao laboratório;
- trate encryption customizada, chains de múltiplos VPNs e rotação de identificadores como hipóteses de teste cujos fluxos, artefatos de conta e endpoint continuem detectáveis.

Para uma red team autorizada, qualquer tentativa de tornar o tráfego menos reconhecível deve ser um objetivo explícito de detecção no ROE, ter um mapa de atribuição mantido pelo controller e incluir um mecanismo de parada/desconflicção.

## Matriz de verificação

| Teste | Resultado esperado | A falha significa |
|---|---|---|
| Tunnel/bridge interrompido | O workload não possui caminho direto IPv4/IPv6/DNS | O enforcement de rota está incompleto |
| Log do alvo inspecionado | Apenas a identidade de saída/aplicação planejada aparece | Header, rota ou account leak |
| Log da entrada inspecionado | A origem está presente; o alvo/requisição em claro está ausente | A divisão de confiança falhou na entrada |
| Log da saída inspecionado | O relay/requisição está presente; a identidade da origem está ausente | A divisão de confiança falhou na saída |
| Origem onion examinada externamente | Nenhum serviço de origem público está acessível/vinculado | A origem sofreu leak ou possui dual-homing |
| Sessão descartável encerrada | O estado da instância desapareceu; as evidências aprovadas foram retidas separadamente | A fronteira de persistência falhou |
| Consulta do controller exercitada | A atividade é mapeada prontamente ao engagement/operador | A accountability da red team falhou |

## References

- [1] [Segurança de Plataforma Apple — segurança do iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Roteamento e Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake e pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Como funcionam os Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Configurações avançadas de Onion Service e autorização de cliente](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Criptografia de dados no Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Modelo de ameaças](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
