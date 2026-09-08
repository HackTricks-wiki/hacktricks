# Arquiteturas avançadas de privacidade de rede

{{#include ../banners/hacktricks-training.md}}

A complexidade é útil apenas quando remove um observador específico ou um modo de falha específico. Uma pilha de túneis única, um formato de pacote personalizado, um user agent raro ou uma infraestrutura frequentemente rotacionada podem se tornar uma fingerprint mais forte do que uma configuração padrão usada por milhares de pessoas.

O [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) fornece o schema comum `Pros`/`Cons`/`Procedure`/`Detection`. Esta página detalha as arquiteturas mais complexas e as fronteiras de confiança.

O objetivo avançado é, portanto, a **separação do conhecimento**: nenhum componente comum deve possuir simultaneamente a identidade do usuário, o destino, o plaintext e o histórico de atividade de longo prazo. Isso não é invisibilidade, e conluio, processo legal, comprometimento do endpoint ou correlação de tráfego end-to-end ainda podem reconstruir o caminho.

## Seleção da arquitetura

| Padrão | Propriedade obtida | Nova confiança/falha | Uso adequado |
|---|---|---|---|
| Standard Tor Browser | Fingerprint compartilhada do browser e caminho com múltiplos relays | A baixa latência permite a correlação de tráfego | Navegação web anônima geral |
| Tor bridge + pluggable transport | Torna mais difícil o bloqueio/classificação direta do Tor | A bridge/transport ainda pode ser detectada; a bridge aprende a origem | Redes censuradas |
| Onion service | Oculta o IP do serviço; evita o exit; autentica a identidade onion | A chave onion e o endpoint do servidor tornam-se ativos críticos | Publicação privada, recebimento ou administração |
| Independent ingress + egress relays | Normalmente, nenhum relay único vê a origem e o destino | Os operadores podem conspirar; o timing atravessa ambos | Aplicações suportadas de alto desempenho |
| Oblivious HTTP | Separa o IP de origem da requisição HTTP stateless criptografada | Requer suporte da aplicação, do relay e do gateway | Telemetria, consultas e envios sem estado de sessão |
| VPN-only workload namespace | Ausência de uma rota para rede clara imposta pelo kernel | A VPN ainda vê ambas as extremidades; o host/root continua confiável | Ferramentas de engagement autorizado e egress fixo |
| Disposable remote browser | O destino é isolado do browser/endpoint local | O provedor do workspace vê a atividade e a identidade de login | Sites/arquivos não confiáveis e pesquisa controlada |
| I2P internal service | Túneis overlay de entrada/saída separados; sem exits oficiais | Ecossistema menor/diferente; comportamento de peers de longa duração | Serviços nativos do I2P, não substituição da web comum |
| Mixnet/asynchronous delivery | Delay, batching e cover traffic resistem à análise de timing | Alta latência, aplicações limitadas e menor maturidade | Mensagens/tarefas que não precisam de interação |

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
Apple Private Relay é um exemplo implementado: a Apple opera a entrada, enquanto um provedor de conteúdo diferente opera a saída; portanto, nenhum dos dois normalmente vê o IP do cliente e o destino da navegação ao mesmo tempo.<sup>[[1]](#references)</sup> Este é um serviço de privacidade específico do Safari/DNS, não uma rede de anonimato para todos os dispositivos, e preserva deliberadamente uma região aproximada.

Oblivious HTTP (OHTTP) padroniza um padrão de aplicação mais restrito. O relay vê o cliente e o tráfego criptografado para o gateway; o gateway descriptografa a mensagem HTTP, mas vê o relay, não o cliente. A RFC 9458 alerta que isso requer suporte voluntário do relay/gateway, é mais adequado para requests sem cookies/autenticação/estado de sessão e exclui a análise de tráfego de suas garantias.<sup>[[2]](#references)</sup>

### Checklist de design

1. Defina as mensagens exatas da aplicação a serem protegidas; não faça proxy silenciosamente de sessões web autenticadas arbitrárias.
2. Use organizações de entrada e saída operadas de forma independente, com administração, credenciais, logging e controle legal separados sempre que possível.
3. Criptografe o request da aplicação para o gateway para que a entrada não possa lê-lo.
4. Remova headers de encaminhamento derivados do cliente, identificadores TLS e tokens estáveis por usuário na camada apropriada.
5. Evite chaves exclusivas, cookies ou campos de payload que permitam ao gateway religar requests apesar da separação de transporte.
6. Agregue, minimize e expire os logs de ambos os lados; documente os riscos de conluio e divulgação compulsória.
7. Faça padding ou batching somente de acordo com um protocolo revisado. Traffic shaping criado manualmente pode gerar uma assinatura exclusiva sem impedir a correlação.
8. Teste com requests canary controlados e compare o que o cliente, a entrada, o gateway e o alvo registram.

Para navegação interativa comum, use Tor Browser em vez de inventar um proxy OHTTP privado. OHTTP protege uma transação de aplicação compatível, não uma identidade completa de browser.

## Enforce a rota por workload

Um kill switch baseado apenas em rotas de host mutáveis pode falhar durante a renovação de DHCP, suspensão/retomada, alterações de IPv6 ou uma falha do túnel. Um padrão Linux mais forte fornece a um container ou network namespace apenas uma interface loopback e uma interface de túnel. O WireGuard documenta que uma interface pode ser criada em um namespace físico, movida para um namespace de workload e manter seu socket UDP criptografado no namespace original.<sup>[[3]](#references)</sup>

### Padrão de deployment

1. Faça a primeira implementação em um host descartável/com console local; erros de namespace podem remover o acesso remoto.
2. Coloque a interface física Ethernet/Wi-Fi e o DHCP/supplicant em um namespace **físico**.
3. Crie a interface WireGuard nesse local para que seu socket de transporte criptografado tenha acesso à rede física.
4. Mova somente a interface WireGuard para o namespace de **workload** e torne-a a única rota padrão.
5. Forneça ao workload um resolver específico do namespace, acessível somente pelo túnel. Considere explicitamente o IPv6.
6. Execute o container de browser/tool nesse namespace sem host networking, capability privilegiada, diretório de browser compartilhado ou agente de credenciais pessoais.
7. Pare o túnel e verifique que o workload não consegue resolver nem conectar-se a um endpoint IPv4 ou IPv6 controlado.
8. Teste roaming de endpoint, renovação de DHCP, suspensão/retomada e tratamento de captive portal fora do namespace de workload.
9. Registre o hash da configuração de namespace/túnel e o endereço de egress aprovado para accountability do engagement.

Isso fornece **enforce da rota**, não anonimato perante a VPN ou o bastion do engagement. Um host/root comprometido pode inspecionar ou alterar namespaces.

## Tor bridges e pluggable transports

Bridges são relays de entrada Tor não públicos. Pluggable transports alteram o tráfego do primeiro salto, dificultando bloqueios simples ou a classificação do protocolo. Eles não adicionam camadas de relay anônimas após a entrada e não impedem um observador capaz de realizar uma correlação temporal mais ampla.

| Transport | Abordagem do primeiro salto | Tradeoff prático |
|---|---|---|
| **obfs4** | Faz o tráfego parecer aleatório e resiste a probing ativo | Um endereço de bridge conhecido ainda pode ser bloqueado |
| **Snowflake** | Usa proxies WebRTC voluntários de curta duração para alcançar uma bridge | O desempenho varia; existem padrões de broker/STUN/WebRTC |
| **WebTunnel** | Transporta o tráfego da bridge em um túnel WebSocket semelhante a HTTPS | Depende de um front web acessível e ainda pode ser classificado |

O Tor Project descreve Snowflake e WebTunnel como transports de circumvention de censura, não como indistinguibilidade perfeita.<sup>[[4]](#references)</sup>

### Workflow seguro

1. Comece com a conexão direta do Tor Browser. Adicione uma bridge somente quando o bloqueio ou a visibilidade no modelo de observador local justificar isso.
2. Use transports integrados ou linhas de bridge obtidas por canais do Tor Project. Não baixe binários de transport aleatórios nem listas públicas de bridges em fóruns.
3. Tente a opção compatível menos complexa que se conecte de forma confiável; registre o motivo da escolha.
4. Mantenha o Tor Browser padronizado no restante. Uma bridge não torna extensões personalizadas, logins de contas ou configurações incomuns do browser seguros.
5. Teste a reconexão e a correção do relógio. Não alterne transports repetidamente de uma forma que envie uma sequência distintiva ao mesmo observador local.
6. Reavalie se o censor ou a política de rede mudar; o uso pode ser sensível ou restrito em alguns locais.

## Onion services como rendezvous privado

Um onion service cria circuitos Tor de saída para introduction points e rendezvous relays; portanto, não precisa de uma porta pública de entrada e não expõe o IP do servidor por meio do protocolo onion. O tráfego cliente-serviço permanece dentro do Tor e o endereço onion autentica a chave do serviço.<sup>[[5]](#references)</sup>

Para um portal de recebimento legítimo, repositório privado, interface administrativa ou entrega de evidências de engagement:

1. Execute a aplicação em um host/VM dedicado e faça bind dela ao loopback ou a um Unix socket isolado.
2. Instale o Tor a partir de seu repositório oficial e siga a configuração oficial de onion service v3; nunca use instruções obsoletas de v2.
3. Proteja a chave privada do onion service como uma chave de TLS/assinatura. Faça backup somente se uma identidade estável for necessária.
4. Adicione autorização de cliente do onion service para um grupo fechado e entregue as credenciais por um canal autenticado de forma independente.<sup>[[6]](#references)</sup>
5. Impedir que a origem busque fontes de terceiros, analytics, updates ou webhooks que revelem seu IP público ou a conta do operador.
6. Implemente autenticação e autorização também na aplicação; possuir o endereço onion não é controle de acesso.
7. Aplique patches, rate-limit e monitore o serviço sem incorporar telemetria de terceiros.
8. A partir de um contexto de teste separado, confirme que DNS, email, páginas de erro, metadados de arquivos e headers de resposta não divulgam a origem.
9. Para uso em red team, liste o serviço, proprietário, finalidade e horário de shutdown no ROE. Não o use para ocultar C2 fora do escopo.

## Browser remoto e workspace descartável

Um browser remoto move a renderização e o conteúdo arriscado para longe do endpoint local e pode apresentar um egress cloud específico do engagement. Ele protege o dispositivo local contra determinados conteúdos e persistência; não torna o operador anônimo perante o provedor do workspace. A AWS, por exemplo, documenta a coleta de dados de portal, identidade, política, preferências e logs de sessão, embora a instância de browser descartável seja eliminada ao final da sessão.<sup>[[7]](#references)</sup>

Use um workspace controlado pela organização por engagement, restrinja downloads/uploads/clipboard, desative provedores de identidade pessoais, envie seu egress fixo pelo bastion aprovado e expire o workspace após a exportação das evidências. Trate o console do provedor, o IdP e o administrador como observadores.

## I2P e overlays internos

O I2P cria túneis unidirecionais separados de entrada e saída e não possui exits oficiais na camada de rede; ele é principalmente destinado a serviços dentro do I2P.<sup>[[8]](#references)</sup> Não é uma forma mais rápida de acessar a Internet pública. Outproxies introduzem um ponto de confiança, e o threat model oficial solicita mais pesquisa e não afirma anonimato perfeito.

Use I2P somente quando ambas as extremidades oferecerem suporte intencional a ele, isole seu router de longa duração das aplicações pessoais e entenda que peers/redes locais podem observar a participação no I2P. Não aumente a quantidade de hops nem ajuste a seleção de peers sem evidências: configurações incomuns podem reduzir o desempenho e o anonymity set.

## Operações resistentes à correlação

- Prefira uma configuração de cliente comum e compatível a um build exclusivo.
- Separe as identidades no endpoint; nenhuma topologia de routing corrige reutilização de conta, pagamento, recuperação ou conteúdo.
- Para tarefas não interativas, prefira um protocolo assíncrono/mixnet revisado a adicionar manualmente delays ou tráfego falso.
- Evite operar identidades supostamente separadas em um padrão sincronizado a partir do mesmo contexto físico.
- Use um gate de exportação unidirecional: conteúdo não confiável entra em um renderer descartável; somente um resultado revisado e sanitizado sai.
- Mantenha os relógios corretos para a segurança do protocolo, mas remova timestamps precisos desnecessários dos artefatos publicados.
- Minimize a duração das sessões e a infraestrutura obsoleta sem rotação rápida de “fast-flux”, que é chamativa e prejudica a accountability.

## Técnicas que não podem usar terceiros não envolvidos

Estas são técnicas reais de adversários, não técnicas imaginárias ou irrelevantes. Sua mecânica e detecção são abordadas em [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) e nos [estudos de caso de APT](government-and-apt-case-studies.md). Durante um exercício autorizado, reproduza seu comportamento observável com substitutos próprios:

- modele a churn de exits residenciais/móveis com pools de relays controlados, nunca com mercados de consentimento incerto;
- modele open proxies, routers comprometidos e botnets com VMs/routers próprios;
- modele cloud accounts roubadas com um tenant de exercício designado e uma identidade de vítima sintética;
- modele domain fronting em um reverse proxy próprio, em vez de um CDN que não consentiu;
- modele Wi-Fi de terceiros com dois APs isolados pertencentes ao laboratório;
- trate encryption personalizada, cadeias de multi-VPN e rotação de identificadores como hipóteses de teste cujo fluxo, conta e artefatos de endpoint continuam detectáveis.

Para um red team autorizado, qualquer tentativa de tornar o tráfego menos reconhecível deve ser um objetivo explícito de detecção no ROE, ter um mapa de atribuição mantido pelo controller e incluir um mecanismo de parada/deconfliction.

## Matriz de verificação

| Teste | Resultado esperado | A falha significa |
|---|---|---|
| Túnel/bridge interrompido | O workload não possui caminho direto IPv4/IPv6/DNS | O enforce da rota está incompleto |
| Log do alvo inspecionado | Somente a identidade de egress/aplicação planejada aparece | Leaked de header, rota ou conta |
| Log da entrada inspecionado | A origem está presente; o alvo/request em claro está ausente | A divisão de confiança falhou na entrada |
| Log da saída inspecionado | O relay/request está presente; a identidade da origem está ausente | A divisão de confiança falhou na saída |
| Origem onion escaneada externamente | Nenhum serviço de origem público está acessível/vinculado | A origem vazou ou possui dual-homing |
| Sessão descartável encerrada | O estado da instância desapareceu; as evidências aprovadas foram retidas separadamente | O limite de persistência falhou |
| Consulta do controller exercida | A atividade é associada prontamente ao engagement/operador | A accountability do red team falhou |

## References

- [1] [Segurança de Plataforma Apple — segurança do iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing e Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake e pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Como funcionam os Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Configurações avançadas de Onion Service e autorização de cliente](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Criptografia de dados no Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
