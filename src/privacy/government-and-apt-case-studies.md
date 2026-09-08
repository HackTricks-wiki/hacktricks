# Estudos de caso de governos e APT

{{#include ../banners/hacktricks-training.md}}

Esses casos públicos mostram como técnicas de privacidade distintas são combinadas em operações reais. Os rótulos de atribuição são os usados pelos investigadores ou governos citados; um endereço IP, a sobreposição de ferramentas ou a compatibilidade geopolítica, por si só, não constituem atribuição conclusiva.

## APT28: acesso Wi-Fi remoto pelo vizinho mais próximo

**Descoberta pública.** A Volexity atribuiu uma intrusão de 2022 ao GruesomeLarch/APT28. Depois que o acesso à Internet com uma credencial validada foi bloqueado por MFA, o ator comprometeu organizações próximas ao alvo e alcançou o Wi-Fi corporativo do alvo a partir de um host dual-homed próximo. O caminho pelo Wi-Fi aceitava a credencial sem o MFA exigido externamente.<sup>[[1]](#references)</sup>

**Efeito sobre a privacidade.** O acesso final originou-se dentro do alcance físico do rádio, e as organizações intermediárias eram vítimas. A operação evitou deslocamentos e fez com que a geolocalização convencional por IP apontasse para um vizinho.

**O que o expôs.** O alerta do alvo, a investigação de host/rede, a atividade da credencial, a topologia das interfaces e a proximidade física tiveram de ser analisados como uma única cadeia. O fato anômalo não era apenas um novo IP; era uma identidade legítima chegando por meio de um contexto incomum de Wi-Fi/dispositivo enquanto sistemas próximos estavam comprometidos.

**Lição defensiva.** Aplique acesso baseado em certificado/dispositivo ao Wi-Fi, correlacione RADIUS com NAC/MDM e o contexto físico, e investigue a infraestrutura vizinha em vez de presumir que o último salto é o operador.

## APT28: infraestrutura criminosa do Moobot reutilizada pelo GRU

**Descoberta pública.** Em fevereiro de 2024, o US Department of Justice descreveu uma botnet com centenas de roteadores Ubiquiti EdgeOS. Atores criminosos instalaram o Moobot em roteadores que mantinham credenciais administrativas padrão conhecidas; a Unidade 26165 do GRU então adicionou scripts e arquivos, transformando uma botnet criminosa existente em uma plataforma de espionagem usada para spearphishing e roubo de credenciais.<sup>[[2]](#references)</sup>

**Efeito sobre a privacidade.** O GRU não construiu toda a infraestrutura por conta própria. O uso de uma frota já comprometida colocou endereços residenciais e de pequenos escritórios não relacionados entre o ator e os alvos, misturou atividade estatal com atividade criminosa e reduziu artefatos de registro específicos do ator.

**O que o expôs.** Arquivos dos roteadores, comportamento de controle do malware e informações de roteamento sem conteúdo sustentaram a investigação. A operação de interrupção alterou temporariamente as regras do firewall e removeu arquivos maliciosos, enquanto o DOJ alertou que credenciais padrão inalteradas poderiam permitir uma reinfecção.

**Lição defensiva.** Substitua roteadores sem suporte, remova a administração exposta à Internet, altere os padrões, aplique patches, colete dados de configuração/fluxo dos dispositivos de borda e procure comportamentos de frota. “IP residencial dos EUA” não é evidência de que o operador seja dos EUA.

## Volt Typhoon: KV Botnet mais living off the land

**Descoberta pública.** O DOJ e um comunicado conjunto da CISA descreveram o Volt Typhoon, patrocinado pelo Estado da RPC, usando a KV Botnet, composta principalmente por roteadores Cisco e NETGEAR SOHO comprometidos e em fim de vida útil, para ocultar a origem da RPC em atividades direcionadas à infraestrutura crítica. Dentro das vítimas, o ator favorecia contas válidas e ferramentas de administração integradas; as agências relataram que o acesso em alguns ambientes durou pelo menos cinco anos.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
```text
PRC operator -> encrypted KV path -> compromised SOHO exit -> edge service
|
valid accounts + native tools
```
**Efeito sobre a privacidade.** O caminho semelhante ao ORB ocultou a origem, enquanto o living-off-the-land reduziu binários novos e oportunidades de detecção por assinatura após o acesso. O ocultamento da rede e do endpoint reforçaram-se mutuamente.

**O que o expôs.** A estrutura de roteadores/controladores, a coleta técnica autorizada judicialmente, a atividade recorrente e a análise entre vítimas foram mais importantes do que um único IOC. Reiniciar um roteador removeu o malware KV volátil nos casos descritos, mas não corrigiu a exposição subjacente do dispositivo em fim de vida.

**Lição defensiva.** Substitua dispositivos de borda EOL, centralize logs de autenticação e de dispositivos de rede, estabeleça uma baseline do comportamento de administradores, restrinja a conectividade de saída e procure sequências comportamentais nas camadas de identidade, endpoint e rede.

## Redes ORB associadas à China: infraestrutura como serviço

**Descoberta pública.** A Mandiant descreveu um ecossistema de redes ORB usado por vários atores de espionagem associados à China. Redes provisionadas usavam nós VPS alugados; redes não provisionadas usavam IoT e roteadores comprometidos; redes híbridas combinavam ambos. ORB3/SPACEHOP apoiava atividades associadas a APT5/APT15. ORB2/FLORAHOX combinava um servidor de administração, servidores alugados, uma camada Tor personalizada e dispositivos Cisco, ASUS e DrayTek comprometidos. A Mandiant avaliou que algumas redes eram administradas de forma independente e alugadas para vários atores APT.<sup>[[5]](#references)</sup>

**Efeito sobre a privacidade.** A infraestrutura tornou-se uma fronteira de serviço. Um operador podia obter saídas geográficas/residenciais sem manter a frota de vítimas, enquanto muitos clientes compartilhando-a enfraqueciam o mapeamento simples entre ator e IP. A rápida rotatividade da frota acelerava a “extinção de IOCs”.

**O que a expôs.** A topologia da rede, imagens clonadas de servidores, portas/serviços, relações entre controladores, implantes em roteadores e padrões de ciclo de vida continuavam agrupáveis. A Mandiant relatou que alguns IPs de nós permaneceram em um ORB por apenas 31 dias.

**Lição defensiva.** Rastreie um ORB como uma entidade em mudança: funções dos nós, fingerprints de serviços, relações upstream, comportamento de scanning e ritmo de rotação. A expiração de um indicador de IP deve atualizar o cluster, não apagar o caso.

## Sistema global de espionagem da RPC: roteadores, links confiáveis e espelhamento de tráfego

**Descoberta pública.** Um advisory multinacional de 2025 descreveu atividades que se sobrepunham a nomes usados em relatórios comerciais, incluindo Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 e GhostEmperor. As agências relataram VPSs alugados e roteadores intermediários comprometidos usados para alcançar provedores de telecomunicações e de rede. Os atores pivotavam por links confiáveis entre provedores e clientes, alteravam rotas, criavam túneis GRE/IPsec, usavam containers de dispositivos e habilitavam SPAN/RSPAN/ERSPAN ou captura nativa de pacotes para coletar autenticação e tráfego de clientes.<sup>[[13]](#references)</sup>

**Efeito sobre a privacidade.** Um roteador comprometido é simultaneamente um relay, um ponto de observação e um participante confiável da rede. Interconexões privadas podem contornar controles projetados em torno da Internet pública, enquanto o espelhamento de tráfego coleta credenciais sem implantar um agente no endpoint.

**O que os expõe.** Diffs de configuração, administração SNMP/SSH/web inesperada, novas rotas/túneis estáticos, sessões de espelhamento, containers Guest Shell, arquivos PCAP, alterações nos destinos TACACS+/RADIUS e logging desabilitado. O advisory enfatiza que alguns roteadores intermediários não faziam parte de uma botnet pública anteriormente nomeada; portanto, a ausência de indicadores ORB conhecidos não era exculpatória.

**Lição defensiva.** Use administração out-of-band, logs centralizados de configuração/autenticação, verificações de integridade de imagens assinadas e do runtime, restrições ao egress das interfaces de gerenciamento e alertas para alterações de rota/espelhamento/túnel/AAA. Amplie o escopo de um comprometimento suspeito para os peers confiáveis antes da remoção.

## UNC3886 RedPenguin: backdoors passivos em roteadores de ISPs

**Descoberta pública.** A Mandiant atribuiu backdoors personalizados derivados do TINYSHELL em roteadores Juniper MX em fim de vida ao UNC3886. O conjunto incluía implantes ativos e passivos, nomes que imitavam daemons legítimos, comportamento de desabilitação de logs, process injection em um processo confiável, capacidade de proxy SOCKS e infraestrutura avaliada como nós de staging ORB. Variantes passivas inspecionavam pacotes por meio de `libpcap` e eram ativadas apenas após um padrão mágico; uma delas podia mudar para um callback ativo fornecido no trigger.<sup>[[14]](#references)</sup>

**Efeito sobre a privacidade.** Um implante passivo não possui beacon periódico para ser descoberto. Ele compartilha portas/tráfego com um dispositivo de rede real, ativa-se brevemente e pode fazer relay por meio de um ORB em vez de se conectar diretamente a um controlador final.

**O que os expõe.** Análise de memória, diferenças entre o código em disco e o código em execução, filtros de captura de pacotes/comportamento inesperado de sockets, nomes de processos/arquivos que apenas se aproximam dos nomes de daemons legítimos, administração por meio de servidores de terminal, logs ausentes e a relação em dois estágios entre nós de staging e um controlador backend.

**Lição defensiva.** Colete memória além de evidências do filesystem/configuração, compare processos/módulos com uma imagem conhecida como legítima, monitore o uso de captura de pacotes/filtros de sockets, proteja servidores de terminal de gerenciamento e substitua hardware de rede EOL. Uma busca limpa por outbound beacons não é garantia de integridade.

## APT29: domain fronting com Tor

**Descoberta pública.** O MITRE registra o uso, pelo APT29, do transporte plugável `meek` do Tor para fazer domain fronting do tráfego C2. O nome TLS externo aparentava ser um domínio permitido hospedado em uma CDN, enquanto o host HTTP interno selecionava a rota real.<sup>[[6]](#references)</sup>

**Efeito sobre a privacidade.** Um observador responsável pela filtragem podia ver uma front/CDN comum em vez do destino interno, e bloqueá-la poderia causar danos colaterais.

**O que o expõe.** A CDN pode observar a divergência de roteamento, e um defensor com visibilidade de endpoint ou TLS obtida legalmente pode correlacionar processo, autoridade, duração da conexão, padrão de bytes e atividade posterior. Mudanças na política do provedor podem desabilitar a técnica.

**Lição defensiva.** Não dependa apenas de allowlisting de SNI. Aplique egress com reconhecimento da aplicação, compare as identidades TLS e HTTP quando visíveis e associe o evento de rede ao processo que o iniciou.

## APT41 e outros dead-drop resolvers

**Descoberta pública.** O MITRE documenta que o APT41 usou sites legítimos, incluindo GitHub, Pastebin, Microsoft TechNet, Cloudflare e fóruns comunitários, para publicar ou recuperar informações de C2. Outras ferramentas associadas a Estados usaram posts, documentos e redes sociais de forma semelhante.<sup>[[7]](#references)</sup>

**Efeito sobre a privacidade.** Um binário contém um serviço/objeto legítimo em vez de um endereço C2 estável. O objeto pode ser editado para rotacionar a infraestrutura, e a solicitação inicial se mistura ao tráfego TLS comum.

**O que o expõe.** O objeto ou identificador da conta é estável; processos raros o baixam repetidamente; o conteúdo é decodificado; e uma segunda conexão de saída ocorre em seguida. Registros da conta e da API do provedor podem vincular a publicação ao operador.

**Lição defensiva.** Preserve os caminhos completos do proxy/IDs dos objetos e a process lineage do endpoint. Um evento no nível do domínio, como “conectou-se ao GitHub”, é genérico demais.

## Turla: C2 por endereço de satélite

**Descoberta pública.** A Kaspersky relatou que o Turla abusava de transmissões downstream não criptografadas de serviços antigos de Internet unidirecional DVB-S. Um operador dentro da área de cobertura do satélite podia selecionar o endereço de um assinante legítimo e receber respostas transmitidas para ele, fazendo o C2 parecer hospedado atrás de um provedor de satélite em outra região.<sup>[[8]](#references)</sup>

**Efeito sobre a privacidade.** O endereço aparente do servidor não identificava o receptor, e processos convencionais de apreensão de hospedagem/WHOIS eram menos úteis.

**O que o expõe.** O ator ainda precisava de um caminho para a solicitação de saída, o roteamento era assimétrico, o assinante legítimo não iniciava a troca de C2 e uma investigação de RF/provedor podia restringir a área de recepção.

**Lição defensiva.** Trate a geolocalização como uma hipótese. Valide a simetria do caminho, o RTT, a propriedade do roteamento e se o endpoint alegado poderia realmente produzir o serviço observado.

## Cyclops Blink e VPNFilter: dispositivos de borda como cobertura duradoura

**Descoberta pública.** Um advisory de 2022 da NCSC/CISA/FBI/NSA descreveu o malware modular Cyclops Blink do Sandworm em dispositivos WatchGuard, implantado de forma persistente como uma atualização de firmware e capaz de adicionar módulos. O DOJ descreveu separadamente a botnet VPNFilter anterior do APT28, composta por roteadores e dispositivos NAS, como capaz de coletar inteligência, realizar atividades destrutivas e promover misattribution.<sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>

**Efeito sobre a privacidade.** Dispositivos de borda estão continuamente online, são confiáveis como infraestrutura e têm pouca cobertura de EDR. A persistência no firmware pode sobreviver a um reinício comum e transformar o dispositivo da vítima em relay ou ponto de controle.

**O que os expõe.** Integridade do firmware, protocolo de implante específico do fornecedor, exposição inesperada de gerenciamento, alterações de configuração e beaconing de saída. Dispositivos de borda devem ser objetos forenses, não uma infraestrutura transparente.

## DPRK: camadas de identidade, rede e finanças

**Descoberta pública.** Casos do DOJ descrevem trabalhadores da DPRK obtendo empregos remotos usando material de identidade falso ou roubado e VPNs, recebendo criptomoedas, dividindo transferências, trocando ativos/chains, usando NFTs e misturando os rendimentos. Outros casos descrevem traders OTC e empresas de fachada convertendo crypto roubada em compras. O Treasury e o FBI vincularam publicamente os rendimentos de Lazarus/TraderTraitor a mixers e identificaram endereços de grandes roubos.<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup>

**Efeito sobre a privacidade.** Isto não é “uma private coin”. É uma cadeia multidomínio: a persona e o acesso remoto ocultam a localização do trabalhador; a crypto movimenta valor; as camadas rompem narrativas transacionais simples; traders OTC/empresas de fachada fazem a ponte para bens e moeda fiduciária.

**O que os expõe.** Anomalias do empregador/dispositivo, facilitadores reutilizados, continuidade de tempo/valor na blockchain, registros de exchanges/bridges, endereços sancionados, identidade da conta e registros de remessa/empresa reconectam a cadeia.

**Lição defensiva.** As equipes de contratação, IAM, endpoint, folha de pagamento, blockchain e sanções precisam de um modelo de caso compartilhado. Mais detalhes aparecem em [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md).

## Padrões entre os casos

| Padrão | Exemplos de APT | Adaptação do defensor |
|---|---|---|
| A saída é outra vítima | APT28/Moobot, Volt Typhoon/KV, ORBs | investigue e corrija a saída; não a equipare à localização do ator |
| Os controles diferem conforme a fronteira | APT28 nearest neighbor | dê ao acesso interno/sem fio a mesma garantia de identidade do acesso à Internet |
| O serviço legítimo é uma camada de roteamento | APT29, APT41 | preserve o contexto de objeto/caminho/processo, não apenas o domínio de destino |
| Dispositivos de borda não têm telemetria | KV, Moobot, Cyclops Blink, ORBs | centralize logs de config/auth/fluxo e verifique firmware/inventário |
| A infraestrutura é compartilhada e de curta duração | ORBs associados à China | agrupe comportamento/topologia e acompanhe alterações de função ao longo do tempo |
| Várias separações fracas se combinam | Personas da DPRK + VPN + crypto + OTC | una evidências de identidade, dispositivo, rede, pagamento e aspectos físicos |

## References

- [1] [Volexity — O ataque Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [US DOJ — Interrupção da botnet de roteadores Moobot controlada pelo GRU](https://www.justice.gov/archives/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian)
- [3] [US DOJ — Interrupção da botnet KV da RPC](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical)
- [4] [CISA AA24-038A — Atores da RPC comprometem e mantêm acesso persistente à infraestrutura crítica dos EUA](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [5] [Google Cloud/Mandiant — Atores de espionagem associados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [6] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [7] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [Kaspersky Securelist — Turla por satélite](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [9] [CISA/NCSC/FBI/NSA — Advisory sobre Cyclops Blink AA22-054A](https://www.cisa.gov/sites/default/files/publications/AA22-054A%20New%20Sandworm%20Malware%20Cyclops%20Blink%20Replaces%20VPN%20Filter.pdf)
- [10] [US DOJ — Interrupção do VPNFilter do APT28](https://www.justice.gov/archives/opa/pr/justice-department-announces-actions-disrupt-advanced-persistent-threat-28-botnet-infected)
- [11] [US DOJ — Representante do Foreign Trade Bank da DPRK acusado de conspirações de lavagem de crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [12] [US Treasury — Sanções contra Blender.io e fundos de Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [13] [CISA AA25-239A — Combate ao comprometimento de redes em todo o mundo por atores patrocinados pelo Estado chinês](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [14] [Google Cloud/Mandiant — Ghost in the Router: UNC3886 tem como alvo roteadores Juniper](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
{{#include ../banners/hacktricks-training.md}}
