# Catálogo de técnicas de acesso anônimo à Internet

Este é o inventário canônico de caminhos de acesso. Ele abrange **famílias** de protocolos e operações, não todos os nomes de fornecedores. Nenhum caminho da Internet garante anonimato: evidências de conta, navegador, endpoint, temporização, pagamento, control plane da cloud e evidências físicas podem derrotar uma rota aparentemente perfeita.

Cada entrada usa os mesmos campos. “Procedimento” significa uma implantação legal ou uma emulação em laboratório próprio. Quando a técnica real depende de comprometer um roteador, roubar acesso ou abusar de um intermediário que não consentiu, a reprodução substitui esses sistemas por sistemas pertencentes ao exercício.

## Matriz de cobertura

| Família | O destino vê | Propriedade mais forte | Velocidade | Tratamento |
|---|---|---|---|---|
| Shared NAT/CGNAT | endereço público compartilhado | ambiguidade entre assinantes | alta | implantável |
| VPN, VPS, SOCKS/HTTP/SSH proxy | endereço do relay | separação rápida do endereço de origem | alta | implantável |
| Multi-hop/split relay, MASQUE | proxy final | divisão de conhecimento ou túnel IP completo | alta/moderada | implantável com relays confiáveis |
| Tor, bridge, onion service | exit ou identidade onion | caminho multiparticipante e navegador comum | moderada | implantável |
| I2P, GNUnet, mixnet | peer/gateway do overlay | resistência de overlay ou de temporização | baixa/variável | específica da aplicação |
| OHTTP/ODoH, Private Relay | gateway/egress | particionamento de origem/requisição | alta | somente aplicações compatíveis |
| Public Wi-Fi, travel router | endereço do local/túnel | alteração de localização/caminho de acesso | alta | requer permissão |
| Cellular/eSIM, satellite | endereço da operadora/provedor | uplink físico independente | alta/variável | assinatura/provedor observam |
| Remote browser/jump host | workspace remoto | separação de endpoint e egress | alta | implantável |
| Residential/mobile proxy | endereço de rede residencial/operadora | aparência de rede de consumidor | alta | consentimento/proveniência críticos |
| ORB/compromised relay | endereço de outra vítima | ocultação da origem e reputação emprestada | alta | reprodução somente em laboratório próprio |
| CDN/fronting/redirector | endereço frontal da CDN | proteção da infraestrutura back-end | alta | requer aprovação do provedor/proprietário |
| Fast flux/DGA/dead drop | nó/serviço rotativo | resistência à descoberta da infraestrutura | variável | reprodução somente em laboratório próprio |
| Drop/nearest-neighbor | endereço adjacente ao alvo | atravessa fronteira geográfica/de rede | alta | somente laboratório no local próprio |
| Store-and-forward/offline | gateway ou receptor físico | reduz vínculo de temporização interativa | baixa | específica da aplicação |
| Pluggable/refraction transport | entrada Tor ou proxy de desvio cooperante | alcançabilidade resistente à censura | variável | cliente compatível ou laboratório de pesquisa |
| IPFS gateway/PIR/remote fetcher | gateway ou serviço da aplicação | particionamento de publicador/consulta/requisição | variável | somente aplicação delimitada |
| Anycast/QUIC/MPTCP | broker estável ou múltiplos subflows | rendezvous e continuidade da sessão | alta | disponibilidade, não anonimato |
| CI/CD automation runner | endereço do runner hospedado | egress descartável e atribuível | alta | somente workflow próprio |
| Non-IP local first hop | gateway da organização | remove a pilha de Internet do sensor | baixa | implantação aprovada pelo proprietário |

## NAT compartilhado direto e Carrier-Grade NAT

**Mecânica:** vários usuários compartilham um endereço público; o provedor de acesso mapeia endereços e portas do assinante para a tupla pública.

**Prós:** rápido; nenhum cliente especial; somente o IP no destino pode identificar uma residência, local ou pool da operadora.

**Contras:** o provedor pode conservar os mapeamentos de assinante/porta/horário; contas e fingerprints permanecem; outros usuários podem prejudicar a reputação do endereço.

**Procedimento:** (1) confirme se o acesso autorizado usa NAT/CGNAT; (2) registre o IP público e a porta de origem exatos em um endpoint próprio; (3) mantenha as identidades de aplicação separadas; (4) não trate o endereçamento compartilhado como controle de privacidade; (5) use um caminho mais forte se o ISP não puder conhecer os destinos.

**Detecção:** os destinos devem conservar a porta de origem e o horário preciso, não apenas o IP. Os provedores correlacionam logs de alocação NAT; investigadores associam evidências de conta/dispositivo/navegador.

## VPN comercial

**Mecânica:** uma conexão full-tunnel criptografada termina na VPN; os destinos veem o egress dela. A VPN normalmente pode associar origem, temporização e destinos.

**Prós:** rápida; simples; protege contra observação passiva local; exits estáveis ou compartilhados; adequada para egress controlado de red team.

**Contras:** confiança concentrada; telemetria de cobrança/login; falhas de kill switch/DNS/IPv6; exits compartilhados frequentemente são bloqueados por reputação.

**Procedimento:** (1) identifique provedor, proprietário, jurisdição, retenção e política de assessment; (2) instale o cliente oficial assinado; (3) habilite full tunnel, always-on e comportamento fail-closed; (4) encaminhe DNS e IPv6 deliberadamente; (5) verifique IPv4/IPv6/DNS observados em um endpoint próprio; (6) interrompa/reconecte o túnel e confirme que não há fallback em claro.<sup>[[1]](#references)</sup>

**Detecção:** redes locais veem um fluxo criptografado longo para a infraestrutura da VPN; provedores têm registros de autenticação/conexão; destinos usam ASN/reputação junto com correlação de conta, TLS/browser e comportamento.

## Egress de VPN self-hosted ou VPS alugado

**Mecânica:** o operador controla um gateway WireGuard/OpenVPN ou encaminha tráfego por um servidor alugado.

**Prós:** alta velocidade previsível; endereço fixo que pode entrar em allowlist; logging/firewall personalizado; bom controle de incidentes.

**Contras:** conjunto de anonimato pequeno; tenant da cloud, pagamento, login de origem, API e histórico da imagem vinculam o operador; um servidor novo e distinto é fácil de agrupar.

**Procedimento:** (1) crie um projeto de organização específico do engagement; (2) provisione uma imagem compatível e endereço fixo; (3) restrinja a administração a MFA/chaves; (4) configure egress full-tunnel e DNS; (5) permita somente destinos delimitados quando possível; (6) teste comportamento de leak/falha; (7) retenha registros de auditoria do controller; (8) destrua credenciais e recursos no teardown.

**Detecção:** correlacione ASN de hosting, endereço visto pela primeira vez, fingerprint de certificado/serviço e comportamento de scanning; proprietários da cloud usam logs de control plane, console, billing e flow.

## HTTP CONNECT, SOCKS e encaminhamento SSH

**Mecânica:** uma aplicação solicita que um proxy abra um fluxo TCP; SOCKS também pode transportar resolução de nomes e UDP, dependendo da versão; SSH encaminha fluxos dentro de uma sessão criptografada.

**Prós:** leve; por aplicação; rápido; útil para chaining e acesso a redes segmentadas.

**Contras:** aplicações podem ignorá-lo; DNS pode vazar; o proxy vê endpoints adjacentes; o estado do navegador permanece; open proxies podem ser armadilhas ou sistemas comprometidos.

**Procedimento:** (1) implante o proxy em um host próprio; (2) exija autenticação e restrinja origem/destino; (3) configure um perfil de aplicação descartável; (4) garanta resolução DNS remota quando necessário; (5) verifique com um endpoint DNS/HTTP próprio; (6) bloqueie egress direto para o workload; (7) inspecione e altere as credenciais do proxy.

**Detecção:** identifique processos capazes de criar túneis, negociação CONNECT/SOCKS, sessões SSH longas e destinos incompatíveis com a aplicação; logs do proxy reconstroem os fluxos.

## Web proxy de reescrita de URL e extensão de proxy do navegador

**Mecânica:** um site busca um destino e reescreve links/forms por sua própria origem, ou uma extensão direciona requisições do navegador para um proxy. O destino vê o serviço, enquanto o serviço pode ver plaintext após a terminação TLS e injetar ou conservar conteúdo.

**Prós:** nenhum cliente sistêmico; rápido para navegação simples; funciona quando a instalação de VPN é impossível.

**Contras:** o proxy pode ler credenciais/conteúdo, reescrever downloads e fingerprintar usuários; scripts/WebSockets/downloads podem escapar; a extensão tem privilégios amplos; conjunto de anonimato pequeno e bloqueios frequentes.

**Procedimento:** (1) use somente um proxy operado pela organização para testes autorizados; (2) isole-o em um navegador descartável sem contas pessoais; (3) proíba a inserção de senhas e downloads sensíveis; (4) verifique em uma página própria se todo subrecurso passa pelo proxy; (5) teste WebSocket, download e comportamento de forms; (6) remova a extensão/perfil após o uso.

**Detecção:** o destino registra o proxy; proxy/DNS corporativos e inventário de extensões identificam o serviço; content-security/reporting ou subrecursos canary próprios revelam bypass direto; logs do proxy mapeiam a sessão do usuário aos alvos.

## Proxy multi-hop ou VPN multi-hop do provedor

**Mecânica:** uma entrada vê a origem, enquanto um ou mais relays de trânsito a separam de um exit que vê o destino.

**Prós:** nenhum relay comum precisa conhecer as duas pontas; falha/apreensão de um nó revela menos; geografia flexível.

**Contras:** administração/logs compartilhados anulam a separação; latência; correlação temporal; mais falhas e rotas DNS; a mesma conta/pagamento pode unir todos os hops.

**Procedimento:** (1) defina qual observador cada hop remove; (2) use relays próprios/aprovados e administrados independentemente quando a separação for importante; (3) imponha acesso somente de entrada a partir do workload; (4) garanta que cada relay alcance apenas o hop seguinte; (5) verifique logs em todas as camadas; (6) pare cada hop e confirme comportamento fail-closed. Reproduza com [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detecção:** correlacione temporização/volume de NetFlow adjacente, handshakes de proxy repetidos e infraestrutura de controller comum; não infira a geografia do operador a partir do exit.

## Relay de aplicação com conhecimento dividido e OHTTP

**Mecânica:** o cliente criptografa uma mensagem HTTP stateless para um gateway e a envia por um relay. O relay vê o IP do cliente, mas não a requisição; o gateway vê a requisição, mas normalmente apenas o IP do relay.

**Prós:** particionamento de privacidade forte e auditável para requisições compatíveis; menor overhead que redes de anonimato gerais.

**Contras:** não permite navegação arbitrária; cookies/autenticação podem religar sessões; conluio relay/gateway e análise de tráfego permanecem; a aplicação precisa implementá-lo.

**Procedimento:** (1) selecione uma aplicação que declare suporte à RFC 9458; (2) verifique as chaves do gateway pelo caminho oficial de configuração; (3) evite campos estáveis por usuário; (4) envie somente a requisição stateless compatível; (5) compare logs do relay, gateway e alvo; (6) teste rotação/falha de chaves sem fallback direto.<sup>[[2]](#references)</sup>

**Detecção:** endpoints expõem o processo iniciador e o relay OHTTP; gateways detectam tráfego malformado/repetido; temporização e campos estáveis de payload/conta podem correlacionar requisições.

## MASQUE CONNECT-UDP/CONNECT-IP e proxies HTTP de privacidade

**Mecânica:** HTTP Extended CONNECT sobre TLS/QUIC transporta pacotes UDP ou IP por um proxy. Pode implementar um túnel moderno semelhante a VPN e misturar o transporte com HTTP/3, mas o proxy continua sendo um observador.<sup>[[3]](#references)</sup>

**Prós:** multiplexação/roaming eficientes; suporta UDP ou IP completo; implantação pela infraestrutura HTTP moderna.

**Contras:** não é uma rede de anonimato; proxy/conta veem origem e destinos; fingerprints QUIC/HTTP e caminhos conhecidos são visíveis a endpoints/provedores.

**Procedimento:** (1) use um cliente/serviço que documente suporte às RFC 9298/9484; (2) autentique o certificado/configuração do proxy; (3) defina rotas de destino permitidas; (4) habilite DNS criptografado dentro do caminho; (5) verifique UDP, TCP, IPv6 e failover contra endpoints próprios; (6) inspecione logs de requisições e flows do proxy.

**Detecção:** endpoints veem o processo do cliente e a interface virtual; redes podem classificar QUIC/TLS sustentado para um proxy; logs do proxy expõem destino/caminho CONNECT e rotas atribuídas.

## Tor Browser

**Mecânica:** Tor seleciona relays guard, middle e exit; a criptografia em camadas limita o que cada relay vê. Tor Browser adiciona um navegador padronizado destinado a resistir a fingerprinting.

**Prós:** grande conjunto público de anonimato; nenhum relay comum conhece ambas as pontas; unlinkability do destino sem operar servidores.

**Contras:** mais lento; focado em TCP; reputação/bloqueios de exits; logins e divulgações identificam o usuário; correlação temporal de baixa latência permanece.

**Procedimento:** (1) baixe e verifique o Tor Browser do projeto; (2) mantenha os padrões e evite extensões; (3) escolha um nível de segurança apropriado; (4) crie uma identidade/sessão separada; (5) evite contas identificáveis e documentos externos ativos; (6) use HTTPS ou onion services autenticados; (7) verifique o exit somente com um endpoint próprio.<sup>[[4]](#references)</sup>

**Detecção:** redes locais podem identificar tráfego para guards conhecidos, a menos que uma bridge/transport seja usada; destinos veem exits e o comportamento do Tor Browser; observadores de ponta a ponta correlacionam temporização/volume.

## Tor bridges e pluggable transports

**Mecânica:** uma bridge não pública substitui o guard público; obfs4, Snowflake ou WebTunnel alteram o transporte do primeiro hop para resistir a bloqueio/probing simples.

**Prós:** contorna censura e oculta destinos de relays públicos óbvios; mantém o circuito Tor após a entrada.

**Contras:** padrões de transporte/descoberta de bridges continuam possíveis; desempenho variável; não acrescenta proteção contra contas ou temporização global.

**Procedimento:** (1) tente Tor direto primeiro; (2) nas configurações de Connection do Tor Browser, selecione um transport compatível integrado ou solicite uma bridge oficial; (3) não use binários/listas aleatórios; (4) conecte e execute um teste benigno; (5) teste reconexão e relógio; (6) mantenha todas as demais configurações do navegador padrão.<sup>[[5]](#references)</sup>

**Detecção:** censores usam descoberta de destino, classificação de protocolo/fluxo e probing ativo; defensores devem distinguir uso de circumvention de comprometimento e depender do processo/contexto do endpoint.

## VPN antes do Tor e Tor antes da VPN

**Mecânica:** VPN-before-Tor oculta o uso direto de Tor do ISP de acesso, mas expõe a origem à VPN. Tor-before-VPN fornece à VPN tráfego pós-Tor e frequentemente uma identidade estável de cliente/túnel.

**Prós:** remove um observador específico quando projetado corretamente; pode alcançar redes que bloqueiam uma camada.

**Contras:** complexidade, fingerprint incomum, leaks, conjunto de anonimato reduzido e falsa confiança; o Tor Project trata combinações como avançadas.<sup>[[6]](#references)</sup>

**Procedimento:** (1) escreva qual observador é removido e qual novo observador é introduzido; (2) use um ambiente descartável; (3) estabeleça somente o caminho externo pretendido; (4) imponha rotas de firewall; (5) verifique DNS/IPv4/IPv6 e a ordem de cada falha; (6) compare a visibilidade de ambos os provedores; (7) abandone a pilha se não houver vantagem mensurável.

**Detecção:** observadores local/VPN/Tor veem camadas adjacentes diferentes; a temporização permanece ponta a ponta; fingerprints incomuns de túneis aninhados e contas de provedores podem vincular sessões.

## Onion service

**Mecânica:** cliente e serviço constroem circuitos Tor até um rendezvous, ocultando o IP do serviço e evitando um exit.

**Prós:** proteção da localização da origem e do serviço; autenticação onion ponta a ponta; nenhuma porta pública de entrada; autorização opcional do cliente.

**Contras:** origem pode vazar por updates/analytics/erros; a chave onion é crítica; identidade da aplicação, temporização e comprometimento do host permanecem.

**Procedimento:** (1) isole a aplicação e faça bind somente a loopback/socket; (2) instale Tor compatível; (3) configure um onion service v3 usando instruções oficiais; (4) proteja/faça backup da chave somente se uma identidade estável for necessária; (5) adicione autorização de cliente para uso fechado; (6) remova fetches de terceiros; (7) verifique externamente que a origem não está acessível.<sup>[[7]](#references)</sup>

**Detecção:** defensores do host/rede encontram o processo/configuração Tor e circuitos de saída; erros de aplicação, DNS, certificados ou recursos de terceiros podem expor a origem.

## Serviços internos I2P

**Mecânica:** I2P usa túneis unidirecionais separados de entrada/saída para destinos dentro do overlay; outproxies para a Internet pública adicionam um ponto de confiança.

**Prós:** publicação interna descentralizada; nenhuma dependência de exit oficial; caminhos de entrada/saída separados.

**Contras:** não substitui a web geral; ecossistema menor; comportamento prolongado de peers; outproxy pode observar navegação pública.

**Procedimento:** (1) instale da fonte oficial; (2) use um contexto dedicado; (3) permita estabilização de integração/bandwidth; (4) acesse um serviço próprio nativo de I2P; (5) evite outproxies salvo necessidade explícita; (6) verifique que o desligamento não cria fallback direto; (7) inspecione logs locais de peers e serviços.<sup>[[8]](#references)</sup>

**Detecção:** redes locais veem tráfego de peers de longa duração e comportamento de bootstrap; endpoints expõem processos de router/aplicação; outproxies registram exits.

## Mixnets

**Mecânica:** pacotes de tamanho fixo, batching, atraso, reordenação e cover traffic reduzem correlação temporal; gateways conectam aplicações.

**Prós:** maior resistência à análise temporal que proxies de baixa latência; úteis para mensagens/transações assíncronas.

**Contras:** latência, overhead de bandwidth, implantação menor e limitações de aplicação; metadados de gateway/conta podem persistir.

**Procedimento:** (1) selecione um cliente mantido e uma aplicação compatível; (2) leia o threat model real; (3) instale em um compartimento separado; (4) envie dados benignos a um endpoint próprio; (5) meça latência/confiabilidade e caminho de resposta; (6) teste falha do gateway; (7) nunca desative atrasos/cover traffic apenas por velocidade.<sup>[[9]](#references)</sup>

**Detecção:** endpoints identificam o cliente; redes de acesso podem classificar gateways/cadência de pacotes; gateways e exits observam funções adjacentes, enquanto correlação ampla exige janelas estatísticas mais longas.

## GNUnet anonymous file sharing

**Mecânica:** GNUnet pode encaminhar requisições de publicação/busca/download por peers e adicionar cover traffic conforme um nível de anonimato. A documentação própria alerta que o nível padrão 1 não exige cover traffic e que análise poderosa de tráfego pode identificar a origem.<sup>[[10]](#references)</sup>

**Prós:** compartilhamento anônimo descentralizado e nativo da aplicação; requisito de cover traffic ajustável.

**Contras:** não é acesso web anônimo comum; custo de desempenho/storage; limitações de peers e análise de tráfego; a documentação de GNUnet VPN diz que seu overlay IP não fornece bom anonimato.

**Procedimento:** (1) instale um build oficial mantido; (2) isole um peer de teste; (3) limite bandwidth/storage; (4) publique um arquivo de teste inofensivo e único com um nível de anonimato escolhido; (5) recupere-o de outro peer próprio; (6) registre cover traffic e latência; (7) não alegue que o componente IP VPN fornece anonimato equivalente.

**Detecção:** bootstrap de peers, tráfego do overlay, datastore/processo local e identificadores de arquivo; um observador amplo pode analisar volume contra o cover traffic.

## DNS criptografado, ODoH e ECH

**Mecânica:** DoH/DoT/DoQ criptografam para um resolver; ODoH divide o endereço do cliente da consulta entre proxy e resolver; ECH criptografa o ClientHello/nome de servidor TLS interno.

**Prós:** remove DNS/SNI em plaintext de alguns observadores locais; ODoH particiona o conhecimento de origem/consulta.

**Contras:** não é um caminho de anonimato IP; resolver/proxy/servidor mantêm suas funções; IP de destino, temporização, volume e endpoint permanecem; fallback pode vazar.

**Procedimento:** (1) escolha se o DNS será controlado pelo OS, aplicação ou túnel; (2) habilite modo estrito criptografado ou ODoH compatível; (3) teste um domínio próprio único; (4) capture localmente para confirmar ausência de consulta em claro; (5) falhe o resolver e verifique o comportamento pretendido; (6) para ECH, confirme nos diagnósticos do servidor a aceitação do ClientHello interno.<sup>[[11]](#references)</sup>

**Detecção:** logs do endpoint/resolver expõem consultas; redes identificam endpoints de resolvers criptografados e flows de destino; o estado de ECH é visível em endpoints/CDN mesmo quando oculto no caminho.

## Relay de privacidade com provedores divididos

**Mecânica:** produtos como iCloud Private Relay usam uma entrada que conhece o cliente e um egress operado independentemente que conhece o destino, com tratamento de região aproximada.

**Prós:** divisão de conhecimento com pouco atrito; rápido; proteção integrada de DNS/web para tráfego compatível.

**Contras:** escopo limitado ao produto/aplicação; o provedor da conta/plataforma ainda identifica o cliente; não fornece anonimato sistêmico arbitrário; permanecem riscos de conluio/legalidade e temporização.

**Procedimento:** (1) confirme as aplicações e tipos de tráfego exatos suportados; (2) habilite o recurso em um contexto de plataforma dedicado quando apropriado; (3) selecione o comportamento regional; (4) teste Safari/DNS e aplicações não compatíveis separadamente; (5) inspecione o endereço visto pelo destino; (6) teste troca/falha de rede.<sup>[[12]](#references)</sup>

**Detecção:** o acesso vê a entrada; o destino vê o egress; logs de plataforma/relay e registros de conta abrangem suas respectivas camadas; aplicações incompatíveis expõem caminhos normais.

## Remote browser, VDI, RDP ou jump host da organização

**Mecânica:** navegação/execução de ferramentas ocorre em um sistema remoto; o destino vê o egress dele, enquanto o provedor do workspace vê a conexão do operador e o control plane.

**Prós:** rápido; isola conteúdo arriscado; egress estável e controlado; estado descartável e auditoria organizacional forte.

**Contras:** provedor/admin pode observar sessão/conta; canais de tela/clipboard/arquivo vazam; fingerprint do navegador remoto pode ser único; não é anônimo para o proprietário do workspace.

**Procedimento:** (1) crie um workspace próprio da organização por engagement; (2) exija MFA e restrinja a administração; (3) desabilite ou limite clipboard/upload/download; (4) encaminhe por egress fixo aprovado; (5) não use IdP/sync pessoal; (6) exporte somente evidências revisadas; (7) destrua workspace e credenciais conforme o cronograma.

**Detecção:** logs do provedor e IdP associam usuário à sessão; destinos agrupam egress/browser do workspace; defensores corporativos identificam protocolos de controle remoto e sessões anômalas na cloud.

## Public ou guest Wi-Fi

**Mecânica:** o tráfego sai pelo NAT do local ou por um túnel iniciado nele.

**Prós:** alta velocidade e endereço compartilhado fora de casa; nenhuma infraestrutura dedicada.

**Contras:** associação ao local/DHCP/portal, câmeras, compra e evidências de localização; peers/APs hostis; termos de uso; risco físico.

**Procedimento:** (1) obtenha acesso oferecido a convidados e confirme o SSID com funcionários; (2) use um dispositivo de baixa confiança e atualizado; (3) desabilite compartilhamento/auto-join e habilite private MAC; (4) conclua o portal sem identidade reutilizada; (5) inicie um caminho VPN/Tor fail-closed; (6) verifique o tráfego tethered; (7) esqueça a rede.

**Detecção:** o local correlaciona AP, MAC, DHCP, portal e horário; o destino vê o local/túnel; investigadores combinam evidências físicas e do dispositivo. Nunca contorne controles de acesso.

## Travel router

**Mecânica:** um roteador pertencente ao operador ingressa no Wi-Fi/Ethernet do local e fornece uma rede interna isolada com política de túnel imposta.

**Prós:** isola workstations; kill switch/DNS central; rede de cliente consistente; protege endpoints privilegiados de broadcasts locais.

**Contras:** o roteador se torna um fingerprint estável de rádio/DHCP; adiciona attack surface; captive portals e tethering podem contornar o túnel.

**Procedimento:** (1) atualize o firmware compatível; (2) defina credenciais únicas de administração e desabilite WAN admin/WPS/UPnP; (3) configure MAC upstream privado quando permitido; (4) crie um SSID interno separado; (5) imponha política de firewall full-tunnel DNS/IPv6; (6) teste portal, reconexão e falha do túnel.

**Detecção:** o local vê a associação do roteador e o formato do tráfego; fingerprinting local de RF/DHCP o identifica; o provedor VPN vê a origem do local.

## Cellular, SIM pré-pago e eSIM

**Mecânica:** um modem usa acesso rádio da operadora e geralmente NAT da operadora; uma camada VPN/Tor pode alterar o exit visível ao destino.

**Prós:** independente da rede wired/Wi-Fi local; móvel; alta velocidade; backhaul útil para drops autorizados.

**Contras:** a operadora conhece assinante/eSIM, IMSI, IMEI, células, horário e portas atribuídas; leis de registro variam; co-localização com telefone pessoal vincula dispositivos.

**Procedimento:** (1) obtenha o serviço legalmente com os dados exigidos corretos; (2) use modem/dispositivo separado pertencente à organização; (3) registre-o com o controller do exercício; (4) desabilite rádios/contas não relacionados; (5) estabeleça o túnel aprovado; (6) teste se clientes tethered realmente o seguem; (7) verifique premissas de retenção do provedor antes de viajar.<sup>[[13]](#references)</sup>

**Detecção:** registros da operadora e localização RF; inventário corporativo de USB/PCI/MDM e surveys de rogue hotspots; temporização do destino/túnel.

## Internet via satellite e abuso de downlink satelital

**Mecânica:** o serviço normal usa terminal/provedor registrado. O abuso antigo de DVB-S one-way permitia que um receptor dentro de um beam observasse tráfego de downlink não criptografado destinado a um assinante legítimo enquanto usava outro caminho para requisições de saída.

**Prós:** ampla cobertura; último trecho independente; o abuso histórico one-way podia atribuir incorretamente C2 à geografia de um assinante.

**Contras:** registros de equipamento/RF/provedor; latência e cobertura; sistemas bidirecionais modernos são diferentes; caminho de saída e roteamento assimétrico continuam sendo evidências.

**Procedimento:** para acesso legal, registre um terminal próprio e use túnel conforme necessário. Para emular o comportamento histórico da Turla, reproduza capturas sintéticas one-way em um laboratório sem RF e teste se analistas detectam uma resposta a um host que não fez requisição; não intercepte tráfego satelital ao vivo.<sup>[[14]](#references)</sup>

**Detecção:** telemetria de provedor/terminal, direction finding RF, flow impossível/assimétrico, inconsistência de RTT/roteamento e configuração do malware.

## Residential/mobile proxy ou proxyware consentido

**Mecânica:** um gateway backconnect atribui exits residenciais/móveis, fixos ou rotativos. A oferta pode ser consentida, incluída de forma enganosa ou maliciosa.

**Prós:** alta velocidade; escolha geográfica; ASN de consumidor evita alguns bloqueios de hosting; pools grandes.

**Contras:** risco de proveniência/consentimento/legalidade; broker vê o cliente; exits infectados prejudicam vítimas; rotação cria anomalias; caro e pouco confiável.

**Procedimento:** use somente agents próprios, documentados e com consentimento informado para emulação: (1) registre endpoints de teste; (2) inventarie proprietários/IPs; (3) configure um gateway; (4) alterne modos sticky/per-request; (5) envie somente a um alvo próprio; (6) compare logs de gateway/exit/alvo; (7) remova todos os agents.

**Detecção:** deslocamento impossível, browser/conta estáveis através de mudanças rápidas de IP/ASN, protocolos backconnect, artefatos de processo/rede proxyware e relações broker/controller.

## ORB, botnet e relays de edge devices comprometidos

**Mecânica:** roteadores/IoT/servidores alugados ou comprometidos formam funções de acesso, trânsito e exit administradas como uma fleet. Vários clientes APT podem compartilhá-la.

**Prós:** reputação/geografia emprestadas; exits de curta duração; mesh multi-hop resiliente; vínculo direto fraco entre ator e IP.

**Contras:** vitimização criminosa; padrões de implant/controller/fleet; apreensão do intermediário; desempenho inconsistente; registros de operador/cliente.

**Procedimento:** nunca comprometa dispositivos reais. Use [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) crie redes isoladas de entrada/trânsito/alvo; (2) conecte containers relay próprios dual-homed; (3) encaminhe somente uma porta de teste; (4) envie uma requisição benigna; (5) verifique que o alvo vê somente o exit; (6) alterne o exit; (7) desmonte todos os assets nomeados.<sup>[[15]](#references)</sup>

**Detecção:** rastreie topologia, portas/serviços, relações de controller, fingerprints de implant e ciclo de vida dos nós; centralize telemetria de configuração/flow/integridade de edge; não iguale IP de exit ao ator.

## CDN redirector, domain fronting e domainless fronting

**Mecânica:** uma edge pública encaminha somente tráfego que corresponde a uma grammar; fronting usa um SNI externo benigno e uma authority HTTP interna diferente, ou SNI vazio, quando o intermediário permite.

**Prós:** oculta/protege o back-end; edge global rápida; mistura o destino a um serviço compartilhado; cutover rápido.

**Contras:** a CDN vê todo o routing e tenant; muitos provedores proíbem fronting cross-tenant; artefatos de SNI/Host/processo/flow e conta; reutilização de configuração agrupa campanhas.

**Procedimento:** reproduza somente em um reverse proxy próprio com [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): crie certificado/edge local, encaminhe um Host incompatível a um alvo próprio, registre SNI e Host, envie requisições normais/incompatíveis e remova os containers.<sup>[[16]](#references)</sup>

**Detecção:** compare SNI/ECH/Host/`:authority` no endpoint ou edge terminadora; associe processo iniciador, tenant/origin, grammar de requisição e cadência do flow.

## Dynamic DNS, DGA, fast flux e double flux

**Mecânica:** DDNS atualiza um nome estável; DGA deriva nomes candidatos variáveis; fast flux alterna endereços de serviço com TTL baixo; double flux também alterna name servers.

**Prós:** descoberta resiliente; substituição rápida da infraestrutura; oculta o controller atrás de muitos nós.

**Contras:** DNS cria telemetria centralizada; entropia/NXDOMAIN/churn; TTL baixo e padrões amplos de ASN; registro e infraestrutura autoritativa permanecem.

**Procedimento:** use [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): sirva uma zona própria retornando endereços RFC 5737 com TTL de cinco segundos, consulte-a repetidamente, altere a epoch sintética e valide analytics. Nunca aponte registros de teste para terceiros.<sup>[[17]](#references)</sup>

**Detecção:** respostas/ASNs únicos em janela deslizante, TTL mediano, geografia, churn autoritativo, clusters DGA de NXDOMAIN/léxico/tempo e follow-on do processo; exclua CDNs legítimas com contexto.

## Serviço web legítimo, dead-drop resolver e tasking one-way

**Mecânica:** um post público, repositório, documento, objeto ou feed contém um endpoint ou task atual codificado. O cliente pode devolver resultados por outro canal.

**Prós:** serviço de alta reputação permitido; TLS; rotação do endpoint sem alterar o binário; tasking assimétrico dificulta correlação simples de flows.

**Contras:** identificadores estáveis de objeto/conta/API; registros do provedor; sequência de decodificação/follow-on; conteúdo pode ser apreendido ou alterado.

**Procedimento:** use [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): hospede um ponteiro codificado em um container próprio, faça fetch/decode a partir de um cliente de curta duração, contate um segundo serviço próprio, preserve ambos os logs e desmonte.

**Detecção:** correlacione processo incomum → leitura de objeto estável → decode → novo destino; faça hash/preserve o conteúdo e retenha caminhos completos dos objetos, não apenas o domínio.

## Serverless, container efêmero e egress cloud-NAT

**Mecânica:** functions/jobs curtos executam atrás de NAT de provedor ou front; o serviço lógico permanece estável enquanto instâncias e endereços rotacionam.

**Prós:** implantação/destruição rápidas; egress compartilhado em escala do provedor; pouco disco local; routing regional elástico.

**Contras:** tenant, role, API, imagem, secret, invocation, billing e logs front-to-origin são duráveis; fingerprints de cold-start/plataforma; política do provedor.

**Procedimento:** (1) use um tenant de exercício pertencente à organização; (2) implante uma function benigna que solicite somente a um endpoint próprio; (3) registre projeto/role/imagem/configuração; (4) invoque em várias instâncias; (5) compare IPs do alvo com audit/request IDs; (6) teste retenção de logs; (7) remova function, roles e secrets.

**Detecção:** logs de auditoria/invocação da cloud, criação incomum de roles, egress compartilhado com grammar de requisição estável, reutilização de imagem/layer/secret e correlação front-origin.

## Drop autorizado no local

**Mecânica:** um computador pequeno inventariado usa wired/Wi-Fi local e rendezvous VPN/cellular de saída, apresentando uma origem local.

**Prós:** teste realista de origem interna; alta velocidade; permite testar NAC, inventário físico e controles de egress.

**Contras:** descoberta/roubo físico; evidências de serial/MAC/USB/DHCP/PoE/RF e câmeras; perda pode expor credenciais.

**Procedimento:** siga [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) obtenha autorização escrita exata para a instalação; (2) registre serial, MAC, foto, localização e horário de recuperação; (3) use imagem mínima assinada e credenciais mútuas de curta duração; (4) restrinja destinos/capacidades somente de saída; (5) adicione quarantine no servidor e limites de bandwidth; (6) teste visibilidade do SOC e resposta à perda; (7) recupere, preserve as evidências exigidas e sanitize conforme a política de lifecycle acordada. Nunca esconda um dispositivo em local sem consentimento.

**Detecção:** NAC/802.1X, switchport/PoE/DHCP, inventário USB, survey RF, túnel recorrente, receiving/câmeras e inspeção física.

## Pivot wireless nearest-neighbor

**Mecânica:** um ator controla um host dentro do alcance de rádio do alvo e usa credenciais Wi-Fi do alvo para atravessar remotamente a fronteira. APT28 usou organizações comprometidas próximas dessa forma.<sup>[[18]](#references)</sup>

**Prós:** nenhum deslocamento do operador; o alvo vê uma origem de rádio local; contorna controles aplicados somente à entrada pela Internet.

**Contras:** requer host dual-radio próximo, comprometido/próprio, e acesso válido; evidências de RADIUS/NAC/AP e endpoint vizinho; anomalias de sinal/dispositivo.

**Procedimento:** reproduza somente com o [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): conecte um pivot próprio aos SSIDs de laboratório vizinho e alvo, encaminhe somente um serviço, colete logs de ambos os APs/pivot, habilite EAP-TLS/device posture e confirme que a segunda tentativa falha.

**Detecção:** correlacione identidade RADIUS, certificado/posture gerenciado, dispositivo visto pela primeira vez, edge/sinal do AP, login concorrente e presença física; procure endpoints próximos com rádios simultâneos, forwarding e túneis.

## Community mesh, delay-tolerant e store-and-forward offline

**Mecânica:** o tráfego atravessa peers locais, gateways assíncronos, mídia removível ou filas agendadas em vez de uma sessão interativa única com a Internet.

**Prós:** funciona durante interrupção/censura; entrega atrasada/em lote enfraquece temporização simples; nenhuma última milha central para comunicação local.

**Contras:** latência alta; conjunto de anonimato pequeno; metadados de custódia/físicos; peers maliciosos; os dados eventualmente chegam a um gateway que os observa.

**Procedimento:** (1) construa uma mesh isolada própria de três nós ou fila de arquivos; (2) criptografe/autentique o conteúdo ponta a ponta; (3) remova rotas diretas de Internet da origem; (4) retransmita um arquivo benigno após atraso controlado; (5) verifique que somente o gateway contata o destino próprio; (6) compare custódia/timestamps; (7) preserve as evidências exigidas e sanitize mídia/filas temporárias no encerramento aprovado.

**Detecção:** atividade de arquivo/processo no endpoint, links de rádio entre peers, auditoria de mídia removível, periodicidade de fila/gateway e identificadores de conteúdo. Janelas de correlação maiores substituem a análise de flow interativo.

## TURN relay e WebRTC forced-relay

**Mecânica:** Traversal Using Relays around NAT (TURN) aloca um endereço público de relay e transporta tráfego UDP, TCP ou TLS entre cliente e peers. Uma política ICE pode forçar o uso de relay em vez de expor um candidate direto. TURN resolve alcançabilidade, não anonimato geral: o servidor autentica o cliente e observa alocações, peers, horário e volume.<sup>[[19]](#references)</sup>

**Prós:** amplamente implementado; lida com NAT restritivo; suporta WebRTC móvel; o peer não recebe o endereço de transporte direto do cliente quando a política relay-only é imposta corretamente.

**Contras:** o operador TURN vê ambos os lados adjacentes; identidade da aplicação, fingerprint de mídia e signaling permanecem; relay-only custa bandwidth e latência; configuração incorreta ainda pode coletar candidates host ou server-reflexive.

**Procedimento:** (1) implante um serviço TURN próprio da organização com TLS e credenciais de curta duração; (2) restrinja realms, peers, portas, quotas e expiração; (3) configure a aplicação de teste para ICE relay-only; (4) faça uma chamada para um peer próprio; (5) inspecione `getStats()` e capture pacotes para confirmar que somente candidates relay transportaram mídia; (6) falhe o relay e confirme ausência de fallback direto; (7) retenha logs de allocation do engagement.

**Detecção:** signaling, processo do navegador e allocations TURN associam a sessão ao relay; redes observam flows sustentados para portas TURN ou endpoints TLS; o peer vê o relay alocado. **Nó capturado:** estado da aplicação e credenciais TURN efêmeras podem revelar realm e serviço de rendezvous. Minimize a exposição com credenciais curtas por dispositivo e mantenha a autenticação do operador somente no controller.

## Rendezvous outbound-only ou reverse overlay

**Mecânica:** um nó atrás de NAT inicia uma conexão autenticada a um broker controlado pela organização. O operador autentica-se separadamente no broker, que autoriza um canal de gerenciamento estreito; não é necessário port forwarding de entrada nem rota direta operador-nó.

**Prós:** estável atrás de NAT e últimas milhas cativas; revogação e auditoria centralizadas; mudanças de endereço do field node não exigem descoberta pelo operador; separa claramente identidade do operador da credencial do nó.

**Contras:** o broker torna-se um ponto de alta importância para correlação; keepalives periódicos são reconhecíveis; um túnel amplo pode virar pivot inseguro; perda do broker encerra o gerenciamento.

**Procedimento:** siga [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): emita uma identidade de dispositivo delimitada, permita somente um broker próprio e serviço de gerenciamento aprovado, use keepalive autenticado, imponha routing fail-closed, teste mudanças de endereço e recuperação após reboot e revogue a identidade no exercício de perda. WireGuard documenta keepalive persistente de 25 segundos como intervalo NAT amplamente útil quando realmente necessário.<sup>[[20]](#references)</sup>

**Detecção:** logs do broker e IdP associam ambos os lados; a rede de acesso vê um destino/cadência criptografados repetidos; inventário do endpoint mostra o agent do overlay. **Nó capturado:** presuma expostos sua chave de dispositivo, nome do broker, endereços do túnel e dados de tasks em cache. Ele não deve conter chave privada do operador, conta pessoal ou token reutilizável do controller.

## Pull mailbox, message queue ou object-store rendezvous

**Mecânica:** um workload de campo consulta uma mailbox autenticada por jobs assinados e pré-aprovados e publica resultados limitados. O operador grava na queue por um control plane separado; não existe socket interativo entre eles.

**Prós:** tolera links intermitentes; desacopla temporização e endereçamento; quotas e schemas podem limitar capacidades; auditoria e revogação centralizadas fáceis.

**Contras:** cadência de polling e nomes estáveis de objeto/queue fingerprintam o sistema; logs do provedor associam produtor e consumidor; controle atrasado; dados enfileirados capturados podem expor o exercício.

**Procedimento:** (1) crie uma queue de engagement e uma identidade de dispositivo; (2) defina um schema assinado de jobs benignos e explicitamente delimitados; (3) defina TTL de mensagens, tamanho máximo de resultado e rate; (4) permita que o nó leia somente sua queue e grave somente em seu prefixo de resultados; (5) teste acúmulo offline, entrega duplicada e revogação; (6) centralize logs de acesso imutáveis; (7) exclua a queue após cumprir os requisitos de retenção.

**Detecção:** procure chamadas periódicas de API por processo incomum, caminhos estáveis de bucket/object/queue, user-agent ou comportamento TLS idênticos e sequência fetch-then-new-connection. **Nó capturado:** cache local pode revelar jobs pendentes e nomes de objetos; mantenha o cache criptografado, limitado e descartável, preservando os logs autoritativos do controller.

## Failover de uplinks duplos e migração de conexão

**Mecânica:** um field node aprovado possui dois uplinks independentes — como Ethernet/Wi-Fi do local e cellular da organização — e mantém a sessão de controle por overlay ou message broker enquanto as rotas mudam. Isso é engenharia de disponibilidade, não anonimato.

**Prós:** sobrevive à falha de um provedor, AP ou captive portal; suporta manutenção planejada; permite isolar rapidamente um caminho suspeito.

**Contras:** dois provedores criam dois registros de localização/conta; uso simultâneo facilita correlação; leaks de rota e DNS durante failover; evidências de co-localização cellular permanecem.

**Procedimento:** (1) registre ambas as interfaces e provedores pertencentes à organização; (2) atribua prioridades de rota e health checks determinísticos a endpoints próprios; (3) vincule DNS e gerenciamento ao overlay; (4) impeça que o caminho secundário aceite tráfego de entrada; (5) desconecte cada caminho e verifique recuperação da sessão, política de origem e ausência de acesso direto ao destino; (6) alerte sobre alterações não planejadas; (7) documente uso de dados e limites de roaming.

**Detecção:** correlacione o mesmo certificado de dispositivo, grammar de requisição e temporização entre ASNs; inventário local vê ambos os rádios; carriers/locais conservam seus próprios registros. **Nó capturado:** ambos os identificadores SIM/dispositivo e SSIDs conhecidos podem estar visíveis; use assets da organização e nunca co-localize ou emparelhe o nó com dispositivos pessoais.

## APN privado da organização ou túnel cellular gerenciado

**Mecânica:** um APN privado da operadora coloca SIMs registrados em um domínio roteado privado ou encaminha o tráfego a um gateway corporativo. Separa o dispositivo da Internet móvel pública, mas não o oculta da operadora ou da organização contratante.

**Prós:** endereçamento privado estável; enrollment e política de tráfego no nível da operadora; evita exposição pública de entrada; útil para appliances remotos autorizados.

**Contras:** atribuição forte por assinante, IMSI/IMEI, célula e billing; prazo e custo de contratação; outage de carrier/gateway; não é anônimo para o operador.

**Procedimento:** (1) contrate o APN em nome da organização do assessment; (2) permita apenas SIMs registrados e prefixes do gateway; (3) adicione mutual authentication na camada da aplicação; (4) restrinja a rota do APN ao rendezvous e serviços de update; (5) teste remoção de SIM, roaming, saída para Internet pública e revogação; (6) monitore registros da operadora e gateway; (7) cancele ou coloque em quarantine cada SIM no encerramento.

**Detecção:** inventário da operadora e telemetria celular, flows do gateway APN, incompatibilidade SIM/IMEI e registros de assets corporativos. **Nó capturado:** SIM e modem identificam o contrato mesmo com storage criptografado; capture resilience significa suspensão rápida e autorização estreita, não deniability.

## Long-range point-to-point wireless bridge

**Mecânica:** Wi-Fi direcional ou outro rádio point-to-point licenciado/não licenciado conecta dois locais aprovados pelos proprietários, com egress de Internet no local remoto. Pode mover a localização aparente do IP sem proxy comercial.

**Prós:** alto throughput; independente de carriers wired intermediários; RF e routing controláveis; útil para testar segmentação e monitoramento do local remoto.

**Contras:** line-of-sight, spectrum, landlord e restrições regulatórias; emissões RF e hardware distintos; ambos os endpoints são evidências físicas; clima/energia/alinhamento afetam estabilidade.

**Procedimento:** (1) obtenha permissão escrita para ambos os locais e verifique regras de spectrum/potência; (2) faça survey sem transmitir fora dos parâmetros aprovados; (3) use criptografia autenticada e uma management VLAN; (4) restrinja a bridge a um rendezvous ou subnet de teste próprio; (5) teste failover, alinhamento, recuperação de energia e contenção RF; (6) etiquete/inventarie ambos os rádios; (7) remova-os e verifique reset da configuração após o exercício.

**Detecção:** surveys RF, análise de spectrum, inspeção de rooftop/local, MAC/OUI da bridge, tráfego de gerenciamento e logs de egress do local remoto. **Nó capturado:** configuração revela seu peer e domínio de gerenciamento; use credenciais exclusivas do exercício, nenhuma conta pessoal de gerenciamento e revogação rápida da peer key.

## Exit cooperativo ou comunitário consentido

**Mecânica:** voluntários ou organizações parceiras operam relays conscientemente sob uma política publicada. O tráfego sai de um pool comunitário compartilhado enquanto a camada de coordenação registra abuso e revogação.

**Prós:** redes não-cloud diversas; consentimento explícito é mais seguro que proxyware; governança compartilhada pode distribuir confiança; útil para pesquisa e estudos de resistência à censura.

**Contras:** pools pequenos e registros de membros reduzem o anonimato; operadores de exit recebem reclamações e observam metadados; participantes maliciosos, uptime variável e jurisdições diferentes.

**Procedimento:** (1) publique política de uso aceitável e logging; (2) obtenha opt-in informado de cada operador; (3) emita identidade de relay única e restrinja destinos/rates; (4) forneça tratamento de abuso e revogação em uma ação; (5) envie somente tráfego autorizado a endpoints próprios durante os testes; (6) meça churn e exposição à correlação; (7) remova o relay corretamente quando o consentimento terminar.

**Detecção:** registros de membership/control plane, certificados de relay, fingerprint de software comum e comportamento de exit identificam o pool. **Nó capturado:** configuração do relay pode identificar a cooperação, mas não deve conter identidades de clientes; armazene a responsabilidade cliente-sessão no controller autorizado sob controle de acesso.

## Endereços temporários IPv6 e rotação de prefix

**Mecânica:** extensões de privacidade IPv6 criam identificadores temporários de interface para que um endereço estável não seja reutilizado em toda conexão de saída. Mudanças de prefix delegado podem adicionar rotação, mas prefix, registro do assinante e fingerprint da camada superior permanecem.<sup>[[21]](#references)</sup>

**Prós:** reduz tracking passivo de longo prazo por identificador de interface estável; integrado a sistemas operacionais comuns; nenhum overhead de relay.

**Contras:** não fornece anonimato de origem; ISP e rede local ainda conhecem prefix/device; DNS, contas e estado do navegador vinculam sessões; churn de endereços complica allowlists e logging.

**Procedimento:** (1) inspecione endereços estáveis e temporários atuais em um cliente próprio; (2) habilite o padrão de privacy address suportado pelo OS em vez de spoofing de terceiros; (3) solicite repetidamente a um endpoint IPv6 próprio durante diferentes lifetimes de endereço; (4) confirme que serviços de entrada fazem bind somente aos endereços estáveis pretendidos; (5) retenha logs precisos de DHCPv6/RA/neighbor e endpoint; (6) teste VPN/firewall para cada endereço IPv6.

**Detecção:** correlacione prefix delegado, identidade de camada 2, neighbor discovery, conta e telemetria do endpoint, em vez de tratar um endereço como um dispositivo. **Nó capturado:** perfis de rede e identificadores de interface permanecem; endereçamento temporário impede um identificador passivo único, não atribuição forense.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 e meek

**Mecânica:** um pluggable transport altera a aparência da primeira conexão Tor ou como ela alcança uma bridge. Snowflake usa proxies WebRTC voluntários de curta duração, WebTunnel se parece com HTTPS comum, obfs4 resiste a identificação simples de protocolo e probing ativo, e meek retransmite por infraestrutura web compatível. São transports de circumvention para entrar no Tor, não camadas extras de anonimato ponta a ponta.<sup>[[22]](#references)</sup>

**Prós:** úteis quando Tor direto ou relays conhecidos são bloqueados; Snowflake evita um endereço público de bridge estável; integrados a clientes Tor mantidos; o destino ainda recebe as propriedades normais do Tor.

**Contras:** desempenho menor ou variável; broker/front/bridge e rede local observam metadados diferentes; fingerprints de transporte e bloqueio continuam possíveis; proxy voluntário não substitui Tor e não deve receber plaintext da aplicação.

**Procedimento:** (1) instale e verifique o Tor Browser oficial ou cliente Tor compatível; (2) selecione o transport integrado em Connection/Bridges; (3) conecte somente a uma página de diagnóstico própria; (4) confirme que a página vê um exit Tor, não o peer Snowflake/WebTunnel; (5) compare bootstrap e desempenho; (6) falhe o transport e confirme que o cliente não se conecta diretamente em silêncio; (7) retorne à configuração padrão compatível após o teste.

**Detecção:** um censor pode combinar allowlists de destino, comportamento TLS/WebRTC, descoberta de broker e análise de flow; endpoints expõem Tor e configuração do transport. **OPSEC resiliente a captura:** use o cliente padrão, nunca copie estado pessoal de navegador para ele e presuma que histórico de bridge/broker pode ser recuperado. **Monitoramento:** observe logs de bootstrap Tor, tentativas diretas inesperadas de DNS/conexão e observações de páginas próprias no controller; falha do transport não prova descoberta.

## Refraction networking ou decoy routing

**Mecânica:** um operador de rede cooperante detecta um sinal encoberto em tráfego aparentemente endereçado a um decoy permitido e desvia o flow para um proxy de circumvention. A implantação exige infraestrutura no caminho da rede; não é algo que um cliente possa criar simplesmente selecionando um site inocente.<sup>[[23]](#references)</sup>

**Prós:** o destino aparente pode ser difícil de bloquear sem dano colateral; nenhum endereço público de bridge precisa ser distribuído; modelo de pesquisa útil para circumvention assistido no caminho.

**Contras:** participação especializada de ISP/transit; deployability e desempenho dependem do routing; flow cliente-decoy e atividade do lado do proxy permanecem; observador global ou cooperante pode correlacionar a temporização.

**Procedimento:** não sinalize por redes não envolvidas. Reproduza a arquitetura em laboratório isolado: (1) crie namespaces próprios de cliente, router, decoy e proxy; (2) use uma requisição de teste benigna com tag; (3) faça o router próprio redirecionar somente essa tag ao proxy; (4) registre tuples e request IDs antes/depois do routing; (5) compare flows normais e sinalizados; (6) teste falsos positivos e remoção; (7) destrua as rotas do laboratório.

**Detecção:** operadores autorizados podem inspecionar divergência de routing, comportamento incomum de client hello/tag e discrepâncias entre flows decoy e back-end. **OPSEC resiliente a captura:** um cliente de pesquisa deve conter somente chaves de teste e endereços de documentação. **Monitoramento:** compare decisões assinadas do lab router com chegadas ao proxy; não faça probing em provedores de transit de produção para descobrir se detectaram signaling.

## Gateway content-addressed ou recuperação por peer em cache

**Mecânica:** um gateway HTTP recupera um content identifier (CID) IPFS, possivelmente de seu cache ou peers, e devolve o conteúdo verificável ao cliente. O publicador original pode ver o gateway ou outros peers, e não o leitor final; o gateway vê o IP do leitor e o CID solicitado. A recuperação peer-to-peer nativa expõe o cliente a peers e participantes de DHT/routing.<sup>[[24]](#references)</sup>

**Prós:** publicador e leitor podem ser separados por caches; conteúdo imutável é verificável por hash; dados replicados sobrevivem a um host; clientes HTTP não exigem pilha peer nativa.

**Contras:** CIDs públicos e logs do gateway revelam interesses; temporização da primeira recuperação pode correlacionar publicador e leitor; conteúdo web malicioso e riscos de same-origin em paths; gateways públicos são best-effort e proíbem abuso.

**Procedimento:** (1) publique um arquivo de teste inofensivo em uma private IPFS swarm ou gateway próprio; (2) registre o CID; (3) recupere-o por um gateway HTTP próprio separado usando isolamento por subdomínio; (4) verifique os bytes contra o CID; (5) repita após caching; (6) compare logs de publicador, peer e gateway; (7) unpin e remova o conteúdo de teste quando terminar a retenção.

**Detecção:** gateways registram origem/CID; conexões DHT e peer revelam recuperação; histórico do endpoint e hashes de arquivo identificam o conteúdo. **OPSEC resiliente a captura:** não armazene chave privada de publicação em um field client read-only e criptografe conteúdo sensível antes do content addressing. **Monitoramento:** alerte sobre pinning inesperado, alteração do conjunto de peers, requisições de CID fora da allowlist ou notificações de abuso do gateway.

## Serviço de private information retrieval

**Mecânica:** Private Information Retrieval (PIR) permite que um cliente recupere um registro de um database enquanto oculta criptograficamente o índice selecionado do servidor, sob um threat model single-server ou multi-server declarado. Protege a seleção da consulta em um dataset delimitado; não é acesso web geral nem anonimato IP.<sup>[[25]](#references)</sup>

**Prós:** privacidade forte e específica da aplicação; modelo de leakage mensurável; útil para diretórios de chaves, blocklists ou databases públicos pequenos; pode reduzir a necessidade de revelar termos exatos de lookup.

**Contras:** overhead de computação/bandwidth; servidor aprende IP/horário da conexão salvo combinação com relay; versão do dataset, tamanho da resposta e estado da aplicação podem particionar usuários; maturidade da implementação varia.

**Procedimento:** (1) implante uma implementação PIR auditada contra um database sintético próprio; (2) publique versão e parâmetros do dataset; (3) recupere vários índices usando tamanhos de requisição idênticos; (4) verifique a correção localmente; (5) compare logs do servidor e confirme ausência do índice; (6) teste respostas maliciosas/truncadas e incompatibilidade de versão; (7) documente a premissa exata de privacidade em vez de chamá-la de navegação anônima.

**Detecção:** redes veem uso e volume do serviço; telemetria do endpoint expõe cliente e uso do registro final; servidor comprometido pode manipular datasets ou temporização. **OPSEC resiliente a captura:** mantenha no cliente apenas parâmetros públicos do database e um cache limitado. **Monitoramento:** valide roots assinadas do dataset, formatos fixos de requisição, mudanças na taxa de erro e rotações de chave do servidor.

## Fetcher, preview ou rendering server-side restrito

**Mecânica:** um serviço remoto busca ou renderiza uma URL e retorna screenshot, metadados ou conteúdo sanitizado. O destino vê o endereço do fetcher; o serviço vê o solicitante, a URL e o resultado. Abusar de bots de link-preview, scanners de segurança ou URL fetchers de terceiros não é uso autorizado de proxy.

**Prós:** isola conteúdo ativo da workstation; o destino recebe fingerprint controlado do fetcher; pode impor limites de tipo/tamanho/destino/renderização; ambiente de execução descartável.

**Contras:** o serviço tem conhecimento completo da requisição; registros de conta/API/billing; risco de SSRF e exfiltração; scripts, autenticação e sites interativos podem não funcionar; URLs únicas correlacionam solicitante e fetch.

**Procedimento:** (1) implante um fetcher próprio da organização com allowlist estrita de domínios de teste próprios; (2) bloqueie endereços privados, link-local, metadata e redirects para endereços não aprovados; (3) limite methods, redirects, bytes e tempo de renderização; (4) remova credenciais/cookies; (5) envie uma URL própria; (6) compare logs do solicitante, fetcher e alvo; (7) destrua a instância de renderização e retenha a auditoria central conforme a política.

**Detecção:** o alvo vê ASN/fingerprint do serviço; logs do provedor/controller associam solicitante à URL; processo/API do endpoint mostra o envio. **OPSEC resiliente a captura:** use um token de projeto curto, sem autoridade para destinos arbitrários. **Monitoramento:** alerte sobre negações de allowlist, violações de redirect, fetches sem controller job ID e notificações de abuso do provedor.

## Anycast rendezvous pool

**Mecânica:** múltiplos nós controlados pela organização anunciam ou frontam um endereço de serviço estável, e o routing seleciona uma instância próxima. Anycast melhora disponibilidade e oculta um back-end individual do cliente, mas o operador controla todas as instâncias e o endereço do serviço é estável.<sup>[[26]](#references)</sup>

**Prós:** ingresso regional resiliente; nenhuma reconfiguração de campo quando uma instância falha; distribuição de DDoS/load; política central pode mover sessões entre nós conhecidos.

**Contras:** registros de BGP/CDN e provedor identificam a organização; mudanças de caminho podem quebrar sessões stateful; monitoramento varia conforme localização do cliente; um endereço estável é facilmente bloqueado ou agrupado por reputação.

**Procedimento:** use um projeto próprio compatível com o provedor ou um laboratório de routing isolado: (1) implante dois health endpoints autenticados idênticos; (2) exponha um endereço de serviço documentado; (3) mantenha o estado de sessão no broker, não na edge; (4) retire um nó e verifique a reconexão; (5) teste consistência de certificado, política e logs; (6) alerte sobre origin/região não autorizados; (7) remova anúncios e credenciais no encerramento.

**Detecção:** BGP/RPKI/history, tenancy do provedor, certificados e comportamento idêntico do serviço identificam o pool. **OPSEC resiliente a captura:** uma edge contém somente a identidade de serviço regional e nenhuma chave de operador ou enrollment de fleet. **Monitoramento:** faça probes de cada região por monitors autorizados, compare origem de rota e digest de configuração e trate uma origem inesperada como incidente.

## Migração QUIC e continuidade Multipath TCP

**Mecânica:** connection IDs do QUIC podem manter uma sessão viva através de rebinding de NAT ou mudança de endereço; Multipath TCP pode transportar um único byte stream confiável por múltiplos subflows. Melhoram continuidade entre Wi-Fi/cellular, mas expõem caminhos antigos/novos ao peer comum e podem facilitar correlação entre caminhos.<sup>[[27]](#references)</sup>

**Prós:** recuperação rápida durante alterações de uplink; sessão da aplicação não precisa reiniciar; MPTCP pode combinar resiliência e throughput; valioso para field nodes aprovados.

**Contras:** não é anonimato; peer vê migração/subflows; connection identifiers e tráfego simultâneo vinculam caminhos; suporte de middlebox/carrier varia; registros duplicados de provedores aumentam exposição.

**Procedimento:** (1) habilite o transport compatível somente entre um field client próprio e rendezvous; (2) autentique a aplicação independentemente do IP; (3) inicie uma transferência limitada em Wi-Fi aprovado; (4) alterne para cellular da organização; (5) confirme validação do caminho, integridade dos dados e ausência de fallback claro/direto; (6) teste idle timeout e retorno; (7) retenha no broker registros de toda transição de caminho.

**Detecção:** o peer observa diretamente migração de endereço ou subflows MPTCP; provedores de acesso veem sua parte; connection IDs, identidade TLS e temporização unem ambos. **OPSEC resiliente a captura:** armazene somente material de sessão por dispositivo e expire rapidamente o estado resumível. **Monitoramento:** alerte sobre mudanças impossíveis de caminho, redes simultâneas não aprovadas, storms de migração e resumption após quarantine.

## Egress de managed CI/CD ou runner de automação efêmero

**Mecânica:** um workflow próprio da organização executa uma verificação de rede delimitada em um runner hospedado. O destino vê um endereço de runner da cloud, enquanto a plataforma conserva atribuição de repository, actor, workflow, token, logs e billing. É execução remota com egress atribuível, não anonimato perante o provedor.<sup>[[28]](#references)</sup>

**Prós:** ambiente limpo descartável; definição de job reproduzível; nenhuma conexão de entrada; útil para verificações de disponibilidade distribuídas geograficamente; auditoria forte do controller.

**Contras:** plataforma e organização identificam o iniciador; tokens amplos e pull requests não confiáveis são perigosos; reputação de IP compartilhada; logs/artifacts podem reter secrets ou dados do alvo.

**Procedimento:** (1) crie um repository privado da organização e um environment para o assessment; (2) permita somente jobs benignos, fixos e aprovados manualmente contra endpoints próprios; (3) use permissões mínimas read-only no workflow e nenhum secret de produção; (4) execute a verificação; (5) compare registros do workflow, provedor e alvo; (6) confirme que artifacts não contêm credenciais; (7) exclua o token do environment e retenha a auditoria exigida.

**Detecção:** auditoria do provedor e logs do workflow fornecem atribuição direta; alvos identificam ASNs/ranges de runners e grammar estável de requisição. **OPSEC resiliente a captura:** nunca coloque secrets de field devices, signing, wallet ou administrador da cloud em variáveis do runner. **Monitoramento:** exija aprovação de branch/environment e alerte sobre alterações de workflow, execução por fork, leitura de secrets e destinos inesperados.

## Primeiro hop local não-IP para um gateway próprio

**Mecânica:** Bluetooth mesh, Wi-Fi Aware/Direct, rádio de baixa potência ou link serial/óptico transporta mensagens delimitadas de um sensor próximo a um gateway de Internet aprovado pelo proprietário. O dispositivo de campo não tem rota de Internet; o gateway é o único egress. Limites de alcance e protocolo tornam isso um design de telemetry/store-and-forward, não Internet anônima interativa.

**Prós:** remove pilha de Internet e credenciais do menor dispositivo de campo; baixo consumo; gateway centraliza a política; pode atravessar zonas temporariamente sem cobertura.

**Contras:** descoberta RF/física, pairing e identificadores de dispositivo; bandwidth e alcance pequenos; gateway ainda vincula todas as mensagens; restrições de spectrum e criptografia variam; captura pode expor dados enfileirados.

**Procedimento:** (1) obtenha aprovação do local e spectrum; (2) faça pairing de um sensor próprio com um gateway próprio usando chaves únicas; (3) defina tipos de mensagem assinados e de tamanho fixo, TTL e rate; (4) dê ao sensor nenhuma rota IP padrão; (5) permita que o gateway encaminhe somente a um collector próprio; (6) teste replay, perda de alcance e outage do gateway; (7) inventarie e recupere ambos os dispositivos.

**Detecção:** survey RF, database de pairing, inspeção física e logs de processo/flow do gateway revelam o caminho. **OPSEC resiliente a captura:** o sensor contém somente sua chave pairwise e queue criptografada limitada, nunca credenciais de operador, Wi-Fi, cellular ou controller. **Monitoramento:** alerte sobre novos peers, rollback de sequência, falha de chave, taxa RF incomum e mensagens que chegam por gateway não registrado.

## Matriz de exposição a captura/comprometimento

Esta tabela aplica uma verificação de capture resilience a cada família acima. “Minimize” significa reduzir secrets e blast radius em assets autorizados; nunca significa apagar evidências ou ocultar-se de uma investigação.

| Família de técnica | Um endpoint/relay capturado pode revelar | Controle autorizado mínimo |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | redes conhecidas, histórico DHCP/portal, MACs, peer do túnel | dispositivo separado da organização; private MAC quando compatível; nenhuma conta pessoal; inventário do controller |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provedores/hostnames, chaves, rotas, logs e hop adjacente | uma identidade por engagement; TTL curto; rotas estreitas; revogação no broker; nenhuma master key |
| OHTTP/ODoH, MASQUE, relay de provedor dividido | configuração relay/gateway, identificadores de aplicação e requests em cache | minimize identificadores do payload; fixe configuração aprovada; cache limitado; ausência estrita de fallback direto |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | software instalado, material bridge/onion, estado local e histórico de peers | cliente padrão; chaves de serviço separadas; estado mínimo criptografado; altere a identidade do serviço comprometido |
| Remote browser/VDI/jump host | token do workspace, clipboard/arquivos e tenant remoto | MFA resistente a phishing no gateway; canais de transferência desabilitados; revogação rápida da sessão |
| Cellular, satellite, APN privado | SIM/eSIM, identidade IMEI/terminal, provedor e localização aproximada | contrato da organização; nenhuma co-localização pessoal; política estreita de APN/overlay; runbook de suspensão |
| Proxy residencial/cooperativo, ORB lab | identidade do agent, controller/próximo hop, tráfego em cache | somente nós consentidos/próprios; agent assinado; credencial por nó; mapeamento de participantes no controller |
| CDN/fronting, fast flux, serverless | tenant/origin/configuração, tokens API, deployment e referências de billing | projeto dedicado; role least-privilege; token de deployment curto; auditoria do provedor retida centralmente |
| Dead drop, pull mailbox, store-and-forward | nomes de objetos, queue, jobs/resultados em cache e dados de custódia | jobs assinados e delimitados; TTL; cache criptografado; identidade de produtor separada; logs de servidor imutáveis |
| Drop, nearest-neighbor, bridge de longo alcance | serial/radio/SSID/peer, device key, artefatos de instalação física | instalação escrita; identidade de dispositivo única; nenhum secret de operador; telemetria de estado/tamper; revogar e recuperar |
| TURN, reverse overlay, dual-uplink | realm/broker, credencial de dispositivo, peer/rota e perfis de uplink | serviço estreito somente de saída; credencial curta; login de operador independente; caminhos fail-closed |
| Endereçamento temporário IPv6 | perfis, histórico de prefix e estado de endpoint/aplicação | tratar apenas como anti-tracking; preservar logs de rede; combinar com compartmentation do endpoint |
| Pluggable transport/refraction lab | configurações bridge/broker/decoy, estado Tor e chaves de pesquisa | cliente padrão ou laboratório isolado; nenhum estado pessoal de navegador; nenhum signaling de produção |
| IPFS/PIR/fetcher | CID/query solicitado, conteúdo em cache, token de gateway/serviço | cache criptografado e limitado; somente parâmetros públicos; token curto de serviço com allowlist |
| Anycast/QUIC/MPTCP | nós de serviço, connection IDs, estado resumível e todos os caminhos conhecidos | somente identidade regional; resumption curta; revogação central de rota/sessão |
| Managed CI/CD runner | repository, workflow, token do provedor, logs e artifacts | workflow least-privilege; nenhum secret de produção/field/wallet; aprovação do environment |
| Non-IP local hop | peer de rádio, chave pairwise, mensagens enfileiradas e identidade do gateway | chave pairwise única; schema fixo de mensagens; nenhuma credencial de Wi-Fi/cellular/operador |

## Monitoramento de possível descoberta para cada família de acesso

Nenhum teste no lado do cliente prova que um investigador ou defensor está observando. Monitore alterações em sistemas pertencentes ao engagement, corrobore-as com controller/cliente e pare em vez de sondar observadores. As linhas abaixo cobrem todas as técnicas acima; combine-as com os [estados de alerta e runbook de resposta do field node](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Técnicas cobertas | Sinais seguros no controller | Condição de quarantine/stop |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, APN privado | sessão lease/portal/carrier, tupla pública, alteração de BSSID/célula/caminho, aviso do provedor | rede/SIM/dispositivo não aprovado, relocation inexplicada ou escalada de provedor/SOC |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, proxy residencial/cooperativo | autenticação do peer, estado do túnel, leaks de rota/DNS, novo evento admin/API, reclamação | credencial duplicada/roubada, administrador desconhecido, fallback direto ou egress fora do escopo |
| OHTTP/ODoH/ECH, MASQUE, relay dividido, TURN | allocation relay/gateway, versão de chave/configuração, conexão direta não suportada, taxa de erro/replay | mismatch de chave, fallback direto, realm/peer desconhecido ou aviso de abuso |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | estado de bootstrap, falha de circuito, descriptor onion/saúde do serviço e página canary própria | crossover com conta pessoal, conexão inesperada não-Tor ou chave de serviço comprometida |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | conjunto de peers, idade/sequência da queue, chegada ao gateway, associação de rádio e hash de conteúdo | peer/gateway desconhecido, rollback de sequência, conteúdo não autorizado ou registro de custódia ausente |
| Remote browser/VDI/jump host, CI/CD runner, serverless | sessão IdP, alteração de workflow/imagem/configuração, novo uso de token, artifact/export e auditoria cloud | login/alteração de workflow desconhecidos, leitura de secret, destino inesperado ou escalada de role/projeto |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | inventário de nós próprios, acesso DNS/edge/objeto, grafo do controller, assinatura do job e TTL | nó/origin/writer de objeto desconhecido, job não assinado/repetido, escape da topologia do laboratório |
| Drop/nearest-neighbor/bridge de longo alcance/outbound overlay/dual uplink | heartbeat assinado, hash de boot/config, estado do enclosure, contexto AP/switch, identidade duplicada | nó movido/aberto, boot/hash/caminho inesperado, uso de sentinel ou relatório do local |
| IPv6 temporário, migração QUIC, MPTCP | prefix delegado, connection ID/subflows, validação de caminho e sessão broker | migração impossível, caminhos simultâneos não aprovados ou resumption após revogação |
| IPFS/cache, PIR, fetcher delimitado | CID/formato da query/root version, mudança de peer/gateway, redirect/negação de allowlist | pin/query/destino inesperado, root de dataset não assinado ou aviso de abuso |
| Lab de refraction/decoy-routing, rendezvous anycast | decisão de desvio própria, chegada ao proxy, origem BGP/RPKI, digest regional de configuração | sinal em caminho de produção, origem de rota desconhecida, inconsistência de região/configuração |

## Escolhendo e testando um caminho

1. Nomeie o observador a remover e os dados a ocultar.
2. Selecione a família menos complexa que o remova.
3. Desenhe os observadores de origem, entrada, trânsito, saída, DNS, conta e pagamento.
4. Use identidade separada de endpoint/aplicação.
5. Verifique IPv4, IPv6, DNS, bypass de WebRTC/aplicação e visão do destino.
6. Interrompa cada hop e confirme que a falha é fechada.
7. Compare logs em cada componente sob seu controle.
8. Registre vínculos residuais de temporização, provedor, endpoint e físicos.

## References

- [1] [EFF — Escolhendo a VPN certa para você](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — HTTP Oblivious](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Proteções do Tor](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Desbloqueando o Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Usando Tor Browser com uma VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Visão geral dos onion services](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Compartilhamento anônimo de arquivos](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — Segurança do iCloud Private Relay](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Registro obrigatório de SIM](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — Atores de espionagem ligados à China usam redes ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports e bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — pesquisa de projeto e implantação](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — Conceitos de HTTP Gateway e ciclo de vida da requisição](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Visão geral de Private Information Retrieval](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — Referência de runners hospedados pelo GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
