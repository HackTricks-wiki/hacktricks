# Privacidade de Rede e Conectividade Anônima

{{#include ../banners/hacktricks-training.md}}

A privacidade de rede é uma decisão de roteamento, não uma identidade completa. Selecione um caminho perguntando quem deve ser incapaz de conectar **origem**, **destino**, **conteúdo** e **tempo**.

Para o inventário normalizado — `Pros`, `Cons`, `Procedure` passo a passo e `Detection` para cada família de caminho de acesso — comece pelo [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Esta página expande as opções comuns e implementáveis.

## O que cada observador geralmente pode ver

| Caminho | Rede local / ISP | Intermediário | Destino | Principal limitação | Velocidade relativa |
|---|---|---|---|---|---|
| HTTPS direto | Metadados da origem, do destino, tempo | Hosting/CDN vê a conexão | IP de origem, dados do navegador/aplicativo | Sem privacidade do IP de origem | Mais rápida |
| VPN comercial | Origem conectada à VPN; não os metadados usuais do destino | VPN vê metadados da origem e do destino | IP de saída da VPN | Um provedor se torna um ponto de correlação | Geralmente rápida |
| VPN/VPS self-hosted | Origem conectada à VPS | Logs do host/conta/pagamento/control plane | IP de saída da VPS | Fácil atribuição ao servidor/conta alugado | Geralmente rápida |
| Tor Browser | Origem conectada ao Tor/bridge; tempo/volume | Cada relay vê uma parte limitada | Saída Tor, dados do navegador | Mais lento; riscos de conta/endpoint/correlação | Moderada/lenta |
| Tails/Whonix | Caminho Tor semelhante, com limites de roteamento mais fortes | Mesmas limitações do Tor | Saída Tor/dados do aplicativo | Erros operacionais e host/hardware continuam relevantes | Moderada/lenta |
| Wi-Fi público de convidados + HTTPS | Local vê dispositivo/tempo e destinos | ISP do local vê metadados | IP público do convidado | Correlação física/captive portal/dispositivo | Rápida/variável |
| Hotspot celular | Operadora vê assinante/dispositivo/localização e destinos | VPN/Tor, se usados | Operadora, VPN ou IP de saída do Tor | Assinatura móvel e localização são identificadores duráveis | Rápida/variável |
| Mixnet | Acesso vê uso da mixnet; tempo/volume | Vários nós de mixing | Gateway/saída | Ecossistema emergente; custo de latência e largura de banda | Mais lenta |

HTTPS protege o conteúdo em trânsito, mas não todos os metadados. A EFF observa que domínio, horário e tamanho do tráfego podem continuar visíveis para intermediários mesmo quando caminhos de páginas, credenciais e mensagens estão criptografados.<sup>[[1]](#references)</sup>

## VPNs: privacidade rápida com confiança concentrada

Uma VPN é útil para ocultar metadados de destino do ISP de acesso, proteger o primeiro salto em uma rede não confiável, apresentar um endereço de saída estável para um engagement ou alcançar uma rede privada. Ela **não** torna o usuário anônimo. A VPN vê a conexão de origem e pode observar metadados do destino; contas, cookies, GPS, fingerprints e informações de pagamento permanecem.<sup>[[1]](#references)</sup>

### Checklist de avaliação do provedor

1. **Propriedade e jurisdição:** identifique a entidade legal, empresa controladora, países de operação, subcontratados de infraestrutura e processos legais aplicáveis.
2. **Dados coletados:** diferencie conta/faturamento, IP de origem, timestamps de conexão, largura de banda, telemetria de falhas, consultas DNS e logs de destino. “Sem logs de navegação” não significa “sem dados”.
3. **Retenção e exclusão:** encontre períodos precisos e verifique se backups, sistemas antifraude e processadores seguem o mesmo cronograma.
4. **Evidências:** prefira auditorias públicas com escopo, data, descobertas e correções; clientes reproduzíveis/open source; relatórios de transparência; e incidentes documentados.
5. **Protocolo e cliente:** WireGuard, OpenVPN ou outro protocolo revisado e mantido; atualizações automáticas; tratamento de DNS e IPv6; kill switch; e testes de leak por plataforma.
6. **Modelo de negócio:** entenda como um serviço gratuito ou subsidiado é financiado. A presença em uma app store, por si só, não prova uma operação confiável.
7. **Adequação do pagamento:** um método de pagamento alternativo pode reduzir a divulgação de informações de cobrança à VPN, mas não elimina o IP de origem observado em cada conexão.

### Configurar e verificar uma VPN

1. Instale o cliente assinado do provedor/organização a partir de sua fonte oficial.
2. Selecione **full tunnel**, a menos que uma rota documentada precise ignorá-lo. Split tunneling cria caminhos de correlação e leak.
3. Ative o comportamento fail-closed/always-on e bloqueie o tráfego durante a reconexão.
4. Envie o DNS pelo túnel e teste IPv4 e IPv6. Desative um protocolo apenas se ele não puder ser tunelado com segurança e a perda de funcionalidade for aceita.
5. Teste suspensão/retomada, troca de rede, login em captive portal, falha do túnel e tethering por hotspot. A NCSC alerta que clientes tethered podem ignorar a VPN do telefone em algumas plataformas.<sup>[[2]](#references)</sup>
6. Use um endpoint de teste controlado pela organização para registrar IPv4, IPv6, resolvedor DNS e tempo de conexão observados. Não exponha um engagement sensível a sites aleatórios de “teste de leak”.
7. Faça novos testes após alterações no cliente, no SO, na rede ou na política.

## Tor Browser: unlinkability web mais forte

O Tor cria um circuito por vários relays para que nenhum relay individual normalmente conheça origem e destino. O destino vê uma saída Tor em vez do IP do usuário; a rede local normalmente vê uma conexão Tor.<sup>[[3]](#references)</sup> O Tor foi projetado para aplicações TCP de baixa latência, portanto é mais lento e não pode garantir proteção contra um adversário capaz de correlacionar ambas as extremidades.<sup>[[4]](#references)</sup>

### Fluxo seguro do Tor Browser

1. Baixe o Tor Browser somente do Tor Project ou de um mirror oficial e verifique a assinatura quando possível.
2. Use o **Tor Browser**, não um navegador normal apontado para uma porta SOCKS do Tor. Navegadores comuns podem causar leak de DNS/WebRTC e de estado identificador.<sup>[[5]](#references)</sup>
3. Mantenha tamanho, fontes, extensões e configurações de privacidade padrão. Add-ons adicionais podem tornar o navegador mais exclusivo.<sup>[[6]](#references)</sup>
4. Escolha o nível de segurança **Safer** ou **Safest** quando o aumento de incompatibilidades for aceitável.
5. Use uma bridge quando o Tor direto estiver bloqueado ou quando os IPs comuns de relays criarem visibilidade local inaceitável. Bridges reduzem o reconhecimento fácil; não eliminam a análise de tráfego.<sup>[[7]](#references)</sup>
6. Não faça login em uma conta identificadora, não forneça informações identificadoras nem abra documentos ativos baixados em um aplicativo externo conectado à rede.
7. Use uma sessão/contexto separado para cada identidade. “New circuit” não é o mesmo que apagar a identidade do navegador/aplicativo; use **New Identity** ou reinicie o ambiente isolado conforme apropriado.
8. Prefira HTTPS autenticado ou um serviço onion autenticado. Uma saída Tor pode observar tráfego HTTP não criptografado.

### Tor com VPN

Combiná-los não é automaticamente mais seguro. Uma VPN antes do Tor pode ocultar conexões diretas aos relays Tor do ISP, enquanto a VPN vê a origem; Tor antes de uma VPN fornece à VPN uma visão estável da atividade pós-Tor e pode reduzir o conjunto de anonimato. Configurações incorretas podem introduzir leaks. O Tor Project recomenda essas combinações apenas para threat models avançados e explícitos.<sup>[[8]](#references)</sup>

## Wi-Fi público e de convidados

O HTTPS moderno significa que vizinhos passivos geralmente não conseguem ler conteúdo web corretamente criptografado, mas o Wi-Fi de convidados não proporciona anonimato. O local pode registrar horários de associação, identificadores do dispositivo, dados do captive portal, destinos e detalhes de DHCP; câmeras, compras, transporte e observação física podem identificar o usuário. Um hotspot falso com nome semelhante também pode capturar credenciais do portal ou manipular tráfego não criptografado.<sup>[[9]](#references)</sup>

### Fluxo legal para rede de convidados

1. Use somente uma rede oferecida para convidados ou uma para a qual o proprietário tenha concedido permissão explícita. Peça à equipe o SSID exato e o procedimento do portal.
2. Atualize o endpoint e o travel router antes da chegada. Desative compartilhamento de arquivos/impressoras, descoberta de entrada, auto-join e sondagem de redes lembradas.
3. Ative o endereço Wi-Fi privado/randomizado do SO. Sistemas Apple atuais podem usar endereços rotativos em redes abertas/fracas; a randomização moderna do Android costuma ser persistente por SSID. Isso reduz apenas um identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prefira um travel router controlado pela organização ou um dispositivo bridge de baixa confiança entre uma workstation privilegiada e a rede de convidados. Isso centraliza a política de firewall/VPN, mas não oculta o router do local.<sup>[[12]](#references)</sup>
5. Conclua um captive portal somente pelo dispositivo/navegador designado de baixa confiança. Nunca insira credenciais pessoais ou reutilizadas em um contexto supostamente anônimo. Feche o navegador do portal após estabelecer a conectividade.
6. Inicie uma VPN full-tunnel ou Tor antes de atividades sensíveis e confirme o comportamento fail-closed.
7. Remova a rede após o uso e revise a política de conta e retenção de dados do portal.

{% hint style="danger" %}
Invadir o Wi-Fi de um vizinho, contornar um portal, usar credenciais de convidados obtidas por leak, clonar o acesso de outro convidado ou esconder um Raspberry Pi em um café são atividades não autorizadas — não uma técnica de privacidade. As alternativas seguras são uma rede de convidados legal, um site aprovado pelo cliente ou um drop node documentado, instalado e recuperado com o consentimento por escrito do proprietário.
{% endhint %}

## Travel routers

Um travel router pode isolar uma workstation de broadcasts locais hostis, aplicar um firewall, fornecer um SSID interno consistente e reconectar uma VPN automaticamente. Ele **não** é anônimo: o upstream vê sua identidade de rádio e o tempo do tráfego, e o provedor de VPN vê a origem do túnel.

- Use firmware OpenWrt/vendor suportado e remova serviços não utilizados.
- Administre via Ethernet ou por um SSID de gerenciamento dedicado com uma senha exclusiva.
- Desative administração pelo lado WAN, UPnP, WPS, compartilhamento de arquivos e tráfego de entrada não solicitado.
- Use um MAC WAN randomizado/privado somente quando houver suporte e permissão.
- Aplique a política de VPN no router, incluindo DNS e IPv6, e bloqueie a saída quando o túnel falhar.
- Não presuma que um hotspot de telefone tunela dispositivos tethered pela VPN do telefone; teste isso.

## Celular, SIMs e eSIMs

A conectividade celular é conveniente, mas não anônima. As operadoras mantêm identificadores de assinante/dispositivo e localização derivada da conexão à rede; um eSIM continua sendo uma assinatura móvel. Pré-pago não significa necessariamente não registrado — os requisitos variam por país e mudam.<sup>[[13]](#references)</sup>

Operacionalmente:

- Use um dispositivo separado e suportado para reduzir a exposição de dados pessoais, não para criar um assinante fictício.
- Não carregue continuamente um dispositivo “separado” junto com um telefone pessoal se a co-localização fizer parte do threat model.
- Desative celular, Wi-Fi, Bluetooth e acesso à localização não utilizados; desligar o dispositivo cria um limite de rádio mais forte do que alternâncias na UI.
- Coloque o tráfego sensível dentro do caminho VPN/Tor aprovado, reconhecendo que a operadora ainda conhece a assinatura, a localização do dispositivo e o endpoint do túnel.
- Verifique as regras atuais de registro e retenção com o regulador nacional ou consultor jurídico local; não dependa de listas online de “países com SIMs anônimos”.

## Metadados de DNS e TLS

- **DoH/DoT/DoQ** criptografam o DNS entre o cliente e o resolvedor, impedindo leitura ou modificação local simples, mas o resolvedor ainda vê consultas e identificadores de transporte. Eles transferem confiança; não fornecem anonimato.<sup>[[14]](#references)</sup>
- **ODoH** adiciona um proxy para que o resolvedor não precise conhecer o IP do cliente, assumindo que o proxy e o destino não colaborem. A análise de tráfego está explicitamente fora do escopo.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** pode proteger o nome interno do servidor em um handshake TLS quando cliente, DNS e servidor oferecem suporte. IP de destino, tempo, volume e endpoint continuam visíveis.<sup>[[16]](#references)</sup>
- Em um ambiente VPN ou Tor configurado corretamente, o DNS deve seguir a rota suportada por esse ambiente. Adicionar um resolvedor separado pode criar um novo observador ou fingerprint.

### Fluxo de verificação de DNS criptografado/ECH

1. Decida se o DNS será controlado pelo ambiente VPN/Tor, pelo SO ou pelo aplicativo. Configure-o em **uma** camada pretendida, em vez de empilhar resolvedores não relacionados.
2. Selecione um resolvedor com base em sua política publicada de privacidade/retenção e ative o modo criptografado estrito quando a plataforma oferecer suporte. O fallback oportunista pode retornar silenciosamente ao texto simples.
3. Consulte um subdomínio exclusivo sob uma zona de teste autoritativa que você controle; confirme que o log autoritativo vê o resolvedor recursivo pretendido.
4. Capture apenas o tráfego do dispositivo de teste com autorização. Confirme que a rede de acesso não consegue ler o DNS em texto simples, reconhecendo que ela pode ver o endpoint do resolvedor/túnel criptografado.
5. Teste um resolvedor criptografado bloqueado/inalcançável. A condição de sucesso é o comportamento fail-closed escolhido ou o fallback documentado — não uma consulta acidental em texto simples.
6. Para ECH, use um host controlado com ECH habilitado e inspecione os diagnósticos do cliente/servidor para confirmar que o **inner** ClientHello foi aceito. Oferecer apenas um registro HTTPS não prova que o ECH funcionou.
7. Repita após mudanças de rede, captive portals, atualizações do navegador e reconexões da VPN. Registre qual componente controla DNS/ECH para que administradores posteriores não criem um bypass.

## Mixnets

Mixnets como Nym ou Katzenpost adicionam pacotes de tamanho fixo, atrasos, reordenação e cover traffic para resistir à correlação temporal. Essas propriedades custam latência e largura de banda, e as evidências independentes em escala de deployment são limitadas. Trate as mixnets de consumo atuais como **opções emergentes/de alta latência**, não como substitutas mais rápidas ou garantidas para Tor/VPNs.<sup>[[17]](#references)</sup>

### Fluxo de avaliação

1. Identifique um cliente mantido e o aplicativo exato suportado; não force tráfego arbitrário do navegador/SO por um proxy não documentado.
2. Leia o threat model atual para entrada, mix nodes, gateway, destino e premissas de conluio.
3. Instale a partir da fonte oficial assinada em um compartimento de teste separado e use somente um endpoint próprio benigno.
4. Meça latência de entrega, limites de tamanho de mensagem, confiabilidade, retransmissão e o que ocorre quando o gateway fica indisponível.
5. Inspecione o tráfego local e o endpoint próprio para confirmar o caminho pretendido e a origem. Verifique se as respostas usam o mesmo design de privacidade.
6. Teste desligamento/falha: o aplicativo não deve retornar silenciosamente ao acesso direto à Internet.
7. Não desative cover traffic, reduza atrasos nem escolha rotas fixas incomuns apenas por velocidade; essas alterações podem invalidar o modelo de anonimato declarado.
8. Mantenha o uso experimental até que o deployment específico, a análise independente e a confiabilidade operacional atendam ao nível de consequência.

## Checklist de preflight da rede

- [ ] A autorização abrange a rede de acesso, o alvo, as datas e a infraestrutura de origem.
- [ ] O endpoint não contém identidades não relacionadas ou sessões de sincronização ativas.
- [ ] IPv4, IPv6, DNS e o comportamento de reconexão correspondem ao plano.
- [ ] O destino vê apenas a saída esperada.
- [ ] O comportamento de captive portal e hotspot foi testado sem tráfego sensível.
- [ ] Compartilhamento/descoberta local e conexão automática a redes estão desativados.
- [ ] A tabela de observadores e o risco residual de correlação de tráfego foram aceitos.
- [ ] A política, retenção e contato de emergência do provedor estão atualizados.

Para relays de conhecimento dividido, workloads com roteamento imposto, transportes plugáveis, serviços onion, I2P e navegadores remotos descartáveis, continue para [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Escolhendo a VPN certa para você](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Orientação de segurança de dispositivos: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — As proteções de privacidade e anonimato oferecidas pelo Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Uma breve introdução ao Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usando o Tor com outros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins e add-ons no Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Desbloqueando o Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usando o Tor Browser com uma VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — As redes Wi-Fi públicas são seguras?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privacidade de Wi-Fi com dispositivos Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementar randomização de MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Princípios para estações de trabalho seguras de acesso privilegiado](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obrigatório de SIM: perspectivas políticas e regulatórias](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendações para operadores de serviços de privacidade DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
