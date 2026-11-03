# Privacidade de rede e conectividade anônima

{{#include ../banners/hacktricks-training.md}}

A privacidade de rede é uma decisão de roteamento, não uma identidade completa. Escolha um caminho perguntando quem não deve conseguir vincular **origem**, **destino**, **conteúdo** e **horário**.

Para o inventário normalizado — `Pros`, `Cons`, `Procedure` passo a passo e `Detection` para cada família de caminhos de acesso — comece pelo [Catálogo de técnicas de acesso anônimo à Internet](anonymous-internet-access-techniques.md). Esta página detalha as opções comuns que podem ser implementadas.

## O que cada observador geralmente consegue ver

| Caminho | Rede local / ISP | Intermediário | Destino | Limitação principal | Velocidade relativa |
|---|---|---|---|---|---|
| HTTPS direto | Origem, metadados do destino, horário/volume | O serviço de hospedagem/CDN vê a conexão | IP de origem, dados do navegador/app | Não protege a privacidade do IP de origem | Mais rápida |
| VPN comercial | Origem conectada à VPN; não vê os metadados habituais do destino | A VPN vê a origem e os metadados do destino | IP de saída da VPN | Um provedor se torna um ponto de correlação | Geralmente rápida |
| VPN/VPS auto-hospedada | Origem conectada à VPS | Logs do host/conta/pagamento/plano de controle | IP de saída da VPS | Fácil de atribuir ao servidor/conta alugados | Geralmente rápida |
| Tor Browser | Origem conectada ao Tor/bridge; horário/volume | Cada relay vê uma parte limitada | Exit do Tor, dados do navegador | Mais lento; riscos relacionados a contas/endpoints/correlação | Moderada/lenta |
| Tails/Whonix | Caminho Tor semelhante, com limites de roteamento mais rígidos | Mesmas limitações do Tor | Exit do Tor/dados do aplicativo | Erros operacionais e o host/hardware continuam sendo fatores | Moderada/lenta |
| Wi-Fi público para visitantes + HTTPS | O local vê o dispositivo local/horário e os destinos | O ISP do local vê metadados | IP público do visitante | Correlação física/captive portal/dispositivo | Rápida/variável |
| Hotspot celular | A operadora vê assinante/dispositivo/localização e destinos | VPN/Tor, se usados | IP de saída da operadora, VPN ou Tor | A assinatura móvel e a localização são identificadores duradouros | Rápida/variável |
| Mixnet | O acesso revela o uso da mixnet; horário/volume | Vários nós de mixagem | Gateway/saída | Ecossistema emergente; custo de latência e largura de banda | Mais lenta |

HTTPS protege o conteúdo em trânsito, mas não todos os metadados. A EFF observa que o domínio, o horário e o tamanho do tráfego podem continuar visíveis para intermediários, mesmo quando caminhos de página, credenciais e mensagens estão criptografados.<sup>[[1]](#references)</sup>

Uma rede sobreposta criptografada não é automaticamente uma rede de anonimato: peers diretos do Yggdrasil podem ver os endereços IP uns dos outros.<sup>[[20]](#references)</sup> Seu [encaminhamento em userspace e transporte SOCKS](../generic-hacking/tunneling-and-port-forwarding.md#yggdrasil-userspace-overlay-with-yggstack) é uma opção de tunneling, não uma camada de anonimato da origem.<sup>[[20]](#references)[[21]](#references)</sup>

## VPNs: privacidade rápida com confiança concentrada

Uma VPN é útil para ocultar metadados do destino do ISP de acesso, proteger o primeiro salto em uma rede não confiável, apresentar um endereço de saída estável para um engagement ou acessar uma rede privada. Ela **não** torna o usuário anônimo. A VPN vê a conexão de origem e pode observar os metadados do destino; contas, cookies, GPS, fingerprints e informações de pagamento continuam sendo fatores identificáveis.<sup>[[1]](#references)</sup>

### Checklist para avaliar um provedor

1. **Propriedade e jurisdição:** identifique a entidade jurídica, a empresa controladora, os países de operação, os subcontratados de infraestrutura e os processos legais aplicáveis.
2. **Dados coletados:** diferencie dados de conta/faturamento, IP de origem, horários de conexão, largura de banda, telemetria de falhas, consultas DNS e logs de destino. “Sem logs de navegação” não significa “sem coleta de dados”.
3. **Retenção e exclusão:** verifique prazos precisos e se backups, sistemas antifraude e processadores seguem o mesmo cronograma.
4. **Evidências:** prefira auditorias públicas que informem escopo, data, conclusões e correções; clientes reproduzíveis/de código aberto; relatórios de transparência; e incidentes documentados.
5. **Protocolo e cliente:** WireGuard, OpenVPN ou outro protocolo revisado e mantido; atualizações automáticas; tratamento de DNS e IPv6; kill switch; e testes de leak em cada plataforma.
6. **Modelo de negócio:** entenda como um serviço gratuito ou subsidiado é financiado. Estar em uma loja de aplicativos, por si só, não comprova uma operação confiável.
7. **Adequação do pagamento:** formas de pagamento alternativas podem reduzir as informações de faturamento divulgadas à VPN, mas não apagam o IP de origem observado em cada conexão.

### Configurar e verificar uma VPN

1. Instale o cliente assinado do provedor/organização a partir da fonte oficial.
2. Selecione **full tunnel**, a menos que haja uma rota documentada que precise contorná-lo. O split tunneling cria caminhos de correlação e leak.
3. Ative o comportamento fail-closed/always-on e bloqueie o tráfego durante a reconexão.
4. Encaminhe o DNS pelo túnel e teste IPv4 e IPv6. Desative um protocolo somente se não for possível encaminhá-lo com segurança e se a perda de funcionalidade for aceitável.
5. Teste suspensão/reativação, troca de rede, login em captive portal, falha do túnel e tethering por hotspot. O NCSC alerta que, em algumas plataformas, clientes conectados por tethering podem contornar a VPN do telefone.<sup>[[2]](#references)</sup>
6. Use um endpoint de teste controlado pela organização para registrar IPv4, IPv6, resolvedor DNS e horário de conexão observados. Não exponha um engagement sensível a sites aleatórios de “teste de leak”.
7. Faça novos testes após mudanças no cliente, sistema operacional, rede ou política.

### Desvios de roteamento em LANs hostis

Uma VPN pode continuar visivelmente “conectada” enquanto alguns pacotes a contornam, porque o sistema operacional escolhe uma rota **antes** de a VPN criptografar o pacote. O TunnelCrack demonstrou duas formas de explorar exceções de roteamento comuns: **LocalNet** faz um destino na Internet parecer estar na sub-rede diretamente conectada, enquanto **ServerIP** falsifica a resolução do gateway da VPN para que um endereço de destino receba a exceção de rede não criptografada necessária ao transporte da VPN. Essas são falhas do cliente/roteamento, não quebras do WireGuard, OpenVPN, IPsec ou TLS; os payloads HTTPS continuam criptografados de ponta a ponta, mas o observador local pode recuperar metadados de destino/horário e quaisquer dados de protocolos em texto não criptografado.<sup>[[18]](#references)</sup>

O TunnelVision aplica a mesma primitiva pré-criptografia por meio da opção DHCP 121. Um servidor DHCP malicioso ou comprometido pode instalar uma rota classless mais específica do que a rota abrangente da VPN, selecionando a interface física para um host ou intervalo arbitrário. O canal de controle da VPN pode continuar ativo, então um kill switch acionado apenas pela desconexão do túnel pode não ser ativado, e uma única verificação pública de “IP leak” pode não detectar desvios seletivos.<sup>[[19]](#references)</sup>

Um kill switch baseado em filtro de pacotes que permita apenas DHCP e o transporte autenticado da VPN na interface física deve fazer com que isso resulte em comportamento fail-closed, mas a injeção direcionada de rotas ainda pode criar um canal lateral de negação seletiva. Para cargas de trabalho Linux com consequências graves, prefira o [padrão mais robusto de network namespace com rotas impostas](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), no qual o namespace do aplicativo não tem interface física nem rota padrão para a rede não criptografada.<sup>[[19]](#references)</sup>

#### Verificação em laboratório próprio

Teste o cliente/SO/versão exatos em um AP, servidor DHCP, endpoint VPN e destino próprios; afirmações sobre produtos envelhecem rapidamente porque as implementações de roteamento e filtro de pacotes variam de plataforma para plataforma. Capture o tráfego no próprio endpoint e também no servidor de teste — um site que mostra o IP de saída, por si só, não comprova que todos os destinos seguem pelo túnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Conecte a VPN, registre o endereço do servidor VPN e salve todas as tabelas de roteamento IPv4/IPv6 e regras de policy routing. No Windows, use `route print`; no macOS, use `netstat -rn`; no Linux, use os comandos abaixo.
2. Consulte a rota selecionada para vários IPs de destino próprios. O próximo salto/interface deve ser o túnel, exceto pelo endpoint de transporte VPN documentado.
3. Para o TunnelVision, renove a concessão na rede DHCP controlada e instale uma rota da opção 121 **somente para um destino de teste próprio**. O teste passa se o tráfego continuar tunelado ou for bloqueado — nunca se for enviado como tráfego de destino pela interface física.
4. Para o LocalNet, atribua ao cliente uma sub-rede de documentação pública, usada apenas em laboratório, como `203.0.113.0/24`, e coloque o destino de teste próprio dentro dela. Verifique se habilitar o acesso à LAN não faz destinos da Internet contornarem o túnel.
5. Para o ServerIP, antes da conexão VPN, configure o DNS controlado para resolver o hostname da VPN para o destino de teste próprio, enquanto o gateway do laboratório encaminha o transporte da VPN ao endpoint VPN real próprio. O cliente não deve isentar tráfego de aplicativo não relacionado destinado ao endereço falsificado.
6. Repita com “acesso à rede local” ativado e desativado, após reconexão, suspensão/reativação, troca de rede e falha do processo da VPN. Teste IPv4, IPv6 e DNS de forma independente.
7. Inspecione a captura na interface física. Ela deve conter DHCP e pacotes criptografados para o servidor VPN, não pacotes endereçados diretamente ao destino de teste próprio. Confirme também que um desvio bloqueado não pode, após prompts do usuário ou reparos de conectividade, voltar silenciosamente a funcionar.

```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```

## Tor Browser: maior unlinkability na web

O Tor cria um circuito por vários relays para que nenhum relay, normalmente, saiba ao mesmo tempo a origem e o destino. O destino vê um exit do Tor, não o IP do usuário; a rede local normalmente vê uma conexão Tor.<sup>[[3]](#references)</sup> O Tor foi projetado para aplicações TCP de baixa latência, por isso é mais lento e não pode garantir proteção contra um adversário capaz de correlacionar as duas pontas.<sup>[[4]](#references)</sup>

### Fluxo de trabalho seguro com o Tor Browser

1. Baixe o Tor Browser somente do Tor Project ou de um mirror oficial e, quando possível, verifique a assinatura.
2. Use o **Tor Browser**, não um navegador comum apontado para uma porta SOCKS do Tor. Navegadores comuns podem causar leaks de DNS/WebRTC e de estado identificável.<sup>[[5]](#references)</sup>
3. Mantenha o tamanho, as fontes, as extensões e as configurações de privacidade padrão. Add-ons adicionais podem tornar o navegador mais exclusivo.<sup>[[6]](#references)</sup>
4. Escolha o nível de segurança **Safer** ou **Safest** quando o aumento de incompatibilidades for aceitável.
5. Use uma bridge quando o Tor direto estiver bloqueado ou quando os IPs de relays comuns criarem visibilidade local inaceitável. Bridges dificultam o reconhecimento; não eliminam a análise de tráfego.<sup>[[7]](#references)</sup>
6. Não faça login em uma conta identificável, não forneça informações que identifiquem você nem abra documentos ativos baixados em um aplicativo externo conectado à rede.
7. Use uma sessão/contexto separado para cada identidade. “New circuit” não é o mesmo que apagar a identidade do navegador/aplicativo; use **New Identity** ou reinicie o ambiente isolado, conforme apropriado.
8. Prefira HTTPS autenticado ou um onion service autenticado. Um exit do Tor pode observar tráfego HTTP não criptografado.

### Tor e VPN

Combiná-los não é automaticamente mais seguro. Uma VPN antes do Tor pode ocultar conexões diretas a relays do Tor do ISP, enquanto a VPN vê a origem; Tor antes de uma VPN dá à VPN uma visão estável da atividade pós-Tor e pode reduzir o conjunto de anonimato. Uma configuração incorreta pode causar leaks. O Tor Project recomenda essas combinações somente para modelos de ameaça explícitos e avançados.<sup>[[8]](#references)</sup>

## Wi-Fi público e de visitantes

O HTTPS moderno significa que vizinhos passivos geralmente não conseguem ler conteúdo web criptografado corretamente, mas Wi-Fi de visitantes não garante anonimato. O estabelecimento pode registrar horários de associação, identificadores de dispositivos, dados do captive portal, destinos e detalhes de DHCP; câmeras, compras, transporte e observação física podem identificar o usuário. Um hotspot falso com nome semelhante também pode capturar credenciais do portal ou manipular tráfego não criptografado.<sup>[[9]](#references)</sup>

### Fluxo de trabalho legal para redes de visitantes

1. Use somente uma rede oferecida a visitantes ou uma para a qual o proprietário tenha concedido permissão explícita. Peça à equipe o SSID exato e o procedimento do portal.
2. Atualize o endpoint e o travel router antes da chegada. Desative o compartilhamento de arquivos/impressoras, a descoberta de entrada, a conexão automática e a sondagem de redes lembradas.
3. Ative o endereço Wi-Fi privado/aleatório do sistema operacional. Sistemas Apple atuais podem usar endereços rotativos em redes abertas/fracas; a randomização do Android moderno costuma ser persistente por SSID. Isso reduz apenas um identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prefira um travel router controlado pela organização ou um dispositivo bridge de baixa confiança entre uma estação de trabalho privilegiada e a rede de visitantes. Isso centraliza as políticas de firewall/VPN, mas não oculta o router do estabelecimento.<sup>[[12]](#references)</sup>
5. Acesse um captive portal somente pelo dispositivo/navegador designado de baixa confiança. Nunca insira credenciais pessoais ou reutilizadas em um contexto supostamente anônimo. Feche o navegador do portal depois de estabelecer a conexão.
6. Inicie uma VPN de túnel completo ou o Tor antes de atividades sensíveis e confirme o comportamento fail-closed.
7. Esqueça a rede após o uso e revise a política de retenção de dados/conta do portal.

{% hint style="danger" %}
Invadir o Wi-Fi de um vizinho, contornar um portal, usar credenciais de visitantes vazadas, clonar o acesso de outro visitante ou esconder um Raspberry Pi em um café são atividades não autorizadas — não são técnicas de privacidade. As alternativas seguras são uma rede de visitantes legal, um local aprovado pelo cliente ou um drop node documentado, instalado e recolhido com o consentimento por escrito do proprietário.
{% endhint %}

## Travel routers

Um travel router pode isolar uma estação de trabalho de broadcasts locais hostis, aplicar um firewall, fornecer um SSID interno consistente e reconectar uma VPN automaticamente. **Não** garante anonimato: a rede upstream vê sua identidade de rádio e os horários do tráfego, e o provedor de VPN vê a origem do túnel.

- Use firmware compatível do OpenWrt/fornecedor e remova serviços não utilizados.
- Administre por Ethernet ou por um SSID de gerenciamento dedicado, com uma senha exclusiva.
- Desative a administração pela WAN, UPnP, WPS, compartilhamento de arquivos e tráfego de entrada não solicitado.
- Use um MAC WAN aleatório/privado somente quando houver suporte e isso for permitido.
- Aplique a política de VPN no router, incluindo DNS e IPv6, e bloqueie o tráfego de saída se o túnel falhar.
- Não presuma que o hotspot de um celular encaminha dispositivos conectados por tethering pela VPN do celular; teste.

## Celular, SIMs e eSIMs

A rede celular é conveniente, mas não é anônima. As operadoras mantêm identificadores de assinantes/dispositivos e dados de localização derivados da conexão à rede; um eSIM ainda é uma assinatura móvel. O pré-pago não significa necessariamente que não há registro — os requisitos variam por país e mudam.<sup>[[13]](#references)</sup>

Na prática:

- Use um dispositivo separado e compatível para reduzir a exposição de dados pessoais, não para criar um assinante fictício.
- Não carregue continuamente um dispositivo “separado” junto com um celular pessoal se a co-localização fizer parte do modelo de ameaça.
- Desative o acesso celular, Wi-Fi, Bluetooth e à localização quando não forem usados; desligar o dispositivo estabelece uma barreira de rádio mais forte do que alternar opções na interface.
- Encaminhe o tráfego sensível pela VPN/Tor aprovada, reconhecendo que a operadora ainda sabe a localização da assinatura/dispositivo e o endpoint do túnel.
- Verifique as regras atuais de registro e retenção junto ao regulador nacional ou a um advogado local; não confie em listas online de “países com SIMs anônimos”.

## Metadados de DNS e TLS

- **DoH/DoT/DoQ** criptografam o DNS entre o cliente e o resolver, impedindo a leitura ou modificação local simples, mas o resolver ainda vê as consultas e os identificadores de transporte. Eles transferem a confiança; não proporcionam anonimato.<sup>[[14]](#references)</sup>
- **ODoH** adiciona um proxy para que o resolver não precise conhecer o IP do cliente, desde que o proxy e o destino não colaborem. A análise de tráfego está explicitamente fora do escopo.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** pode proteger o nome interno do servidor em um handshake TLS quando o cliente, o DNS e o servidor oferecem suporte. O IP de destino, o horário, o volume e o endpoint continuam visíveis.<sup>[[16]](#references)</sup>
- Em um ambiente VPN ou Tor configurado corretamente, o DNS deve seguir a rota compatível com esse ambiente. Adicionar um resolver separado pode criar um novo observador ou uma nova impressão digital.

### Fluxo de verificação de DNS criptografado/ECH

1. Decida se o DNS é controlado pelo ambiente VPN/Tor, pelo sistema operacional ou pelo aplicativo. Configure-o em **uma** camada planejada, em vez de empilhar resolvers sem relação entre si.
2. Escolha um resolver com base na política publicada de privacidade/retenção e ative o modo criptografado estrito quando houver suporte na plataforma. O fallback oportunista pode voltar silenciosamente ao texto simples.
3. Consulte um subdomínio exclusivo em uma zona de teste autoritativa que você controla; confirme que o log autoritativo mostra o resolver recursivo planejado.
4. Capture somente o tráfego do dispositivo de teste, com autorização. Confirme que a rede de acesso não consegue ler DNS em texto simples, reconhecendo que ela consegue ver o endpoint do resolver/túnel criptografado.
5. Teste um resolver criptografado bloqueado/inacessível. A condição de aprovação é o comportamento fail-closed escolhido ou o fallback documentado — não uma consulta acidental sem criptografia.
6. Para ECH, use um host habilitado para ECH sob seu controle e inspecione os diagnósticos do cliente/servidor para confirmar que o **ClientHello** interno foi aceito. Apenas oferecer um registro HTTPS não comprova que o ECH funcionou.
7. Repita após mudanças de rede, captive portals, atualizações do navegador e reconexões da VPN. Registre qual componente controla DNS/ECH para que administradores futuros não criem um bypass.

## Mixnets

Mixnets como Nym ou Katzenpost adicionam pacotes de tamanho fixo, atraso, reordenação e tráfego de cobertura para resistir à correlação temporal. Essas propriedades custam latência e largura de banda, e há poucas evidências independentes em escala de implantação. Trate as mixnets de consumo atuais como **opções emergentes/de alta latência**, não como substitutas mais rápidas ou garantidas para Tor/VPNs.<sup>[[17]](#references)</sup>

### Fluxo de avaliação

1. Identifique um cliente mantido e o aplicativo exato compatível; não force tráfego arbitrário do navegador/sistema por um proxy não documentado.
2. Leia o modelo de ameaça atual para as premissas sobre entrada, mix nodes, gateway, destino e colaboração.
3. Instale a partir da fonte oficial assinada em um compartimento de teste separado e use somente um endpoint próprio e benigno.
4. Meça a latência de entrega, os limites de tamanho das mensagens, a confiabilidade, as retransmissões e o que acontece quando o gateway fica indisponível.
5. Inspecione o tráfego local e o endpoint próprio para confirmar a rota e a origem planejadas. Verifique se as respostas usam o mesmo modelo de privacidade.
6. Teste o encerramento/falha: o aplicativo não deve recorrer silenciosamente ao acesso direto à Internet.
7. Não desative o tráfego de cobertura, não reduza os atrasos nem escolha rotas fixas incomuns apenas para ganhar velocidade; essas mudanças podem invalidar o modelo de anonimato declarado.
8. Mantenha a solução em caráter experimental até que a implantação específica, a análise independente e a confiabilidade operacional sejam adequadas ao nível de consequência.

## Checklist prévio de rede

- [ ] A autorização cobre a rede de acesso, o alvo, as datas e a infraestrutura de origem.
- [ ] O endpoint não contém identidades não relacionadas nem sessões de sincronização ativas.
- [ ] IPv4, IPv6, DNS e comportamento de reconexão correspondem ao plano.
- [ ] A injeção controlada de rotas DHCP/sub-rede local não consegue mover o tráfego de teste para a interface física.
- [ ] O destino vê somente a saída esperada.
- [ ] O comportamento do captive portal e do hotspot foi testado sem tráfego sensível.
- [ ] O compartilhamento/descoberta local e a conexão automática a redes estão desativados.
- [ ] A tabela de observadores e o risco residual de correlação de tráfego são aceitos.
- [ ] A política do provedor, a retenção e o contato de emergência estão atualizados.

Para relays com conhecimento dividido, workloads com rotas impostas, pluggable transports, onion services, I2P e navegadores remotos descartáveis, continue para [Arquiteturas avançadas de privacidade de rede](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Como escolher a VPN certa para você](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Orientações de segurança de dispositivos: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — As proteções de privacidade e anonimato oferecidas pelo Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Uma breve introdução ao Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Usar o Tor com outros navegadores](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins e add-ons no Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Desbloquear o Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Usar o Tor Browser com uma VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Redes Wi-Fi públicas são seguras?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Privacidade de Wi-Fi com dispositivos Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implementar a randomização de MAC](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Princípios para estações de trabalho seguras com acesso privilegiado](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obrigatório de SIM: perspectivas políticas e regulatórias](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendações para operadores de serviços de privacidade de DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — DNS sobre HTTPS Oblivious](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Modelo de ameaça](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Contornando túneis: vazamento de tráfego de clientes VPN por meio do abuso de tabelas de roteamento](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: como atacantes podem desanonimizar VPNs baseadas em roteamento e causar um leak total da VPN](https://www.leviathansecurity.com/blog/tunnelvision)
- [20] [FAQ do Yggdrasil: o Yggdrasil é anônimo?](https://yggdrasil-network.github.io/faq.html#is-yggdrasil-anonymous)
- [21] [README do Yggstack](https://github.com/yggdrasil-network/yggstack)
{{#include ../banners/hacktricks-training.md}}
