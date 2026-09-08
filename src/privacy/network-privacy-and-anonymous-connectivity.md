# Privacidade de Rede e Conectividade Anônima

A privacidade de rede é uma decisão de roteamento, não uma identidade completa. Selecione um caminho perguntando quem deve ser impedido de correlacionar **origem**, **destino**, **conteúdo** e **tempo**.

Para o inventário normalizado — `Pros`, `Cons`, `Procedure` passo a passo e `Detection` para cada família de caminho de acesso — comece pelo [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Esta página expande as opções comuns e implementáveis.

## O que cada observador normalmente pode ver

| Caminho | Rede local / ISP | Intermediário | Destino | Principal limitação | Velocidade relativa |
|---|---|---|---|---|---|
| HTTPS direto | Metadados da origem, do destino e do tempo/volume | Hosting/CDN vê a conexão | IP de origem, dados do navegador/app | Sem privacidade do IP de origem | Mais rápida |
| VPN comercial | Origem conectada à VPN; não os metadados usuais do destino | VPN vê os metadados da origem e do destino | IP de saída da VPN | Um provedor se torna um ponto de correlação | Normalmente rápida |
| VPN/VPS self-hosted | Origem conectada à VPS | Logs do host/conta/pagamento/control plane | IP de saída da VPS | Fácil atribuição ao servidor/conta alugada | Normalmente rápida |
| Tor Browser | Origem conectada ao Tor/bridge; tempo/volume | Cada relay vê uma parte limitada | Exit do Tor, dados do navegador | Mais lento; riscos de conta/endpoint/correlação | Moderada/lenta |
| Tails/Whonix | Caminho Tor semelhante, com limites de roteamento mais fortes | Mesmas limitações do Tor | Exit do Tor/dados da aplicação | Erros operacionais e host/hardware continuam relevantes | Moderada/lenta |
| Wi-Fi público para visitantes + HTTPS | Local vê dispositivo local/tempo e destinos | ISP do local vê metadados | IP público dos visitantes | Correlação física/captive portal/dispositivo | Rápida/variável |
| Hotspot celular | Operadora vê assinante/dispositivo/localização e destinos | VPN/Tor, se usado | IP de saída da operadora, VPN ou Tor | Assinatura móvel e localização são identificadores duradouros | Rápida/variável |
| Mixnet | Acesso vê o uso da mixnet; tempo/volume | Vários nós de mixing | Gateway/saída | Ecossistema emergente; custo de latência e largura de banda | Mais lenta |

O HTTPS protege o conteúdo em trânsito, mas não todos os metadados. A EFF observa que domínio, horário e tamanho do tráfego podem continuar visíveis para intermediários mesmo quando caminhos de páginas, credenciais e mensagens estão criptografados.<sup>[[1]](#references)</sup>

## VPNs: privacidade rápida com confiança concentrada

Uma VPN é útil para ocultar os metadados do destino do ISP de acesso, proteger o primeiro salto em uma rede não confiável, apresentar um endereço de saída estável para um engagement ou acessar uma rede privada. Ela **não** torna o usuário anônimo. A VPN vê a conexão de origem e pode observar os metadados do destino; contas, cookies, GPS, fingerprints e informações de pagamento permanecem.<sup>[[1]](#references)</sup>

### Checklist de avaliação do provedor

1. **Propriedade e jurisdição:** identifique a entidade legal, a empresa controladora, os países de operação, os subcontratados de infraestrutura e os processos legais aplicáveis.
2. **Dados coletados:** diferencie conta/faturamento, IP de origem, timestamps de conexão, largura de banda, telemetria de falhas, consultas DNS e logs de destino. “Sem logs de navegação” não significa “sem dados”.
3. **Retenção e exclusão:** encontre os períodos precisos e verifique se backups, sistemas antifraude e processadores seguem o mesmo cronograma.
4. **Evidências:** prefira auditorias públicas com escopo, data, descobertas e correções; clients reproduzíveis/open; relatórios de transparência; e incidentes documentados.
5. **Protocolo e client:** WireGuard, OpenVPN ou outro protocolo analisado e mantido; atualizações automáticas; tratamento de DNS e IPv6; kill switch; e testes de leak por plataforma.
6. **Modelo de negócios:** entenda como um serviço gratuito ou subsidiado é financiado. A presença em uma app store, por si só, não é evidência de operação confiável.
7. **Adequação do pagamento:** um método de pagamento alternativo pode reduzir a exposição do faturamento à VPN, mas não elimina o IP de origem observado em cada conexão.

### Configurar e verificar uma VPN

1. Instale o client assinado do provedor/organização a partir de sua fonte oficial.
2. Selecione **full tunnel**, a menos que uma rota documentada precise ignorá-lo. Split tunneling cria caminhos de correlação e leak.
3. Ative o comportamento fail-closed/always-on e bloqueie o tráfego durante a reconexão.
4. Envie o DNS pelo túnel e teste IPv4 e IPv6. Desative um protocolo somente se ele não puder ser tunelado com segurança e a perda de funcionalidade for aceita.
5. Teste suspensão/retomada, troca de rede, login em captive portal, falha do túnel e tethering por hotspot. O NCSC alerta que clients tethered podem ignorar a VPN de um telefone em algumas plataformas.<sup>[[2]](#references)</sup>
6. Use um endpoint de teste controlado pela organização para registrar IPv4, IPv6, resolver DNS e tempo de conexão observados. Não exponha um engagement sensível a sites aleatórios de “leak test”.
7. Repita o teste após alterações no client, OS, rede ou política.

## Tor Browser: unlinkability web mais forte

O Tor cria um circuito por vários relays para que nenhum relay individual normalmente conheça a origem e o destino. O destino vê um exit do Tor em vez do IP do usuário; a rede local normalmente vê uma conexão Tor.<sup>[[3]](#references)</sup> O Tor foi projetado para aplicações TCP de baixa latência, portanto é mais lento e não pode garantir proteção contra um adversário capaz de correlacionar ambas as pontas.<sup>[[4]](#references)</sup>

### Workflow seguro do Tor Browser

1. Baixe o Tor Browser somente do Tor Project ou de um mirror oficial e verifique a assinatura quando possível.
2. Use o **Tor Browser**, não um navegador comum apontado para uma porta SOCKS do Tor. Navegadores comuns podem causar leak de DNS/WebRTC e de estado identificador.<sup>[[5]](#references)</sup>
3. Mantenha tamanho, fontes, extensões e configurações de privacidade padrão. Add-ons adicionais podem tornar o navegador mais exclusivo.<sup>[[6]](#references)</sup>
4. Escolha o nível de segurança **Safer** ou **Safest** quando o aumento de incompatibilidades for aceitável.
5. Use um bridge quando o Tor direto estiver bloqueado ou quando os IPs de relays comuns criarem visibilidade local inaceitável. Bridges reduzem o reconhecimento fácil; não eliminam a análise de tráfego.<sup>[[7]](#references)</sup>
6. Não faça login em uma conta identificadora, não forneça informações identificadoras nem abra documentos ativos baixados em uma aplicação externa conectada à rede.
7. Use uma sessão/contexto separado para cada identidade. “New circuit” não é o mesmo que apagar a identidade do navegador/aplicação; use **New Identity** ou reinicie o ambiente isolado conforme apropriado.
8. Prefira HTTPS autenticado ou um onion service autenticado. Um exit do Tor pode observar tráfego HTTP não criptografado.

### Tor com VPN

Combinar ambos não é automaticamente mais seguro. Uma VPN antes do Tor pode ocultar conexões diretas aos relays do Tor de um ISP, enquanto a VPN vê a origem; Tor antes de uma VPN dá à VPN uma visão estável da atividade pós-Tor e pode reduzir o conjunto de anonimato. Configuração incorreta pode introduzir leaks. O Tor Project recomenda essas combinações somente para threat models avançados e explícitos.<sup>[[8]](#references)</sup>

## Wi-Fi público e para visitantes

O HTTPS moderno significa que vizinhos passivos normalmente não conseguem ler conteúdo web corretamente criptografado, mas o Wi-Fi para visitantes não é anonimato. O local pode registrar horários de associação, identificadores de dispositivos, dados do captive portal, destinos e detalhes de DHCP; câmeras, compras, transporte e observação física podem identificar o usuário. Um hotspot falso com nome semelhante também pode capturar credenciais do portal ou manipular tráfego não criptografado.<sup>[[9]](#references)</sup>

### Workflow legal para rede de visitantes

1. Use somente uma rede oferecida para visitantes ou uma para a qual o proprietário tenha concedido permissão explícita. Pergunte à equipe o SSID exato e o procedimento do portal.
2. Atualize o endpoint e o travel router antes da chegada. Desative compartilhamento de arquivos/impressoras, descoberta de entrada, auto-join e sondagem de redes memorizadas.
3. Ative o endereço Wi-Fi privado/randomizado do OS. Os sistemas Apple atuais podem usar endereços rotativos em redes abertas/fracas; a randomização moderna do Android costuma ser persistente por SSID. Isso reduz apenas um identificador local.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Prefira um travel router controlado pela organização ou um dispositivo bridge de baixo nível de confiança entre uma workstation privilegiada e a rede de visitantes. Isso centraliza a política de firewall/VPN, mas não oculta o router do local.<sup>[[12]](#references)</sup>
5. Conclua o captive portal somente pelo dispositivo/navegador designado de baixo nível de confiança. Nunca insira credenciais pessoais ou reutilizadas em um contexto supostamente anônimo. Feche o navegador do portal após estabelecer a conectividade.
6. Inicie uma VPN full-tunnel ou Tor antes da atividade sensível e confirme o comportamento fail-closed.
7. Esqueça a rede após o uso e revise a política de conta do portal e de retenção de dados.

{% hint style="danger" %}
Invadir o Wi-Fi de um vizinho, contornar um portal, usar credenciais de visitantes obtidas por leak, clonar o acesso de outro visitante ou esconder um Raspberry Pi em um café é atividade não autorizada — não uma técnica de privacidade. As alternativas seguras são uma rede de visitantes legal, um site aprovado pelo cliente ou um drop node documentado, instalado e recuperado com o consentimento por escrito do proprietário.
{% endhint %}

## Travel routers

Um travel router pode isolar uma workstation de broadcasts locais hostis, aplicar um firewall, fornecer um SSID interno consistente e reconectar uma VPN automaticamente. Ele **não** é anônimo: o upstream vê sua identidade de rádio e o tempo do tráfego, e o provedor de VPN vê a origem do túnel.

- Use firmware OpenWrt/vendor suportado e remova serviços não utilizados.
- Administre por Ethernet ou por um SSID de gerenciamento dedicado com uma senha exclusiva.
- Desative administração pelo lado WAN, UPnP, WPS, compartilhamento de arquivos e tráfego de entrada não solicitado.
- Use um MAC WAN randomizado/privado somente quando houver suporte e permissão.
- Aplique a política de VPN no router, incluindo DNS e IPv6, e bloqueie a saída quando o túnel falhar.
- Não presuma que um hotspot de telefone tunela dispositivos tethered pela VPN do telefone; teste isso.

## Celular, SIMs e eSIMs

A rede celular é conveniente, mas não anônima. As operadoras mantêm identificadores de assinante/dispositivo e localização derivada da conexão à rede; um eSIM continua sendo uma assinatura móvel. Pré-pago não significa necessariamente não registrado — os requisitos variam por país e mudam.<sup>[[13]](#references)</sup>

Operacionalmente:

- Use um dispositivo separado e suportado para reduzir a exposição de dados pessoais, não para criar um assinante fictício.
- Não carregue continuamente um dispositivo “separado” junto com um telefone pessoal se a co-localização fizer parte do threat model.
- Desative celular, Wi-Fi, Bluetooth e acesso à localização não utilizados; desligar o dispositivo cria um limite de rádio mais forte do que alternâncias na UI.
- Coloque o tráfego sensível dentro do caminho VPN/Tor aprovado, reconhecendo que a operadora ainda conhece a localização da assinatura/dispositivo e o endpoint do túnel.
- Verifique as regras atuais de registro e retenção com o regulador nacional ou um assessor jurídico local; não dependa de listas online de “países com SIMs anônimos”.

## Metadados de DNS e TLS

- **DoH/DoT/DoQ** criptografam o DNS entre o client e o resolver, impedindo leitura ou modificação local simples, mas o resolver ainda vê consultas e identificadores de transporte. Eles transferem a confiança; não fornecem anonimato.<sup>[[14]](#references)</sup>
- **ODoH** adiciona um proxy para que o resolver não precise conhecer o IP do client, assumindo que proxy e destino não façam collusion. A análise de tráfego está explicitamente fora do escopo.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** pode proteger o nome interno do servidor em um handshake TLS quando client, DNS e servidor oferecem suporte. IP de destino, tempo, volume e endpoint continuam visíveis.<sup>[[16]](#references)</sup>
- Em um ambiente VPN ou Tor configurado corretamente, o DNS deve seguir a rota suportada por esse ambiente. Adicionar um resolver separado pode criar um novo observador ou fingerprint.

### Workflow de verificação de DNS criptografado/ECH

1. Decida se o DNS é controlado pelo ambiente VPN/Tor, pelo OS ou pela aplicação. Configure-o em **uma** camada pretendida, em vez de empilhar resolvers não relacionados.
2. Selecione um resolver com base em sua política publicada de privacidade/retenção e ative o modo criptografado estrito quando a plataforma oferecer suporte. O fallback oportunista pode retornar silenciosamente ao plaintext.
3. Consulte um subdomínio exclusivo em uma zona de teste authoritative que você controle; confirme que o log authoritative vê o recursive resolver pretendido.
4. Capture somente o tráfego do dispositivo de teste com autorização. Confirme que a rede de acesso não consegue ler DNS plaintext, reconhecendo que ela pode ver o endpoint do resolver/túnel criptografado.
5. Teste um resolver criptografado bloqueado/inacessível. A condição de aprovação é o comportamento fail-closed escolhido ou o fallback documentado — não uma consulta clear acidental.
6. Para ECH, use um host controlado com ECH habilitado e examine os diagnostics do client/servidor para confirmar que o **inner** ClientHello foi aceito. Oferecer apenas um registro HTTPS não prova que o ECH funcionou.
7. Repita após alterações de rede, captive portals, atualizações do navegador e reconexões da VPN. Registre qual componente controla o DNS/ECH para que administradores posteriores não criem um bypass.

## Mixnets

Mixnets como Nym ou Katzenpost adicionam pacotes de tamanho fixo, atraso, reordenação e cover traffic para resistir à correlação temporal. Essas propriedades custam latência e largura de banda, e as evidências independentes em escala de implantação são limitadas. Trate as mixnets de consumo atuais como **opções emergentes/de alta latência**, não como substitutas mais rápidas ou garantidas para Tor/VPNs.<sup>[[17]](#references)</sup>

### Workflow de avaliação

1. Identifique um client mantido e a aplicação exata suportada; não force tráfego arbitrário de navegador/sistema por um proxy não documentado.
2. Leia o threat model atual para as suposições sobre entrada, mix nodes, gateway, destino e collusion.
3. Instale a partir da fonte oficial assinada em um compartimento de teste separado e use somente um endpoint próprio benigno.
4. Meça a latência de entrega, os limites de tamanho das mensagens, a confiabilidade, as retransmissões e o comportamento quando o gateway estiver indisponível.
5. Inspecione o tráfego local e o endpoint próprio para confirmar o caminho e a origem pretendidos. Verifique se as respostas usam o mesmo design de privacidade.
6. Teste desligamento/falha: a aplicação não deve retornar silenciosamente ao acesso direto à Internet.
7. Não desative cover traffic, reduza atrasos nem escolha rotas fixas incomuns apenas por velocidade; essas alterações podem invalidar o modelo de anonimato declarado.
8. Mantenha a solução em caráter experimental até que a implantação específica, a análise independente e a confiabilidade operacional correspondam ao nível de consequência.

## Checklist de preflight da rede

- [ ] A autorização abrange a rede de acesso, o alvo, as datas e a infraestrutura de origem.
- [ ] O endpoint não contém identidades não relacionadas nem sessões de sincronização ativas.
- [ ] IPv4, IPv6, DNS e o comportamento de reconexão correspondem ao plano.
- [ ] O destino vê somente a saída esperada.
- [ ] O comportamento do captive portal e do hotspot foi testado sem tráfego sensível.
- [ ] O compartilhamento/descoberta local e a conexão automática a redes estão desativados.
- [ ] A tabela de observadores e o risco residual de correlação de tráfego foram aceitos.
- [ ] A política do provedor, a retenção e o contato de emergência estão atualizados.

Para relays de conhecimento dividido, workloads com roteamento imposto, transportes plugáveis, onion services, I2P e navegadores remotos descartáveis, continue em [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

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
- [12] [UK NCSC — Princípios para workstations seguras de acesso privilegiado](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Registro obrigatório de SIM: perspectivas políticas e regulatórias](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recomendações para operadores de serviços de privacidade de DNS](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
