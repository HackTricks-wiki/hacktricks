# Acesso Físico e Sem Fio Encoberto

{{#include ../banners/hacktricks-training.md}}

Para uma implementação detalhada e aprovada pelo proprietário, abrangendo rendezvous de saída, recuperação de energia/uplink, segredos mínimos armazenados no dispositivo, testes de captura e monitoramento para possível descoberta, consulte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Alterar o caminho da rede também pode mudar a origem física aparente. Um agente sofisticado pode usar um sistema comprometido próximo, um dispositivo oculto, acesso público, backhaul celular ou um receptor de satélite, fazendo com que os logs do alvo apontem para longe do operador. Nenhuma dessas opções elimina evidências físicas, de rádio ou do provedor; elas transferem a atribuição para diferentes conjuntos de dados.

## Matriz de técnicas

| Técnica | Origem aparente | Condição necessária | Evidência de alto valor |
|---|---|---|---|
| Pivot sem fio próximo | uma empresa ou residência ao lado do alvo | host dual-homed comprometido e acesso ao Wi-Fi do alvo | logs de endpoint do host vizinho, associação de RF e RADIUS/DHCP do alvo |
| Rede pública/de convidados | NAT do local ou saída do túnel | acesso legal ou bypass do controle de acesso | captive portal, DHCP, associação ao AP, CCTV e registros de pagamento/localização |
| Dispositivo de drop encoberto | endereço cabeado, Wi-Fi ou celular do alvo/próximo a ele | instalação física ou entrega | switchport/USB, RF, inventário, energia e telemetria do túnel de saída |
| Roteador celular/eSIM | NAT da operadora ou APN dedicado | modem/SIM/assinatura | IMEI/IMSI/eSIM, setor de célula, conta da operadora e temporização do tráfego |
| Abuso de link via satélite | endereço do assinante dentro da área de cobertura do feixe | vulnerabilidade específica do protocolo e do serviço | localização de RF, fluxo de uplink, RTT/roteamento impossível e registros do provedor |

## Ataque Nearest Neighbor

A Volexity documentou uma operação de APT28/GRU em 2022 na qual o agente estava remoto em relação ao seu alvo final. Ele realizou password spraying contra o serviço público do alvo para obter credenciais válidas, mas a MFA impediu o login direto pela Internet. O Wi-Fi corporativo do alvo aceitava essas credenciais sem MFA. O agente comprometeu organizações fisicamente próximas ao alvo, encontrou um sistema dual-homed com alcance sem fio e usou esse sistema para se autenticar no Wi-Fi do alvo. A Volexity chamou isso de **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
A novidade está na composição. Nenhum operador se desloca até o alvo, e o MFA do serviço exposto à Internet continua funcionando. O vizinho comprometido fornece a proximidade física; a credencial roubada do alvo fornece o acesso lógico; o Wi-Fi do alvo torna-se o caminho que atravessa a fronteira.

### Pré-condições e visibilidade

- Um sistema próximo deve ser controlável remotamente e ter um rádio compatível ou acesso a outro pivot próximo.
- O SSID do alvo deve alcançar esse sistema, e a admissão ao Wi-Fi deve aceitar uma credencial/certificado/estado do dispositivo reutilizável.
- O pivot geralmente precisa de dois caminhos simultâneos: um de volta ao operador e outro para a WLAN do alvo.
- O alvo pode ver um novo MAC de estação e um nome de usuário legítimo, mas nenhum certificado de dispositivo gerenciado, postura, histórico ou entrada esperada no prédio correspondente.
- Os logs do endpoint vizinho podem mostrar scans wireless, novos perfis, alterações de interface, tunneling e atividade de controle remoto.

### Detecção e prevenção

1. Exija EAP-TLS respaldado por certificado e postura de dispositivo gerenciado para o Wi-Fi corporativo; não considere suficiente uma senha que falhou no MFA na Internet apenas porque chega pelo rádio.
2. Correlacione a autenticação RADIUS com a identidade do MDM/NAC, o vínculo histórico entre estação e dispositivo, a localização do AP, eventos de acesso físico e sessões simultâneas.
3. Gere alertas quando uma conta se associar pela primeira vez, a partir de uma borda de AP incomum, sem um certificado gerenciado ou enquanto a mesma identidade estiver ativa em outro local.
4. Monitore endpoints capazes de fazer bridge entre interfaces. No Windows, Linux e appliances de rede, investigue perfis WLAN inesperados, configurações de forwarding/NAT, adaptadores virtuais e túneis persistentes.
5. Reduza o vazamento desnecessário de sinal com posicionamento adequado dos APs e planejamento de potência. Esse é um controle auxiliar, não autenticação.
6. Coordene a resposta a incidentes com tenants vizinhos: a fonte final do rádio pode ser ela própria uma vítima.

O [lab de emulação de adversário com duas organizações próprias](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduz esses observáveis sem atacar um vizinho.

## Locais públicos e Wi-Fi de terceiros

Usar o Wi-Fi de um café, hotel, aeroporto ou município altera o IP mostrado a um destino. Isso não cria anonimato. O local ou seu provedor pode reter a associação ao AP, o MAC do dispositivo, a concessão DHCP, a conta do captive portal, a validação por SMS/email e os logs de fluxo. Registros de entrada física, CFTV, compras, localização móvel e viagens podem conectar o evento digital a uma pessoa.

Um ator pode tentar reduzir uma dessas identificações usando endereços MAC randomizados, um dispositivo separado, dinheiro ou um túnel. A correlação entre camadas continua possível por meio do horário de chegada, padrão recorrente de uso do local, fingerprints de rádio, comportamento do portal, timing do tráfego, imagens de câmeras e o provedor do túnel. Uma VPN também move o destino dos logs do local para os logs da VPN; ela não elimina o conhecimento do local de que o dispositivo esteve presente.

Os responsáveis pelo acesso público devem isolar os clientes, bloquear o tráfego lateral, usar WPA2/3-Enterprise ou chaves por dispositivo quando viável, reter logs DHCP/RADIUS/security proporcionais, proteger captive portals e publicar um processo para abuso. Red teams devem usar esse tipo de local somente quando seus termos e o engagement permitirem; contornar um portal, roubar acesso ou atacar outros visitantes não é um atalho autorizado para testes.

## Dispositivos de drop covert e warshipping

Um drop é um pequeno sistema colocado ou entregue em um local e depois controlado por meio de Ethernet, Wi-Fi ou celular de saída. “Warshipping” acondiciona o dispositivo de modo que uma entrega comum o transporte para dentro do perímetro de rádio. O hardware possível varia de um computador de placa única a um carregador modificado, periférico USB, appliance de rede ou modem alimentado por bateria.

Arquitetura operacional:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
O dispositivo pode fornecer um ponto de apoio remoto, realizar medições sem fio, emular um peripheral autorizado para exercícios ou retransmitir tráfego. Sua origem aparente é local, mas ele cria artefatos físicos: números de série, embalagens, fingerprints, câmeras, logs de acesso, consumo de energia, descritores USB, negociação de switchport, fingerprints de DHCP, comportamento de OUI/randomização de MAC, emissões de RF e conexões recorrentes de rendezvous.

### Controles defensivos

- Mantenha procedimentos para a sala de recebimento e o inventário de ativos; inspecione eletrônicos e pacotes inesperados endereçados a funcionários inexistentes.
- Use 802.1X/NAC em acessos cabeados e sem fio, desative portas não utilizadas e coloque dispositivos desconhecidos em uma VLAN de remediação restrita.
- Gere alertas para novos fingerprints de DHCP, MACs administrados localmente que persistem, novos dispositivos USB de rede/HID, Wi-Fi Direct/Bluetooth não autorizados e túneis de saída de longa duração.
- Estabeleça uma baseline do switchport, power-over-Ethernet, DNS e comportamento de TLS. Um host pequeno sem registro no inventário que faça conexões criptografadas periódicas é um sinal mais forte do que apenas “Raspberry Pi OUI”.
- Durante um exercício, faça o inventário, etiquete, defina o escopo, criptografe, forneça um remote kill, estabeleça um prazo para recuperação e garanta que a perda não possa expor credenciais reutilizáveis.

## Backhaul celular e eSIM

Um modem celular evita o gateway de Internet do alvo e pode manter um drop acessível atrás de NAT da operadora por meio de um rendezvous de saída. Os endereços móveis podem mudar ou ser compartilhados; ainda assim, a operadora celular possui evidências fortes do assinante e da rede: identidade do SIM/eSIM, IMSI, IMEI do dispositivo, endereços/portas atribuídos, temporização da célula/setor, registros de conta/pagamento e roaming.

Na perspectiva da empresa, detecte modems inesperados e hotspots pessoais com levantamentos de wireless/RF, inventário de USB/PCI dos endpoints, restrições de MDM, monitoramento de rogue SSIDs e inspeção física. Um drop que use celular para controle ainda pode ser detectado por seu comportamento local de Ethernet/Wi-Fi e por suas emissões de rádio.

Para exercícios autorizados, a organização deve ser proprietária da assinatura e do modem, registrar os identificadores com o controlador e validar que os termos da operadora/provedor permitem o tráfego. Uma etiqueta pré-paga ou uma compra com cryptocurrency não elimina os registros de torre, dispositivo ou varejo.

## Randomização de MAC e fingerprinting de dispositivos

Sistemas modernos podem usar um MAC randomizado e administrado localmente para cada rede. Isso reduz o rastreamento passivo de longo prazo por um MAC de fábrica estável; não oculta:

- o timing de probe/associação e o conjunto de recursos de rede solicitados;
- elementos de informação 802.11, taxas compatíveis e comportamento específico do fornecedor;
- opções/hostname de DHCP, identificadores IPv6 e fingerprint de captive portal/navegador;
- identidade ou certificado autenticado de 802.1X;
- conta de camada superior, túnel e padrão de tráfego; ou
- observação física.

Os defensores não devem usar allowlists de MAC como autenticação. Relacione a identidade de rádio à postura do certificado/dispositivo e trate MACs que mudam como normais, a menos que outro contexto seja anômalo.

## Sequestro de link via satélite

A Kaspersky documentou a Turla usando fragilidades em um serviço mais antigo de Internet via satélite DVB-S unidirecional. No modelo relatado, um assinante remoto legítimo enviava solicitações de saída por um link terrestre, mas recebia dados downstream por meio de uma transmissão via satélite de ampla cobertura e não criptografada. Um ator dentro da área de cobertura do satélite podia observar o downlink, escolher um IP de assinante ativo e fazer com que as respostas de C2 fossem endereçadas a esse IP. Tanto o assinante legítimo quanto o ator recebiam a transmissão; o ator extraía o tráfego da porta selecionada, enquanto o assinante legítimo descartava os pacotes não solicitados. O operador de C2 então aparentava usar um endereço do provedor de satélite em outra região geográfica.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Isso era específico do protocolo/serviço, limitado pela largura de banda e não equivalente ao comprometimento de um terminal de satélite moderno bidirecional e criptografado. Também não ocultava o caminho de saída da solicitação do agente de uma observação suficientemente capaz. As oportunidades de detecção incluem roteamento assimétrico/impossível, tráfego para um assinante que não iniciou o fluxo, portas de destino incomuns, telemetria do provedor, investigação da localização do receptor/RF e da configuração do malware. Use este caso para questionar a suposição de que geolocalizar um IP de C2 geolocaliza seu controlador — não como uma receita de construção.

## Planilha de correlação físico-digital

Quando uma origem aparentemente local for suspeita, crie uma única linha do tempo:

1. normalize os relógios de AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controle de acesso físico;
2. identifique a primeira associação de rádio ou ativação do link, não apenas o primeiro alerta;
3. mapeie a estação para o certificado, a postura do dispositivo, a impressão digital de DHCP e a localização do switch/AP;
4. procure atividades simultâneas de controle remoto/túnel em sistemas próximos;
5. revise entregas, visitantes, exceções de inventário, câmeras e achados de RF de acordo com a política/lei aplicável;
6. preserve o dispositivo suspeito e o estado volátil da rede; não desligue ou reinicie indiscriminadamente;
7. determine se a infraestrutura aparentemente originária é controlada pelo agente ou se é outra vítima.

## References

- [1] [Volexity — O ataque do vizinho mais próximo: como um APT russo armou redes Wi-Fi próximas para obter acesso sigiloso](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla via satélite: comando e controle de APT no céu](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Adições de hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Diretrizes para proteger redes locais sem fio](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
