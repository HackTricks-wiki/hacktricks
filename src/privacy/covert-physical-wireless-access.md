# Acesso físico e sem fio encoberto

Para uma implementação detalhada e aprovada pelo proprietário, abrangendo rendezvous de saída, recuperação de energia/uplink, segredos mínimos mantidos pelo dispositivo, testes de captura e monitoramento para possível descoberta, consulte [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Alterar o caminho de rede também pode alterar a origem física aparente. Um actor sofisticado pode usar um sistema comprometido próximo, um dispositivo oculto, acesso público, backhaul celular ou um receptor de satélite para que os logs do alvo apontem para longe do operador. Nenhuma dessas opções elimina evidências físicas, de rádio ou do provedor; elas deslocam a atribuição para diferentes conjuntos de dados.

## Matriz de técnicas

| Técnica | Origem aparente | Condição necessária | Evidência de alto valor |
|---|---|---|---|
| Pivot sem fio próximo | uma empresa/residência ao lado do alvo | host comprometido com duas interfaces de rede e acesso ao Wi-Fi do alvo | logs do endpoint do host vizinho, associação de RF e RADIUS/DHCP do alvo |
| Rede pública/de convidados | NAT do local ou saída do túnel | acesso autorizado ou bypass do controle de acesso | captive portal, DHCP, associação ao AP, CCTV e registros de pagamento/localização |
| Dispositivo de drop encoberto | endereço cabeado, Wi-Fi ou celular do alvo/próximo a ele | posicionamento físico ou entrega | switchport/USB, RF, inventário, energia e telemetria do túnel de saída |
| Roteador celular/eSIM | NAT da operadora ou APN dedicado | modem/SIM/assinatura | IMEI/IMSI/eSIM, setor de célula, conta da operadora e temporização do tráfego |
| Abuso de link via satélite | endereço do assinante na área de cobertura do feixe | fraqueza específica do protocolo e do serviço | localização de RF, fluxo de uplink, RTT/roteamento impossível e registros do provedor |

## Nearest Neighbor Attack

A Volexity documentou uma operação de APT28/GRU em 2022 na qual o actor estava remoto em relação ao alvo final. Ele realizou password spraying no serviço público do alvo para obter credenciais válidas, mas a MFA impediu o login direto pela Internet. O Wi-Fi corporativo do alvo aceitava essas credenciais sem MFA. O actor comprometeu organizações fisicamente próximas do alvo, encontrou um sistema com duas interfaces de rede e alcance sem fio, e usou esse sistema para se autenticar no Wi-Fi do alvo. A Volexity chamou isso de **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
A novidade está na composição. Nenhum operador se desloca até o alvo, e a MFA do serviço exposto à Internet continua funcionando. O vizinho comprometido fornece proximidade física; a credencial roubada do alvo fornece acesso lógico; o Wi-Fi do alvo torna-se o caminho que atravessa a fronteira.

### Pré-requisitos e visibilidade

- Um sistema próximo deve ser controlável remotamente e ter um rádio compatível ou acesso a outro pivot próximo.
- O SSID do alvo deve alcançar esse sistema, e a admissão ao Wi-Fi deve aceitar uma credencial/certificado/estado de dispositivo reutilizável.
- O pivot geralmente precisa de dois caminhos simultâneos: um de volta ao operador e outro para a WLAN do alvo.
- O alvo pode visualizar um novo MAC de station e um nome de usuário legítimo, mas nenhum certificado de dispositivo gerenciado, postura, histórico ou entrada esperada no edifício correspondente.
- Os logs do endpoint vizinho podem mostrar varreduras wireless, novos perfis, alterações de interface, tunneling e atividade de remote-control.

### Detecção e prevenção

1. Exija EAP-TLS baseado em certificado e postura de dispositivo gerenciado para Wi-Fi corporativo; não considere suficiente uma senha que falhou na MFA na Internet apenas porque chega pelo rádio.
2. Correlacione a autenticação RADIUS com a identidade do MDM/NAC, o vínculo histórico entre station/dispositivo, a localização do AP, eventos de acesso físico e sessões simultâneas.
3. Gere um alerta quando uma conta se associar pela primeira vez, a partir de uma borda de AP incomum, sem um certificado gerenciado ou enquanto a mesma identidade estiver ativa em outro local.
4. Monitore endpoints capazes de fazer bridge entre interfaces. No Windows, Linux e em network appliances, investigue perfis WLAN inesperados, configurações de forwarding/NAT, adaptadores virtuais e túneis persistentes.
5. Reduza o vazamento desnecessário de sinal com posicionamento adequado dos APs e planejamento de potência. Isso é um controle complementar, não autenticação.
6. Coordene a resposta a incidentes com os ocupantes vizinhos: a fonte de rádio final pode ser ela própria uma vítima.

O [laboratório próprio de duas organizações](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduz esses observáveis sem atacar um vizinho.

## Locais públicos e Wi-Fi de terceiros

Usar Wi-Fi de um café, hotel, aeroporto ou município altera o IP mostrado a um destino. Isso não cria anonimato. O local ou seu provedor pode manter registros da associação ao AP, MAC do dispositivo, concessão DHCP, conta do captive portal, validação por SMS/email e fluxos de tráfego. Entrada física, CCTV, compras, localização móvel e registros de viagem podem conectar o evento digital a uma pessoa.

Um ator pode tentar reduzir um identificador usando endereços MAC randomizados, um dispositivo separado, dinheiro ou um túnel. A correlação entre camadas continua possível por meio do horário de chegada, padrão repetido de locais, radio fingerprints, comportamento do portal, timing do tráfego, imagens de câmeras e o provedor do túnel. Uma VPN também transfere o destino dos logs do local para os logs da VPN; ela não remove o conhecimento do local de que o dispositivo esteve presente.

Os responsáveis por acesso público devem isolar os clientes, bloquear tráfego lateral, usar WPA2/3-Enterprise ou chaves por dispositivo quando viável, manter logs proporcionais de DHCP/RADIUS/security, proteger captive portals e publicar um processo para abusos. Red teams devem usar esse tipo de local somente quando seus termos e o engagement permitirem; contornar um portal, roubar acesso ou visar outros clientes não é um atalho autorizado para testes.

## Dispositivos de drop e warshipping

Um drop é um sistema pequeno colocado ou entregue em um local e depois controlado por Ethernet, Wi-Fi ou celular de saída. “Warshipping” embala o dispositivo para que uma entrega comum o leve para dentro do perímetro de rádio. O hardware possível varia de um single-board computer a um carregador modificado, periférico USB, network appliance ou modem alimentado por bateria.

Arquitetura operacional:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
O dispositivo pode fornecer um foothold remoto, realizar medições sem fio, emular um periférico de exercício autorizado ou retransmitir tráfego. Sua origem aparente é local, mas ele cria artefatos físicos: números de série, embalagens, fingerprints, câmeras, registros de acesso, consumo de energia, descritores USB, negociação de switchport, fingerprints de DHCP, OUI/randomization behavior de MAC, emissões de RF e conexões recorrentes de rendezvous.

### Controles defensivos

- Mantenha procedimentos para a sala de recebimento e o inventário de ativos; inspecione eletrônicos e pacotes inesperados endereçados a funcionários inexistentes.
- Use 802.1X/NAC em acessos com e sem fio, desabilite portas não utilizadas e coloque dispositivos desconhecidos em uma VLAN de remediation restrita.
- Gere alertas para novos fingerprints de DHCP, MACs administrados localmente que persistam, novos dispositivos USB de rede/HID, Wi-Fi Direct/Bluetooth não autorizados e túneis de saída de longa duração.
- Estabeleça uma baseline de switchport, power-over-Ethernet, DNS e comportamento de TLS. Um host pequeno sem registro no inventário que faça conexões criptografadas periódicas é um sinal mais forte do que apenas “Raspberry Pi OUI”.
- Durante um exercício, faça o inventário, etiquete, defina o escopo, criptografe, forneça um remote kill, estabeleça um prazo para recuperação e garanta que a perda não possa expor credenciais reutilizáveis.

## Backhaul celular e eSIM

Um modem celular evita o gateway de Internet do alvo e pode manter um drop acessível atrás de carrier NAT por meio de um rendezvous de saída. Os endereços móveis podem mudar ou ser compartilhados; ainda assim, a operadora celular possui fortes evidências do assinante e da rede: identidade do SIM/eSIM, IMSI, endereços/portas atribuídos, temporização de célula/setor, registros de conta/pagamento e roaming.

Do ponto de vista da empresa, detecte modems e hotspots pessoais inesperados com levantamentos de wireless/RF, inventário de USB/PCI nos endpoints, restrições de MDM, monitoramento de rogue SSIDs e inspeção física. Um drop que use celular para controle ainda pode ser detectado por seu comportamento local de Ethernet/Wi-Fi e por suas emissões de rádio.

Para exercícios autorizados, a organização deve ser proprietária da assinatura e do modem, registrar os identificadores com o controlador e validar se os termos da operadora/provedor permitem o tráfego. Uma compra pré-paga ou com cryptocurrency não apaga registros de torres, dispositivos ou varejo.

## Randomization de MAC e fingerprinting de dispositivos

Os sistemas modernos podem usar um MAC randomizado e administrado localmente por rede. Isso reduz o rastreamento passivo de longo prazo por um MAC de fábrica estável; não oculta:

- o timing de probe/association e o conjunto de recursos de rede solicitados;
- elementos de informação 802.11, taxas compatíveis e comportamento específico do fornecedor;
- opções/hostname de DHCP, identificadores IPv6 e fingerprint de captive portal/browser;
- identidade ou certificado autenticado de 802.1X;
- conta na camada superior, túnel e padrão de tráfego; ou
- observação física.

Os defensores não devem usar allowlists de MAC como autenticação. Vincule a identidade de rádio ao certificado/postura do dispositivo e trate MACs variáveis como normais, a menos que outro contexto seja anômalo.

## Hijacking de link via satélite

A Kaspersky documentou a Turla usando vulnerabilidades em Internet via satélite DVB-S unidirecional mais antiga. No modelo relatado, um assinante remoto legítimo enviava solicitações de saída por um link terrestre, mas recebia dados downstream por meio de uma transmissão via satélite de área ampla e não criptografada. Um ator dentro da área de cobertura do satélite podia observar o downlink, escolher o IP de um assinante ativo e fazer com que as respostas C2 fossem endereçadas a esse IP. Tanto o assinante legítimo quanto o ator recebiam a transmissão; o ator extraía o tráfego destinado à porta selecionada, enquanto o assinante legítimo descartava os pacotes não solicitados. O operador de C2 então aparentava usar um endereço de um provedor de satélite em outra região geográfica.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Isso era específico do protocolo/serviço, limitado pela largura de banda e não equivalente ao comprometimento de um terminal de satélite moderno bidirecional e criptografado. Além disso, não ocultava o caminho da solicitação de saída do ator de um observador suficientemente capaz. As oportunidades de detecção incluem roteamento assimétrico/impossível, tráfego destinado a um assinante que não iniciou o fluxo, portas de destino incomuns, telemetria do provedor, investigação da localização do receptor/RF e da configuração do malware. Use este caso para questionar a suposição de que geolocalizar um IP de C2 geolocaliza seu controlador — não como uma receita de construção.

## Planilha de correlação físico-digital

Quando uma fonte aparentemente local for suspeita, crie uma única linha do tempo:

1. normalize os relógios de AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controle de acesso físico;
2. identifique a primeira associação de rádio ou ativação do link, não apenas o primeiro alerta;
3. associe a estação ao certificado, à postura do dispositivo, à fingerprint de DHCP e à localização do switch/AP;
4. procure atividade simultânea de controle remoto/túnel em sistemas próximos;
5. analise entregas, visitantes, exceções de inventário, câmeras e descobertas de RF conforme a política/lei aplicável;
6. preserve o dispositivo suspeito e o estado volátil da rede; não desligue nem reinicie de forma indiscriminada;
7. determine se a infraestrutura aparentemente de origem é controlada pelo ator ou se pertence a outra vítima.

## References

- [1] [Volexity — O ataque do vizinho mais próximo: como um APT russo weaponized redes Wi-Fi próximas](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Turla via satélite: command and control de APT no céu](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Adições de hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Diretrizes para proteger redes locais sem fio](https://csrc.nist.gov/pubs/sp/800/153/final)
