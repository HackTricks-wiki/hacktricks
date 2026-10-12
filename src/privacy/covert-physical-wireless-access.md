# Acesso físico e sem fio encoberto

{{#include ../banners/hacktricks-training.md}}

Para uma implementação detalhada e aprovada pelo proprietário, que abrange rendezvous de saída, recuperação de energia/uplink, segredos mínimos armazenados no dispositivo, testes de captura e monitoramento para detectar possíveis descobertas, consulte [Nós de campo autorizados resilientes à captura](capture-resilient-authorized-field-nodes.md).

Alterar o caminho da rede também pode alterar a origem física aparente. Um agente sofisticado pode usar um sistema comprometido nas proximidades, um dispositivo oculto, acesso público, backhaul celular ou um receptor de satélite para fazer com que os logs do alvo apontem para longe do operador. Nenhuma dessas opções elimina evidências físicas, de rádio ou do provedor; elas transferem a atribuição para outros conjuntos de dados.

## Matriz de técnicas

| Técnica | Origem aparente | Condição necessária | Evidências de alto valor |
|---|---|---|---|
| Pivô por rede sem fio próxima | uma empresa/residência ao lado do alvo | host comprometido com duas interfaces de rede e acesso ao Wi-Fi do alvo | logs de endpoint do host vizinho, associação RF e RADIUS/DHCP do alvo |
| Rede pública/de visitantes | NAT do estabelecimento ou saída do túnel | acesso legítimo ou bypass do controle de acesso | portal cativo, DHCP, associação ao AP, CFTV e registros de pagamento/localização |
| Dispositivo de acesso encoberto | endereço cabeado, Wi-Fi ou celular do alvo/próximo a ele | instalação física ou entrega | telemetria de porta do switch/USB, RF, inventário, energia e túnel de saída |
| Roteador celular/eSIM | NAT da operadora ou APN dedicado | modem/SIM/assinatura | IMEI/IMSI/eSIM, setor de célula, conta da operadora e horários do tráfego |
| Abuso de link de satélite | endereço do assinante na área de cobertura do feixe | vulnerabilidade específica do protocolo e do serviço | localização RF, fluxo de uplink, RTT/roteamento impossível e registros do provedor |

## Ataque do vizinho mais próximo

A Volexity documentou uma operação de 2022 do APT28/GRU na qual o agente estava distante do alvo final. Ele executou um password spraying no serviço público do alvo para obter credenciais válidas, mas a MFA impediu o login direto pela Internet. O Wi-Fi corporativo do alvo aceitava essas credenciais sem MFA. O agente comprometeu organizações fisicamente próximas ao alvo, encontrou um sistema com duas interfaces de rede que tinha alcance sem fio e usou esse sistema para se autenticar no Wi-Fi do alvo. A Volexity chamou isso de **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

A novidade está na composição. Nenhum operador vai até o alvo, e o MFA do serviço exposto à Internet continua funcionando. O vizinho comprometido fornece a proximidade física; a credencial roubada do alvo fornece o acesso lógico; o Wi-Fi do alvo se torna o caminho para cruzar a fronteira.

### Pré-requisitos e visibilidade

- Um sistema próximo precisa poder ser controlado remotamente e ter um rádio compatível ou acesso a outro pivô próximo.
- O SSID do alvo precisa alcançar esse sistema, e a admissão ao Wi-Fi precisa aceitar uma credencial/certificado reutilizável ou um estado de dispositivo.
- O pivô geralmente precisa de dois caminhos simultâneos: um de volta ao operador e outro para a WLAN do alvo.
- O alvo pode ver um novo endereço MAC de estação e um nome de usuário legítimo, mas nenhum certificado de dispositivo gerenciado correspondente, postura, histórico ou entrada esperada no edifício.
- Os logs de endpoints do vizinho podem mostrar varreduras sem fio, novos perfis, alterações de interface, tunelamento e atividade de controle remoto.

### Detecção e prevenção

1. Exija EAP-TLS com certificado e postura de dispositivo gerenciado para o Wi-Fi corporativo; não considere suficiente uma senha que falhou no MFA pela Internet só porque foi recebida por rádio.
2. Correlacione a autenticação RADIUS com a identidade do MDM/NAC, o vínculo histórico entre estação e dispositivo, a localização do AP, os eventos de acesso físico e as sessões simultâneas.
3. Gere alertas quando uma conta se associar pela primeira vez, a partir de uma borda incomum de AP, sem um certificado gerenciado ou enquanto a mesma identidade estiver ativa em outro lugar.
4. Monitore endpoints capazes de interligar interfaces. No Windows, Linux e appliances de rede, investigue perfis WLAN inesperados, configurações de encaminhamento/NAT, adaptadores virtuais e túneis persistentes.
5. Reduza o vazamento desnecessário de sinal com posicionamento sensato dos APs e planejamento de potência. Este é um controle complementar, não um método de autenticação.
6. Coordene a resposta a incidentes com os inquilinos vizinhos: a fonte de rádio final pode, ela própria, ser uma vítima.

O [laboratório próprio com duas organizações](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduz esses indicadores sem atacar um vizinho.

### Validar um caminho de pivô no Windows

Um host Windows com duas interfaces de rede não interliga suas interfaces automaticamente. Primeiro, faça o inventário dos adaptadores, das rotas e do estado da WLAN; depois, associe-se somente por meio de um perfil aprovado. O argumento `name` de `netsh wlan connect` identifica um perfil instalado, não um SSID e uma senha arbitrários. Compare a tabela de rotas antes e depois da associação para garantir que uma nova rota padrão não interrompa o caminho de controle nem invalide o resultado. Continue com as [verificações pós-associação](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) somente depois de confirmar a interface e a rota pretendidas.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

A divulgação de artefatos do incidente pela Volexity mostra outra distinção útil. O C# incorporado abre a WLAN API, enumera interfaces, lê XML de EAP do disco e chama `WlanSetProfileEapXmlUserData` para um perfil nomeado na primeira interface sem fio. A API define credenciais de usuário EAP em um perfil 802.1X existente, mas o componente divulgado não contém `WlanConnect` nem a lógica de descoberta descrita no relatório. Trate-o como provisionamento de perfil, não como um conector completo, e inspecione o perfil resultante como parte da [avaliação de clientes e supplicants](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md).<sup>[[5]](#references)[[7]](#references)</sup>

## Locais públicos e Wi-Fi de terceiros

Usar o Wi-Fi de um café, hotel, aeroporto ou município altera o IP que um destino vê. Isso não cria anonimato. O local ou seu provedor pode manter registros de associação ao AP, MAC do dispositivo, concessão DHCP, conta do portal cativo, validação por SMS/e-mail e fluxos de tráfego. Registros de entrada física, câmeras de vigilância, compras, localização do celular e viagens podem vincular o evento digital a uma pessoa.

Um agente pode tentar ocultar um identificador usando endereços MAC aleatórios, um dispositivo separado, dinheiro ou um túnel. Ainda é possível correlacionar informações entre camadas por meio do horário de chegada, padrões de visitas repetidas ao local, impressões digitais de rádio, comportamento no portal, horário do tráfego, imagens das câmeras e provedor do túnel. Uma VPN também transfere os registros do destino do local para os registros da VPN; ela não elimina o conhecimento do local de que o dispositivo esteve presente.

Os responsáveis pelo acesso público devem isolar os clientes, bloquear tráfego lateral, usar WPA2/3-Enterprise ou chaves por dispositivo quando viável, manter registros proporcionais de DHCP/RADIUS/segurança, proteger portais cativos e publicar um processo para lidar com abusos. Red teams só devem usar esses locais quando os termos e o escopo do engajamento permitirem; contornar um portal, roubar acesso ou visar outros clientes não é um atalho de teste autorizado.

## Dispositivos drop covertos e warshipping

Um drop é um sistema pequeno colocado ou entregue em um local e, em seguida, controlado por meio de Ethernet, Wi-Fi ou rede celular de saída. O “warshipping” acondiciona o dispositivo para que uma entrega comum o leve para dentro do perímetro de rádio. O hardware pode variar de um computador de placa única a um carregador modificado, periférico USB, equipamento de rede ou modem alimentado por bateria.

Arquitetura operacional:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

O dispositivo pode fornecer um ponto de acesso remoto, realizar medições sem fio, emular um periférico de exercício autorizado ou retransmitir tráfego. Sua origem aparente é local, mas ele cria vestígios físicos: números de série, embalagens, impressões digitais, câmeras, registros de acesso, consumo de energia, descritores USB, negociação de porta de switch, fingerprints de DHCP, comportamento de OUI/randomização de MAC, emissões de RF e conexões recorrentes de rendezvous.

### Controles defensivos

- Mantenha procedimentos para salas de recebimento e inventário de ativos; inspecione eletrônicos inesperados e pacotes endereçados a funcionários inexistentes.
- Use 802.1X/NAC no acesso com e sem fio, desative portas não utilizadas e coloque dispositivos desconhecidos em uma VLAN de remediação restrita.
- Gere alertas para novos fingerprints de DHCP, MACs administrados localmente que persistam, novos dispositivos USB de rede/HID, Wi-Fi Direct/Bluetooth não autorizados e túneis de saída de longa duração.
- Estabeleça uma linha de base para o comportamento de portas de switch, Power over Ethernet, DNS e TLS. Um host minúsculo sem registro no inventário que faz conexões criptografadas periódicas é um sinal mais relevante do que apenas “OUI de Raspberry Pi”.
- Durante um exercício, inventarie, identifique, defina o escopo, criptografe, disponibilize um kill switch remoto, estabeleça um prazo para recuperação e garanta que a perda não possa expor credenciais reutilizáveis.

## Backhaul celular e eSIM

Um modem celular evita o gateway de Internet do alvo e pode manter um dispositivo implantado acessível atrás do NAT da operadora por meio de um rendezvous de saída. Os endereços móveis podem mudar ou ser compartilhados; ainda assim, a operadora celular possui fortes evidências de assinante e de rede: identidade do SIM/eSIM, IMSI, IMEI do dispositivo, endereços/portas atribuídos, horário de célula/setor, conta/pagamento e registros de roaming.

Na perspectiva da empresa, detecte modems inesperados e hotspots pessoais com levantamentos de wireless/RF, inventário USB/PCI dos endpoints, restrições de MDM, monitoramento de SSIDs clandestinos e inspeção física. Um dispositivo implantado que usa celular para controle ainda pode ser detectado pelo comportamento local de Ethernet/Wi-Fi e pelas emissões de rádio.

Em exercícios autorizados, a organização deve ser proprietária da assinatura e do modem, registrar os identificadores com o controlador e validar se os termos da operadora/provedor permitem o tráfego. Uma etiqueta pré-paga ou uma compra com criptomoeda não apaga registros de torres, dispositivos ou pontos de venda.

## Randomização de MAC e fingerprinting de dispositivos

Sistemas modernos podem usar um MAC aleatório administrado localmente para cada rede. Isso reduz o rastreamento passivo de longo prazo por um MAC de fábrica estável; não oculta:

- o horário de sondagem/associação e o conjunto de recursos de rede solicitados;
- elementos de informação 802.11, taxas compatíveis e comportamento específico do fornecedor;
- opções/hostname de DHCP, identificadores IPv6 e fingerprint do navegador/portal cativo;
- identidade ou certificado autenticado de 802.1X;
- conta de camada superior, túnel e padrão de tráfego; ou
- observação física.

Os defensores não devem usar listas de permissão de MAC como autenticação. Correlacione a identidade de rádio com o certificado/postura do dispositivo e trate MACs em mudança como normais, a menos que outro contexto seja anômalo.

## Sequestro de link via satélite

A Kaspersky documentou o uso, por Turla, de vulnerabilidades em serviços mais antigos de Internet via satélite DVB-S unidirecional. No modelo relatado, um assinante remoto legítimo enviava solicitações de saída por um link terrestre, mas recebia dados downstream por uma transmissão via satélite não criptografada de ampla cobertura. Um agente dentro da área de cobertura do satélite podia observar o downlink, escolher o IP de um assinante ativo e fazer com que as respostas de C2 fossem endereçadas a esse IP. Tanto o assinante legítimo quanto o agente recebiam a transmissão; o agente extraía o tráfego da porta selecionada, enquanto o assinante legítimo descartava pacotes não solicitados. O operador de C2 então parecia usar um endereço de provedor de satélite em outra região geográfica.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Isso era específico de protocolo/serviço, limitado pela largura de banda e não equivalia a comprometer um terminal de satélite bidirecional criptografado moderno. Também não ocultava o caminho da solicitação de saída do agente de um observador suficientemente capaz. As oportunidades de detecção incluem roteamento assimétrico/impossível, tráfego para um assinante que não iniciou o fluxo, portas de destino incomuns, telemetria do provedor, investigação da localização do receptor/RF e configuração do malware. Use este caso para questionar a suposição de que geolocalizar um IP de C2 geolocaliza seu controlador — não como uma receita de construção.

## Planilha de correlação físico-digital

Quando uma fonte aparentemente local for suspeita, monte uma linha do tempo:

1. normalize os relógios de AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch e controle de acesso físico;
2. identifique a primeira associação de rádio ou conexão, não apenas o primeiro alerta;
3. mapeie a estação ao certificado, à postura do dispositivo, à impressão digital DHCP e à localização do switch/AP;
4. procure atividade simultânea de controle remoto/túnel em sistemas próximos;
5. analise entregas, visitantes, exceções de inventário, câmeras e descobertas de RF de acordo com a política/lei aplicável;
6. preserve o dispositivo suspeito e o estado volátil da rede; não reinicie às cegas;
7. determine se a fonte aparente é uma infraestrutura controlada pelo agente ou outra vítima.

## References

- [1] [Volexity — O ataque do vizinho mais próximo: como um APT russo transformou redes Wi-Fi próximas em arma para obter acesso furtivo](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: comando e controle de APT no céu](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Adições de hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Diretrizes para proteger redes locais sem fio](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Código PowerShell/C# de perfil WLAN com redações](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — função WlanSetProfileEapXmlUserData](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}
