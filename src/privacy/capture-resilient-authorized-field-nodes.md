# Nós de campo autorizados resilientes à captura

Um Raspberry Pi, mini-PC, travel router ou appliance celular instalado no local pode fornecer a uma red team autorizada um ponto de observação duradouro. Ele também é um provável ponto de descoberta, roubo e atribuição. Portanto, o objetivo correto de design é **acesso estável e controlado com pouca autoridade no nó de campo**, não um implante impossível de rastrear.

Este guia se aplica somente a equipamentos instalados com autorização por escrito do proprietário do local. Uma cafeteria, vizinho, hotel ou edifício compartilhado não está no escopo apenas porque sua rede pode ser acessada. Não esconda hardware em um local cujo consentimento não foi obtido, não contorne um captive portal, não use as credenciais de outra pessoa, não interfira no monitoramento nem tente apagar evidências após a descoberta.

{% hint style="warning" %}
Não existe uma configuração confiável de “não deixar rastros”. Registros de associação de rádio, DHCP/NAT, operadora, câmeras, compra, dispositivo, provedor, controlador e destino podem permanecer após a remoção do dispositivo. Uma red team responsável, em vez disso, remove **segredos pessoais e não relacionados** do nó, mantém a atribuição protegida no controlador e torna a captura fácil de conter.
{% endhint %}

## Prós e contras

**Prós:** fonte interna ou adjacente ao alvo mais realista; testes estáveis e de alta velocidade; valida NAC, egress, inventário físico e cobertura do SOC; pode continuar funcionando mesmo com alterações no endereço do operador; o acesso limitado pode ser revogado centralmente.

**Contras:** a instalação física cria evidências fortes; a perda pode expor credenciais do dispositivo, perfis de rede e dados coletados; o tráfego de controle repetido é detectável; energia, portais e alterações de rádio prejudicam a confiabilidade; um túnel amplo pode se tornar um pivot não controlado.

## Modelo de ameaça e invariantes de design

Presuma que quem encontrar o dispositivo possa remover o armazenamento, inspecionar o firmware, copiar todos os segredos armazenados pelo software, observar o comportamento posterior da rede e entregar o dispositivo ao cliente ou às autoridades policiais. A criptografia de disco completo protege um dispositivo desligado somente dentro do modelo de ameaça especificado; um nó em execução e desbloqueado e chaves liberadas para a memória são casos diferentes.

| Invariante | Consequência prática |
|---|---|
| Nenhuma identidade direta do operador para o nó | O operador faz login no gateway da organização; o nó possui uma identidade de dispositivo diferente |
| Nenhum material da estação de trabalho pessoal | Nenhuma chave SSH pessoal, perfil de navegador, e-mail, gerenciador de senhas, pareamento com telefone ou cache de CLI de cloud |
| Nenhum segredo mestre do controlador | Um nó não pode registrar outro, alterar políticas ou descriptografar outros engagements |
| Somente saída e de forma limitada | A rede de campo não aceita nenhum listener de gerenciamento; o nó acessa somente serviços de rendezvous, atualização e tempo nomeados |
| Autoridade limitada e de curta duração | Cada credencial possui um dispositivo, público, serviço, expiração e caminho de revogação imediata |
| Dados locais mínimos | Os resultados são enviados ao controlador; os caches são criptografados, têm tamanho/TTL limitados e não são autoritativos |
| A responsabilidade do controlador sobrevive à captura | O mapeamento entre ativo e engagement, as aprovações, o acesso dos operadores e os comandos são armazenados centralmente e têm acesso controlado |
| A perda interrompe o trabalho | Descoberta ou alteração de estado inexplicada aciona parada, revogação, notificação e preservação de evidências — não destruição remota |

O baseline de IoT do NIST agrupa identificação do dispositivo, configuração, proteção de dados, acesso lógico, atualização segura de software e consciência do estado de cybersecurity como recursos essenciais. Ele trata especificamente a consciência do estado e os registros de eventos fora do dispositivo como suporte à investigação de comprometimento.<sup>[[1]](#references)</sup>

## Arquitetura de referência
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
O gateway deve saber qual operador identificado alcançou qual dispositivo identificado. O field node precisa apenas de uma credencial de dispositivo para o rendezvous. Ele nunca aprende o endereço de origem ou o segredo de autenticação do operador, e o operador nunca copia uma management key privada para ele. Isso reduz o vínculo pessoal recuperável **a partir do armazenamento do field node** sem destruir a accountability do exercício.

Para uma frota maior, um sistema de workload identity pode emitir identidades X.509 de curta duração e fazer a rotação automática de chaves. O SPIFFE recomenda X.509 SVIDs quando possível e descreve lifetimes curtos e rotação frequente como formas de limitar a exposição ao comprometimento de chaves.<sup>[[2]](#references)</sup> Uma equipe pequena pode aplicar as mesmas propriedades com uma CA privada e certificados automatizados por dispositivo; instalar o SPIRE não é necessário apenas para cumprir o padrão.

## Step 1: autorizar e registrar a instalação

1. Registre o proprietário, o local, a zona exata de instalação permitida, as redes permitidas, a janela da avaliação, os destinos/ações permitidos e os contatos de emergência.
2. Registre o modelo, o número de série, o número de série do armazenamento, os MACs com e sem fio, o IMEI/eSIM ou ICCID do SIM, a fonte de alimentação e uma fotografia atual.
3. Dê ao dispositivo um identificador de engagement não pessoal, por exemplo `E2026-014-DROP03`. Não inclua o nome do cliente em hostnames ou SSIDs de broadcast.
4. Informe ao controller do exercício e ao menor grupo necessário de segurança física/SOC para deconfliction o que “perdido”, “movido” e “descoberto” significam para este teste.
5. Combine previamente quem poderá recuperá-lo e como um finder poderá reportá-lo. Uma etiqueta de segurança pode omitir detalhes sensíveis do cliente e ainda fornecer um callback controlado.
6. Defina uma expiração automática da autorização. A conectividade que continuar após o fim do escopo não deve estender a permissão.

## Step 2: criar uma imagem mínima recuperável

Use uma imagem de OS compatível, verifique sua assinatura/checksum pelo canal documentado pelo vendor, instale security updates e mantenha um build manifest reproduzível. Prefira uma base read-only ou immutable com uma pequena partição de dados gravável, quando o software permitir.

1. Remova contas padrão, demo services, compiladores e pacotes que não sejam necessários para o workload autorizado.
2. Desabilite a GUI local, Bluetooth, protocolos de discovery, file sharing, Wi-Fi P2P e administração inbound, salvo se o exercício exigir explicitamente algum deles.
3. Habilite secure boot e measured boot/liberação de chaves baseada em TPM se o hardware realmente oferecer suporte; não afirme que uma configuração de Raspberry Pi possui measured boot de nível PC sem validar o modelo exato.
4. Criptografe o estado local gravável e configure um tamanho máximo e um tempo de retenção rigorosos. A criptografia é um controle de atraso/containment, não uma prova de que um node em execução não revela nada.
5. Envie os logs importantes para fora do dispositivo. Limite os journals locais para evitar o esgotamento do armazenamento, mas não configure limpeza de logs ou exclusão anti-forensics.
6. Armazene o image manifest, as versões dos pacotes, o hash da configuração e as instruções de recuperação no controller.
7. Reimage um spare a partir do manifest e execute o mesmo health test. Um design que somente seu criador consegue recuperar não está pronto para campo.

## Step 3: emitir identidades com confiança unidirecional

Crie três identidades diferentes:

- uma **identidade de dispositivo**, aceita apenas pelo rendezvous desse dispositivo;
- uma **identidade de operador**, aceita pelo gateway da organização e protegida com MFA resistente a phishing; e
- uma **identidade de controller/deployment**, usada para assinar jobs ou configurações aprovados, mantida fora do operador e do field node.

O node deve possuir a public key necessária para verificar jobs assinados, nunca a signing key. Uma credencial de dispositivo capturada não deve autenticar em cloud consoles, source repositories, payment accounts, outros nodes ou na produção do cliente.

Use certificate lifetimes curtos quando a renovação automática for confiável. Quando uma chave WireGuard de longa duração for operacionalmente necessária, trate sua public key como o revocation handle e restrinja-a com um tunnel address específico do peer, uma firewall policy e uma autorização do broker. Mantenha uma ação do controller testada que remova imediatamente esse peer.

## Step 4: rendezvous outbound estável

O padrão de owned-lab a seguir fornece gerenciamento estável através de NAT sem expor um serviço inbound. É uma rede WireGuard comum, não um reverse shell oculto. Use documentation addresses e substitua-os apenas por endpoints pertencentes à organização.

No rendezvous da organização, atribua `10.77.0.1/32`; atribua `10.77.0.20/32` ao field node. A entrada do peer no gateway deve aceitar apenas o endereço único do node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
O node aponta para fora em direção ao rendezvous e mantém o mapeamento NAT somente quando necessário:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
O WireGuard documenta 25 segundos como um intervalo de keepalive adequado em muitas implementações de NAT/firewall quando a persistência é necessária; deixá-lo desabilitado é preferível quando não é necessário.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` deliberadamente torna este um caminho de gerenciamento, não um pivot de rota padrão.

Em seguida, aplique controles fora do WireGuard:

1. Resolva `vpn.redteam.example` por meio do caminho de DNS de bootstrap aprovado e fixe o endpoint esperado da organização nos registros de deployment.
2. No node, permita DHCP/RA de saída, DNS/NTP necessários, o endpoint de rendezvous e o caminho mínimo de update aprovado. Negue tráfego de entrada não solicitado em cada uplink.
3. No rendezvous, permita que `10.77.0.20` alcance apenas o serviço de broker/health necessário para o exercício. Não o encaminhe genericamente para uma client network.
4. Coloque o acesso interativo de operator atrás do gateway da organização. Evite expor SSH do node através do túnel se uma interface de signed pull-job atender à assessment.
5. Configure o service manager para iniciar o túnel após a rede, reiniciá-lo após falhas com backoff limitado e alertar após falhas repetidas. Um loop de reinicialização não deve sobrecarregar o local nem ocultar a falha subjacente.
6. Verifique o latest handshake do peer, mas não use “handshake existe” como prova de que o device não foi comprometido.

TURN pode fornecer reachability somente por relay para um control plane WebRTC desenvolvido especificamente para esse fim, e uma message queue pode tolerar serviço intermitente. TURN fornece explicitamente a um client um endereço público de relay atrás de NAT; o servidor continua sendo um observer.<sup>[[4]](#references)</sup> Escolha uma arquitetura de controle em vez de empilhar túneis sem um observer ou benefício de confiabilidade declarado.

## Step 5: estabilidade do uplink sem links pessoais

Para um node de venue autorizado, prefira esta ordem:

1. VLAN cabeada ou de teste dedicada fornecida pelo client;
2. perfil de enterprise/guest Wi-Fi aprovado pelo owner;
3. fallback de cellular/private APN contratado pela organização.

Nunca o configure com um personal phone hotspot, SSID doméstico, eSIM pessoal, conta pessoal da Apple/Google ou perfil Wi-Fi exportado de um laptop de uso diário. Esses são exatamente os artifacts aos quais uma captura se conectará.

Para cada uplink aprovado:

- registre SSID/BSSID ou switch/VLAN e o comportamento esperado do captive portal;
- defina prioridade determinística e uma health check para um endpoint pertencente à organização;
- faça com que o failover altere apenas o underlay; as identidades do device e do operator permanecem no broker;
- garanta que DNS, IPv6 e o tráfego de application não contornem o rendezvous durante a transição;
- alerte sobre SSID/BSSID desconhecido, alteração de SIM, novo default gateway, alteração de public-IP/ASN ou uplinks simultâneos;
- teste perda de energia, renovação de DHCP, reinicialização do AP, alteração de public-IP, 24 horas de inatividade, perda do túnel e recuperação de primary para secondary e novamente para primary antes do deployment.

O private MAC addressing pode reduzir o tracking casual entre networks, mas um MAC estável por network muitas vezes é necessário para o NAC autorizado. Registre o que o OS escolhido realmente faz e não alterne em torno do controle de acesso do owner.

## Step 6: restrinja trabalho e dados

Um field node seguro não deve aceitar texto arbitrário de shell vindo de uma mailbox. Defina tipos de job assinados, como `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ou outra ação explicitamente nomeada nas rules of engagement. Valide novamente destination, duration, rate, output size e scope no node.

1. Dê a cada job um ID exclusivo, device audience, issue time, expiry, scope reference e output máximo.
2. Assine-o com a identidade de controller/deployment.
3. Rejeite campos desconhecidos, jobs expirados/reproduzidos e jobs destinados a outro device.
4. Envie os resultados em streaming para um collector pertencente à organização; criptografe e aplique TTL a qualquer spool local inevitável.
5. Registre o job ID aceito/rejeitado e o result hash no controller. Não coloque parâmetros de comandos sensíveis em um canal público de monitoring.
6. Interrompa o processamento quando a autorização expirar, a identity rotation falhar ou o controller marcar o device como quarantined.

## Monitoring para descoberta, perda ou comprometimento

O monitoring pode informar ao controller que o estado observado mudou. Ele não pode provar com confiabilidade que “investigators encontraram o device”, e tentar surveil responders ou sondar os sistemas deles excederia uma assessment autorizada.

### Colete o estado off-device

Envie um health record assinado e de baixo volume ao controller em um intervalo operacional aleatório, porém limitado. Inclua apenas o que o controller precisa:

- device ID, boot ID/counter e uptime monotônico;
- hash da configuração/imagem e software version;
- serial do device-certificate e estado de renewal;
- classe de uplink, interface, BSSID ou contexto de switch conforme autorizado, hash do default-gateway e public IP/ASN conforme observado por um serviço pertencente à organização;
- idade do tunnel handshake, packet counters e queue depth;
- estado do enclosure switch ou do hardware-tamper, caso o owner tenha aprovado o sensor;
- pressão do disco, temperatura, estimativa de clock-offset e último job ID bem-sucedido;
- um sequence number e uma assinatura para revelar replay ou lacunas.

Armazene centralmente a autenticação do gateway, policy decisions, acesso de operator, submissão de jobs, result hashes, eventos de auditoria do provider e alertas. A CISA recomenda centralizar logs, protegê-los contra exclusão, estabelecer uma baseline da atividade normal e designar contatos de incident-response.<sup>[[5]](#references)</sup>

### Indicadores de descoberta/comprometimento

| Signal | Possíveis explicações | Ação do controller |
|---|---|---|
| Heartbeat ausente | falha de energia/rede, alteração do portal, dano, bloqueio deliberado ou remoção | corrobore o estado do provider/site; não reconecte por um caminho não aprovado |
| Boot counter alterado inesperadamente | corte de energia, crash, remoção ou manutenção | coloque os jobs em quarantine; compare o horário e os eventos do site |
| Hash da config/image alterado | erro de update, falha de armazenamento ou tampering | interrompa o trabalho; revogue se não for um release aprovado pelo controller |
| Novo uplink/BSSID/gateway/ASN | substituição do AP, roaming, device movido ou interception | compare o inventário aprovado; coloque em quarantine uma transição sem explicação |
| Job/signature rejeitado repetidamente | corrupção, replay ou controller não autorizado | interrompa o processamento e investigue os logs do gateway/controller |
| Device credential usada duas vezes ou em caminhos incompatíveis | chave clonada, reutilização de snapshot ou transição de network | revogue imediatamente; preserve ambos os session records |
| Login, interface, processo ou evento de privilégio local inesperado | manutenção ou comprometimento | isole por meio da broker policy; preserve as evidências |
| Transição de enclosure switch/state | serviço, movimentação ou descoberta | notifique o site contact nomeado; não acione ação destrutiva |
| Aviso de abuso do provider/query da conta ou alerta do SOC | detecção, configuração incorreta ou tráfego fora do escopo | interrompa a atividade e acione o processo de deconfliction/incident |
| Sentinel credential acessada | alguém leu um secret decoy sem privilégios, exclusivo deste node | revogue a identidade real do device e preserve o alert trail |

Uma sentinel credential deve conceder **nenhum acesso**, chamar apenas um serviço de alert pertencente à organização e ser divulgada nas rules of engagement. Ela é um tripwire para leitura não autorizada, não um beacon para rastrear quem encontrou o equipamento.

### Limiares de alerta

Use regras stateful, não um único alerta dramático de “capturado”:

- **warning:** um intervalo perdido, alteração normal de endereço ou crescimento da fila;
- **degraded:** três perdas consecutivas, atraso de renewal, perda do primary-uplink ou restart repetido;
- **quarantine:** alteração não aprovada de hash/boot/uplink, credential duplicada, uso do sentinel ou evento privilegiado inesperado;
- **confirmed discovery/loss:** relatório do site/controller, divergência no inventário físico, recuperação do device por uma parte não planejada ou escalada validada do provider/SOC.

Teste a entrega de alertas por um canal independente do field node. Evite enviar detalhes sensíveis de client/device para mensagens pessoais ou contas de consumer push.

## Runbook para suspeita de descoberta ou captura

1. **Pare:** suspenda novos jobs e sessões de operator. Não envie uma probe para “verificar se está sendo observado”.
2. **Coloque em quarantine:** faça o broker negar a identidade do device e suas routes, mantendo os logs existentes.
3. **Revogue:** revogue o certificado/key do device, queue token, update credential e qualquer service token de finalidade única. Suspenda o SIM da organização quando a perda física for plausível.
4. **Preserve:** faça snapshot dos registros do controller, gateway, provider e alertas; registre o trusted time, quem agiu e a última configuração conhecida. Não limpe nem faça wipe remoto do node.
5. **Notifique:** entre em contato com o exercise controller, o client incident contact e os contatos legal/privacy definidos na autorização. Se um terceiro o encontrou, use o processo de recuperação previamente acordado.
6. **Avalie:** presuma que todo secret e resultado em cache no node foi exposto. Enumere exatamente o que cada secret poderia acessar e se foi usado após o evento suspeito.
7. **Contenha downstream:** faça rotation das service credentials afetadas, invalide jobs pendentes e inspecione os logs dos targets/providers pertencentes à organização em busca de comportamento inesperado.
8. **Recupere com segurança:** faça a recuperação apenas por meio de uma pessoa autorizada; fotografe/embale o equipamento, registre a custody e adquira evidências forenses conforme orientação do client.
9. **Retome com uma nova identidade:** nunca reative silenciosamente a credential capturada. Recompile a partir do manifest conhecido, corrija a falha de controle e obtenha aprovação explícita.

A orientação atual de incident-response do NIST integra preparação, detecção, resposta e recuperação ao gerenciamento de riscos de cybersecurity em toda a organização; preserve primeiro para que o client possa determinar o que aconteceu e escolher a resposta apropriada.<sup>[[6]](#references)</sup>

## Capture drill antes do deployment

Entregue uma unidade de teste desbloqueada ou uma cópia de seu storage a um reviewer separado e peça que ele enumere:

1. identificadores de device/site/engagement;
2. nomes de operator, contas pessoais, networks de casa/workstation e recovery contacts;
3. destinations e credentials do controller/broker;
4. profiles de client network e cached results;
5. outros devices/projects acessíveis com cada secret;
6. credentials de valor ou pagamento;
7. o que o controller pode revogar e com que rapidez;
8. qual atividade continua atribuível a partir dos logs centrais.

Critérios de aprovação: zero contas pessoais/keys de workstation; zero autoridade de cross-engagement ou enrollment; nenhuma credential de pagamento; cache criptografado e limitado; uma ação documentada de device-revocation; accountability completa no controller. Trate qualquer link pessoal inesperado ou capacidade lateral como um bloqueio de release.

## Encerramento

1. Interrompa os jobs e desabilite a broker route ao final do escopo.
2. Recupere e reconcilie o inventário exato; informe qualquer item ausente.
3. Preserve logs/results e, se necessário, uma forensic image de acordo com o plano de retenção do engagement.
4. Revogue as identidades de device, SIM, queue, update e service mesmo quando o hardware tiver sido recuperado.
5. Somente após a preservação/aceitação, sanitize ou destrua a mídia usando o processo aprovado de descarte de dados do owner e registre a conclusão. Isso é gerenciamento do ciclo de vida, não concealment.
6. Remova as reservas de NAC/DHCP do venue, broker routes, DNS, cloud roles, alert rules e contatos temporários.
7. Documente a detecção observada, a telemetria ausente, o tempo até a quarantine e cada artifact que a captura expôs.

## References

- [1] [NIST — Catálogo de Recursos de Cybersecurity para Dispositivos IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Conceitos e workload identities de curta duração](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Recomendações e Considerações de Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
