# Nós de Campo Autorizados e Resilientes à Captura

{{#include ../banners/hacktricks-training.md}}

Um Raspberry Pi, mini-PC, travel router ou appliance celular instalado no local pode oferecer a uma equipe de red team autorizada um ponto de observação duradouro. Ele também é um provável ponto de descoberta, furto e atribuição. Portanto, o objetivo correto do design é **acesso estável e controlado, com pouca autoridade no nó de campo**, e não um implante impossível de rastrear.

Este guia se aplica somente a equipamentos instalados com autorização por escrito do proprietário do local. Uma cafeteria, vizinho, hotel ou prédio compartilhado não está no escopo apenas porque sua rede pode ser acessada. Não esconda hardware em um local cujo responsável não tenha consentido, contorne um captive portal, use as credenciais de outra pessoa, interfira no monitoramento ou tente apagar evidências após a descoberta.

{% hint style="warning" %}
Não existe uma configuração confiável de “não deixar rastros”. Registros de associação de rádio, DHCP/NAT, operadora, câmeras, compra, dispositivo, provedor, controller e destino podem sobreviver ao dispositivo. Uma equipe de red team responsável, em vez disso, remove **segredos pessoais e não relacionados** do nó, mantém a atribuição protegida no controller e torna a captura fácil de conter.
{% endhint %}

## Prós e contras

**Prós:** origem interna ou adjacente ao alvo mais realista; testes estáveis e de alta velocidade; valida NAC, egress, inventário físico e cobertura do SOC; pode continuar funcionando mesmo com mudanças no endereço do operador; o acesso limitado pode ser revogado centralmente.

**Contras:** a instalação física gera evidências fortes; a perda pode expor credenciais do dispositivo, perfis de rede e dados coletados; tráfego de controle repetido é detectável; mudanças de energia, portais e rádio prejudicam a confiabilidade; um túnel amplo pode se tornar um pivot não controlado.

## Modelo de ameaça e invariantes de design

Presuma que quem encontrar o dispositivo possa remover o armazenamento, inspecionar o firmware, copiar todos os segredos mantidos pelo software, observar o comportamento de rede posterior e entregar o dispositivo ao cliente ou às autoridades policiais. A criptografia de disco completo protege um dispositivo desligado somente dentro do seu modelo de ameaça declarado; um nó em execução e desbloqueado e as chaves liberadas para a memória são casos diferentes.

| Invariante | Consequência prática |
|---|---|
| Nenhuma identidade direta entre operador e nó | O operador faz login no gateway da organização; o nó possui uma identidade de dispositivo diferente |
| Nenhum material da workstation pessoal | Nenhuma chave SSH pessoal, perfil de navegador, e-mail, gerenciador de senhas, pareamento com telefone ou cache de CLI de cloud |
| Nenhum segredo mestre do controller | Um nó não pode cadastrar outro, alterar políticas ou descriptografar outros engagements |
| Somente saída e de forma restrita | A rede de campo não aceita nenhum listener de gerenciamento; o nó acessa somente services nomeados de rendezvous, update e time |
| Autoridade de curta duração e escopo limitado | Cada credencial tem um dispositivo, audience, service, expiry e caminho de revogação imediata |
| Dados locais mínimos | Os resultados são transmitidos ao controller; os caches são criptografados, têm tamanho/TTL limitado e não são autoritativos |
| A responsabilidade do controller sobrevive à captura | O mapeamento entre ativo e engagement, as aprovações, o acesso dos operadores e os comandos são armazenados centralmente e têm acesso controlado |
| A perda interrompe o trabalho | A descoberta ou uma alteração de estado inexplicada aciona interrupção, revogação, notificação e preservação de evidências — não destruição remota |

O baseline de IoT do NIST agrupa identificação do dispositivo, configuração, proteção de dados, acesso lógico, atualização segura de software e consciência do estado de cybersecurity como capacidades essenciais. Ele trata especificamente a consciência do estado e os registros de eventos fora do dispositivo como suporte à investigação de comprometimentos.<sup>[[1]](#references)</sup>

## Reference architecture
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
O gateway deve saber qual operador identificado alcançou qual dispositivo identificado. O field node precisa apenas de uma credencial de dispositivo para o rendezvous. Ele nunca descobre o endereço de origem ou o segredo de autenticação do operador, e o operador nunca copia uma chave privada de gerenciamento para ele. Isso reduz o vínculo pessoal recuperável **a partir do armazenamento de campo** sem destruir a accountability do exercício.

Para uma frota maior, um sistema de workload identity pode emitir identidades X.509 de curta duração e fazer a rotação automática de chaves. O SPIFFE recomenda X.509 SVIDs quando possível e descreve vidas úteis curtas e rotação frequente como formas de limitar a exposição ao comprometimento de chaves.<sup>[[2]](#references)</sup> Uma equipe pequena pode aplicar as mesmas propriedades com uma CA privada e certificados automatizados por dispositivo; instalar o SPIRE não é necessário apenas para cumprir o padrão.

## Step 1: autorizar e registrar a instalação

1. Registre o proprietário, o local, a zona exata de instalação permitida, as redes permitidas, a janela da avaliação, os destinos/ações permitidos e os contatos de emergência.
2. Registre o modelo, o número de série, o número de série do armazenamento, os MACs com e sem fio, o IMEI/eSIM ou ICCID do SIM, a fonte de alimentação e uma fotografia atual.
3. Dê ao dispositivo um identificador de engagement não pessoal, por exemplo `E2026-014-DROP03`. Não codifique o nome de um cliente em hostnames de broadcast ou SSIDs.
4. Informe ao controlador do exercício e ao menor grupo necessário de segurança física/SOC para deconfliction o que significam “perdido”, “movido” e “descoberto” para este teste.
5. Combine previamente quem pode recuperá-lo e como um localizador pode comunicá-lo. Uma etiqueta de segurança pode omitir detalhes sensíveis do cliente e ainda fornecer um callback controlado.
6. Defina uma expiração automática da autorização. A conectividade que continuar após o fim do escopo não deve estender a permissão.

## Step 2: criar uma imagem mínima recuperável

Use uma imagem de OS compatível, verifique sua assinatura/checksum pelo canal documentado pelo fornecedor, instale as atualizações de segurança e mantenha um manifesto de build reproduzível. Prefira uma base somente leitura ou imutável com uma pequena partição de dados gravável quando o software permitir.

1. Remova contas padrão, serviços de demonstração, compiladores e pacotes não necessários para o workload autorizado.
2. Desative a GUI local, Bluetooth, protocolos de descoberta, compartilhamento de arquivos, Wi-Fi P2P e administração de entrada, salvo quando o exercício exigir explicitamente um deles.
3. Ative secure boot e measured boot/liberação de chaves respaldada por TPM se o hardware realmente oferecer suporte; não afirme que uma configuração de Raspberry Pi possui measured boot de classe PC sem validar o modelo exato.
4. Criptografe o estado local gravável e configure um tamanho máximo e um tempo de retenção rigorosos. A criptografia é um controle de atraso/containment, não uma prova de que um node em execução não revela nada.
5. Envie logs importantes para fora do dispositivo. Limite os journals locais para evitar o esgotamento do armazenamento, mas não configure limpeza de logs ou exclusão anti-forensics.
6. Armazene o manifesto da imagem, as versões dos pacotes, o hash da configuração e as instruções de recuperação no controlador.
7. Reimage um spare a partir do manifesto e execute o mesmo health test. Um design que somente seu criador consegue recuperar não está pronto para campo.

## Step 3: emitir identidades com confiança unidirecional

Crie três identidades diferentes:

- uma **identidade de dispositivo**, aceita somente pelo rendezvous desse dispositivo;
- uma **identidade de operador**, aceita pelo gateway da organização e protegida com MFA resistente a phishing; e
- uma **identidade de controlador/deployment**, usada para assinar jobs ou configurações aprovados, mantida fora do operador e do field node.

O node deve possuir a chave pública necessária para verificar jobs assinados, nunca a chave de assinatura. Uma credencial de dispositivo capturada não deve autenticar em cloud consoles, source repositories, contas de pagamento, outros nodes ou produção do cliente.

Use vidas úteis curtas de certificados quando a renovação automática for confiável. Quando uma chave WireGuard de longa duração for operacionalmente necessária, trate sua chave pública como o identificador de revogação e restrinja-a com endereço de túnel específico do peer, política de firewall e autorização do broker. Mantenha uma ação testada do controlador que remova esse peer imediatamente.

## Step 4: rendezvous outbound estável

O padrão de laboratório controlado a seguir fornece gerenciamento estável por NAT sem expor um serviço de entrada. É uma rede WireGuard comum, não um reverse shell covert. Use endereços de documentação e substitua-os somente por endpoints pertencentes à organização.

No rendezvous da organização, atribua `10.77.0.1/32`; atribua ao field node `10.77.0.20/32`. A entrada do peer do gateway deve aceitar somente o endereço único do node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
O node aponta para o rendezvous de saída e mantém o mapeamento NAT apenas quando necessário:
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
A documentação do WireGuard indica 25 segundos como um intervalo de keepalive adequado em muitas implementações de NAT/firewall quando a persistência é necessária; mantê-lo desativado é preferível quando não é necessário.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` deliberadamente transforma isso em um caminho de gerenciamento, não em um pivot de rota padrão.

Depois, aplique controles fora do WireGuard:

1. Resolva `vpn.redteam.example` por meio do caminho aprovado de DNS de bootstrap e fixe o endpoint esperado da organização nos registros de deployment.
2. No node, permita DHCP/RA de saída, DNS/NTP necessários, o endpoint de rendezvous e o caminho mínimo de update aprovado. Negue tráfego de entrada não solicitado em cada uplink.
3. No rendezvous, permita que `10.77.0.20` alcance apenas o serviço de broker/health necessário para o exercício. Não o encaminhe de forma geral para uma rede de cliente.
4. Coloque o acesso interativo dos operadores atrás do gateway da organização. Evite expor SSH do node pelo tunnel se uma interface de signed pull-job atender à avaliação.
5. Configure o service manager para iniciar o tunnel após a rede, reiniciá-lo após falhas com backoff limitado e emitir um alerta após falhas repetidas. Um loop de reinicialização não deve sobrecarregar o local nem ocultar a falha subjacente.
6. Verifique o latest handshake do peer, mas não use “handshake existe” como prova de que o dispositivo não foi comprometido.

O TURN pode fornecer reachability apenas por relay para um control plane WebRTC desenvolvido especificamente para esse fim, e uma message queue pode tolerar serviço intermitente. O TURN fornece explicitamente a um cliente um endereço público de relay atrás de NAT; o servidor permanece como observador.<sup>[[4]](#references)</sup> Escolha uma arquitetura de controle em vez de empilhar tunnels sem um observador ou benefício de confiabilidade declarado.

## Etapa 5: estabilidade do uplink sem links pessoais

Para um node autorizado no local, prefira esta ordem:

1. VLAN cabeada ou de teste dedicada fornecida pelo cliente;
2. perfil de enterprise/guest Wi-Fi aprovado pelo proprietário;
3. fallback de cellular/private APN contratado pela organização.

Nunca o configure com um hotspot de telefone pessoal, SSID doméstico, eSIM pessoal, conta pessoal da Apple/Google ou perfil Wi-Fi exportado de um laptop usado diariamente. Esses são exatamente os artifacts aos quais uma capture se conectará.

Para cada uplink aprovado:

- registre SSID/BSSID ou switch/VLAN e o comportamento esperado do captive portal;
- defina prioridade determinística e um health check para um endpoint controlado;
- faça com que o failover altere apenas o underlay; as identidades do dispositivo e do operador permanecem no broker;
- garanta que DNS, IPv6 e o tráfego da aplicação não contornem o rendezvous durante a transição;
- emita alertas sobre SSID/BSSID desconhecido, alteração de SIM, novo default gateway, alteração de public-IP/ASN ou uplinks simultâneos;
- teste perda de energia, renovação de DHCP, reinicialização do AP, alteração de public-IP, 24 horas de inatividade, perda do tunnel e recuperação de primary para secondary e novamente para primary antes do deployment.

O endereçamento de MAC privado pode reduzir o rastreamento casual entre redes, mas frequentemente é necessário um MAC estável por rede para o NAC autorizado. Registre o que o OS escolhido realmente faz e não faça rotação em torno do controle de acesso do proprietário.

## Etapa 6: limitar trabalho e dados

Um field node seguro não deve aceitar texto arbitrário de shell a partir de uma mailbox. Defina tipos de job assinados, como `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` ou outra ação explicitamente nomeada nas regras de engagement. Valide novamente destination, duration, rate, output size e scope no node.

1. Dê a cada job um ID exclusivo, audience do dispositivo, horário de emissão, expiração, referência de scope e output máximo.
2. Assine-o com a identidade do controller/deployment.
3. Rejeite campos desconhecidos, jobs expirados/reexecutados e jobs destinados a outro dispositivo.
4. Transmita os resultados para um collector controlado; criptografe e aplique TTL a qualquer spool local inevitável.
5. Registre o ID do job aceito/rejeitado e o hash do resultado no controller. Não coloque parâmetros de comandos sensíveis em um canal público de monitoring.
6. Interrompa o processamento quando a autorização expirar, a rotação de identidade falhar ou o controller colocar o dispositivo em quarantine.

## Monitoring para discovery, loss ou compromise

O monitoring pode informar ao controller que o estado observado mudou. Ele não pode provar de forma confiável que “investigators encontraram o dispositivo”, e tentar vigiar responders ou sondar seus sistemas excederia uma avaliação autorizada.

### Coletar estado off-device

Envie um registro de health assinado e de baixo volume ao controller em um intervalo operacional aleatório, mas limitado. Inclua apenas o que o controller necessita:

- ID do dispositivo, boot ID/counter e uptime monotônico;
- hash da configuração/imagem e versão do software;
- serial do device-certificate e estado de renovação;
- classe do uplink, interface, BSSID ou contexto do switch conforme autorizado, hash do default-gateway e public IP/ASN conforme observado por um serviço controlado;
- idade do handshake do tunnel, packet counters e queue depth;
- estado do switch do enclosure ou do hardware-tamper, caso o proprietário tenha aprovado o sensor;
- pressão do disco, temperatura, estimativa de clock-offset e ID do último job bem-sucedido;
- um número de sequência e uma assinatura para revelar replay ou lacunas.

Armazene centralmente a autenticação do gateway, decisões de policy, acesso de operadores, submissão de jobs, hashes de resultados, eventos de auditoria do provider e alertas. A CISA recomenda centralizar logs, protegê-los contra exclusão, estabelecer uma baseline da atividade normal e designar contatos de incident-response.<sup>[[5]](#references)</sup>

### Indicadores de discovery/compromise

| Signal | Possíveis explicações | Ação do controller |
|---|---|---|
| Heartbeat ausente | falha de energia/rede, alteração do portal, dano, bloqueio deliberado ou remoção | corrobore o estado do provider/local; não reconecte por um caminho não aprovado |
| Boot counter alterado inesperadamente | corte de energia, crash, remoção ou manutenção | coloque os jobs em quarantine; compare o horário e os eventos do local |
| Hash da configuração/imagem alterado | erro de update, falha de storage ou tampering | interrompa o trabalho; revogue se não for um release aprovado pelo controller |
| Novo uplink/BSSID/gateway/ASN | substituição do AP, roaming, dispositivo movido ou interception | compare com o inventário aprovado; coloque em quarantine uma transição sem explicação |
| Job/signature rejeitado repetidamente | corrupção, replay ou controller não autorizado | interrompa o processamento e investigue os logs do gateway/controller |
| Credential do dispositivo usada duas vezes ou por caminhos incompatíveis | chave clonada, reutilização de snapshot ou transição de rede | revogue imediatamente; retenha ambos os registros de sessão |
| Login, interface, processo ou evento de privilege local inesperado | manutenção ou compromise | isole por meio da policy do broker; preserve as evidências |
| Transição do switch/estado do enclosure | serviço, movimentação ou discovery | notifique o contato designado do local; não acione uma ação destrutiva |
| Notificação de abuso do provider/consulta à conta ou alerta do SOC | detecção, configuração incorreta ou tráfego fora do scope | interrompa a atividade e acione o processo de deconfliction/incident |
| Sentinel credential acessada | alguém leu um secret decoy sem privilégios, exclusivo deste node | revogue a identidade real do dispositivo e preserve o histórico do alerta |

Uma sentinel credential não deve conceder **nenhum acesso**, deve chamar apenas um serviço de alerta controlado pela organização e deve ser divulgada nas regras de engagement. Ela é um tripwire para leitura não autorizada, não um beacon para rastrear quem encontrou o equipamento.

### Limiares de alerta

Use regras com estado, não um único alerta dramático de “caught”:

- **warning:** um intervalo perdido, alteração normal de endereço ou crescimento da queue;
- **degraded:** três intervalos consecutivos perdidos, atraso na renovação, perda do uplink primário ou restart repetido;
- **quarantine:** alteração não aprovada de hash/boot/uplink, credential duplicada, uso do sentinel ou evento privilegiado inesperado;
- **confirmed discovery/loss:** relatório do local/controller, divergência no inventário físico, recuperação do dispositivo por uma pessoa não planejada ou escalation validado do provider/SOC.

Teste a entrega de alertas por meio de um canal independente do field node. Evite enviar detalhes sensíveis do cliente/dispositivo para messaging pessoal ou contas de push de consumidores.

## Runbook para discovery ou capture suspeita

1. **Pare:** suspenda novos jobs e sessões de operadores. Não envie uma probe de “verificar se está sendo monitorado”.
2. **Coloque em quarantine:** faça o broker negar a identidade do dispositivo e suas rotas, mantendo os logs existentes.
3. **Revogue:** revogue o certificado/chave do dispositivo, o token da queue, a credential de update e qualquer service token de finalidade única. Suspenda o SIM da organização quando a perda física for plausível.
4. **Preserve:** faça snapshot dos registros do controller, gateway, provider e alertas; registre o horário confiável, quem agiu e a última configuração conhecida. Não limpe nem faça wipe remoto do node.
5. **Notifique:** contate o controller do exercício, o contato de incident do cliente e os contatos legais/de privacidade definidos na autorização. Se um terceiro o encontrou, use o processo de recuperação previamente acordado.
6. **Avalie:** presuma que todo secret e resultado em cache no node foi exposto. Enumere exatamente o que cada secret poderia acessar e se foi usado após o evento suspeito.
7. **Contenha downstream:** faça rotate das credentials de serviços afetados, invalide jobs pendentes e inspecione os logs dos targets/providers controlados quanto a comportamento inesperado.
8. **Recupere com segurança:** recupere apenas por meio de uma pessoa autorizada; fotografe/embale o equipamento, registre a custody e adquira evidências forenses conforme orientação do cliente.
9. **Retome com uma nova identidade:** nunca reative silenciosamente a credential capturada. Faça rebuild a partir do manifest conhecido, corrija a falha de controle e obtenha aprovação explícita.

A orientação atual do NIST para incident-response integra preparation, detection, response e recovery ao gerenciamento de riscos de cybersecurity em toda a organização; preserve primeiro para que o cliente possa determinar o que aconteceu e escolher a resposta apropriada.<sup>[[6]](#references)</sup>

## Capture drill antes do deployment

Entregue uma unidade de teste desbloqueada ou uma cópia de seu storage a um reviewer separado e peça que ele enumere:

1. identificadores de dispositivo/local/engagement;
2. nomes de operadores, contas pessoais, redes domésticas/de workstation e contatos de recovery;
3. destinations e credentials do controller/broker;
4. perfis de rede do cliente e resultados em cache;
5. outros dispositivos/projetos acessíveis com cada secret;
6. credentials de valor ou pagamento;
7. o que o controller pode revogar e com que rapidez;
8. qual atividade continua atribuível a partir dos logs centrais.

Critérios de aprovação: zero contas pessoais/chaves de workstation; zero autoridade de cross-engagement ou enrollment; nenhuma credential de pagamento; cache criptografado e limitado; uma ação documentada de revogação do dispositivo; accountability completa no controller. Trate qualquer link pessoal inesperado ou capacidade lateral como bloqueador de release.

## Encerramento

1. Interrompa os jobs e desative a rota do broker no fim do scope.
2. Recupere e reconcilie o inventário exato; reporte qualquer item ausente.
3. Preserve logs/resultados e, se necessário, uma imagem forense de acordo com o plano de retenção do engagement.
4. Revogue as identidades do dispositivo, SIM, queue, update e services mesmo quando o hardware tiver sido recuperado.
5. Somente após a preservação/aceitação, sanitize ou destrua a mídia usando o processo de descarte de dados aprovado pelo proprietário e registre a conclusão. Isso é gerenciamento do ciclo de vida, não concealment.
6. Remova as reservas de NAC/DHCP do local, rotas do broker, DNS, roles de cloud, regras de alerta e contatos temporários.
7. Documente a detecção observada, a telemetria perdida, o tempo até a quarantine e cada artifact que a capture expôs.

## References

- [1] [NIST — Catálogo de Recursos de Cybersecurity para Dispositivos IoT](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Conceitos e workload identities de curta duração](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
