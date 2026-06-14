# Ataques de Side-Channel de Delivery Receipt em mensageiros E2EE

{{#include ../banners/hacktricks-training.md}}

Delivery receipts são obrigatórios em mensageiros modernos de end-to-end encrypted (E2EE) porque os clientes precisam saber quando um ciphertext foi descriptografado para que possam descartar o estado de ratcheting e chaves efêmeras. O servidor encaminha blobs opacos, então acknowledgements do dispositivo (double checkmarks) são emitidos pelo destinatário após a descriptografia bem-sucedida. Medir o round-trip time (RTT) entre uma ação disparada pelo atacante e o correspondente delivery receipt expõe um canal de timing de alta resolução que leak estado do dispositivo, presença online e pode ser abusado para covert DoS. Deployments multi-device de "client-fanout" ampliam o leak porque todo dispositivo registrado descriptografa o probe e retorna seu próprio receipt.

## Fontes de delivery receipt vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitam um delivery receipt, mas não mostrem artefatos de UI na vítima. A tabela abaixo resume o comportamento confirmado empiricamente:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Sempre ruidoso → útil apenas para bootstrap de estado. |
| | Reaction | ● | ◐ (apenas se reagindo à mensagem da vítima) | Self-reactions e remoções permanecem silenciosas. |
| | Edit | ● | Silent push dependente da plataforma | Janela de edição ≈20 min; ainda recebe ack após expirar. |
| | Delete for everyone | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda recebem ack. |
| **Signal** | Text message | ● | ● | Mesmas limitações do WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisíveis para a vítima. |
| | Edit/Delete | ● | ○ | O servidor impõe janela de ~48 h, permite até 10 edits, mas pacotes tardios ainda recebem ack. |
| **Threema** | Text message | ● | ● | Delivery receipts multi-device são agregados, então apenas um RTT por probe fica visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento da UI dependente da plataforma é indicado inline. Desative read receipts se necessário, mas delivery receipts não podem ser desligados no WhatsApp ou Signal.

## Objetivos e modelos do atacante

* **G1 – Fingerprinting de dispositivo:** Conte quantos receipts chegam por probe, agrupe RTTs para inferir OS/client (Android vs iOS vs desktop) e observe transições online/offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTT de alta frequência (≈1 Hz é estável) como uma time-series e infira screen on/off, app foreground/background, deslocamento vs horário de trabalho, etc.
* **G3 – Exaustão de recursos:** Mantenha rádios/CPUs de cada dispositivo da vítima acordados enviando silent probes sem fim, drenando bateria/dados e degradando a qualidade de VoIP/RTC.

Dois threat actors bastam para descrever a superfície de abuso:

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de self-reactions, reaction removals ou edits/deletes repetidos vinculados a message IDs já existentes.
2. **Spooky stranger:** registra uma conta descartável e envia reactions referenciando message IDs que nunca existiram na conversa local; WhatsApp e Signal ainda descriptografam e confirmam mesmo que a UI descarte a mudança de estado, então nenhuma conversa prévia é necessária.

## Ferramentas para acesso bruto ao protocolo

Use clients que exponham o protocolo E2EE subjacente para que você possa montar packets fora das restrições da UI, especificar `message_id`s arbitrários e registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo do WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) permitem emitir frames brutos de `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` mantendo o estado do double-ratchet sincronizado.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado com [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expõe cada tipo de mensagem via CLI/API. A sintaxe atual do `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para que os delivery receipts sejam realmente coletados. Exemplo de toggle de self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** A source do Android client documenta como os delivery receipts são consolidados antes de saírem do dispositivo, explicando por que o side channel tem bandwidth desprezível ali.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) traz backends de WhatsApp/Signal, usa por padrão silent delete probes e marca `active` vs `standby` com um threshold de rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é um CLI mais leve, focado em WhatsApp, com `--delay`, `--concurrent`, exporters CSV/Prometheus e saída amigável ao Grafana. Trate ambos como helpers de reconnaissance, não como referências de protocolo; o ponto importante é quão pouco código é necessário quando existe acesso bruto ao client.

Quando não houver tooling customizado disponível, você ainda pode disparar actions silenciosas a partir do WhatsApp Web ou Signal Desktop e farejar o encrypted websocket/WebRTC channel, mas APIs brutas removem delays da UI e permitem operações inválidas.

## Creepy companion: silent sampling loop

1. Escolha qualquer mensagem histórica que você tenha escrito no chat para que a vítima nunca veja mudanças nos balões de "reaction".
2. Alterne entre um emoji visível e um payload de reaction vazio (codificado como `""` em protobufs do WhatsApp ou `--remove` no signal-cli). Cada transmissão gera um device ack apesar de não haver delta de UI para a vítima.
3. Marque o horário de envio e cada chegada de delivery receipt. Um loop de 1 Hz como o seguinte fornece traces de RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam updates de reaction ilimitados, o atacante nunca precisa postar novo conteúdo no chat nem se preocupar com janelas de edição.

## Spooky stranger: sondando números de telefone arbitrários

1. Registre uma conta nova no WhatsApp/Signal e obtenha as public identity keys do número-alvo (feito automaticamente durante a configuração da sessão).
2. Monte um packet de reaction/edit/delete que referencie um `message_id` aleatório nunca visto por nenhuma das partes (WhatsApp aceita GUIDs arbitrários em `key.id`; Signal usa timestamps em milissegundos).
3. Envie o packet mesmo que não exista thread alguma. Os dispositivos da vítima descriptografam, não conseguem casar a mensagem base, descartam a mudança de estado, mas ainda assim confirmam o ciphertext recebido, enviando delivery receipts de volta ao atacante.
4. Repita continuamente para construir séries de RTT sem jamais aparecer na lista de chats da vítima.

Se você primeiro precisar descobrir quais números estão registrados ou quiser pré-popular inventários de dispositivos em escala, encadeie isso com [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar ranges E.164 aleatórios manualmente.

Trabalhos publicados sobre contact-discovery mostraram por que isso importa operacionalmente: com tabelas precisas de prefixo telefônico e recursos modestos, pesquisadores conseguiram consultar cerca de `10%` dos números móveis dos EUA no WhatsApp e `100%` no Signal antes de passar para probing direcionado. Na prática, pré-filtrar contas vivas primeiro mantém seu budget de silent-probe focado em números que realmente descriptografarão packets.

Builds recentes do WhatsApp também expõem `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trate isso como limitador de throughput, não como correção: ele principalmente atrapalha flooding sustentado vindo apenas de strangers e é irrelevante depois que você já é um contato conhecido.

## Reutilizando edits e deletes como triggers covertes

* **Deletes repetidos:** Depois que uma mensagem é deleted-for-everyone uma vez, packets de delete adicionais referenciando o mesmo `message_id` não têm efeito na UI, mas todo dispositivo ainda descriptografa e confirma.
* **Operações fora da janela:** WhatsApp impõe janelas de delete de ~60 h / edit de ~20 min na UI; Signal impõe ~48 h. Mensagens de protocolo montadas fora dessas janelas são ignoradas silenciosamente no dispositivo da vítima, mas receipts ainda são transmitidos, então atacantes podem sondar indefinidamente muito depois de a conversa terminar.
* **Payloads inválidos:** Bodies de edit malformados ou deletes referenciando mensagens já purgadas provocam o mesmo comportamento — descriptografia mais receipt, zero artefatos visíveis ao usuário.

## Amplificação multi-device e fingerprinting

* Cada dispositivo associado (phone, desktop app, browser companion) descriptografa o probe de forma independente e retorna seu próprio ack. Contar receipts por probe revela o número exato de dispositivos.
* Se um dispositivo estiver offline, seu receipt fica enfileirado e é emitido na reconexão. Lacunas, portanto, leak ciclos online/offline e até horários de deslocamento (por exemplo, receipts do desktop param durante a viagem).
* As distribuições de RTT diferem por plataforma devido ao power management do OS e aos wakeups de push. Agrupe RTTs (por exemplo, k-means em features de mediana/variância) para rotular “Android handset”, “iOS handset”, “Electron desktop”, etc.
* Como o remetente precisa recuperar o inventário de chaves do destinatário antes de criptografar, o atacante também pode observar quando novos devices são pareados; um aumento súbito no número de devices ou um novo cluster de RTT é um forte indicador.

## Cadência de sampling, queueing e stacked receipts

* **Tolerância a bursts no WhatsApp:** Medições publicadas relataram que o WhatsApp aceitou bursts de silent-reaction tão rápidos quanto um probe a cada `50 ms` sem queueing óbvio no lado do servidor. Isso é útil para bursts curtos de calibração, contagem rápida de devices ou para acelerar um ataque de drain.
* **Queueing de longo prazo no Signal:** O Signal tolerou bursts curtos, mas começou a fazer queue de tráfego sustentado com múltiplos probes por segundo. Para monitoramento de longa duração, mantenha a cadência em torno de `1 Hz` (ou menor) para que cada receipt ainda reflita o estado atual do device, em vez de drenar backlog.
* **Artefatos de reconexão:** Quando um device volta online, alguns clients agrupam ou drenam rapidamente múltiplos receipts atrasados. Trate esses bursts de receipts como marcador de transição de estado, e não como amostras RTT independentes, ou seu clustering / classificador de `active` vs `idle` vai overfit no ruído de reconexão.

## Inferência de comportamento a partir de traces de RTT

1. Faça sampling em ≥1 Hz para capturar efeitos de agendamento do OS. Com WhatsApp no iOS, RTTs < 1 s correlacionam fortemente com screen-on/foreground, e > 1 s com screen-off/background throttling.
2. Construa classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue rótulos em streaks para derivar horários de dormir, deslocamentos, horas de trabalho ou quando o companion desktop está ativo.
3. Correlacione probes simultâneos para cada device para ver quando usuários trocam de mobile para desktop, quando companions ficam offline e se o app é rate limited por push versus persistent socket.
4. Em redes reais, evite um único threshold fixo de `1 s`. Faça bootstrap de cada device com uma janela curta de warm-up e mantenha uma baseline rolling (por exemplo, `threshold = 0.9 * median RTT`) para que o drift de Wi-Fi/celular não derrube seu classificador.

## Inferência de localização a partir do delivery RTT

O mesmo primitive de timing pode ser reaproveitado para inferir onde o destinatário está, e não apenas se ele está ativo. O trabalho `Hope of Delivery` mostrou que treinar em distribuições de RTT para locais conhecidos do receptor permite ao atacante depois classificar a localização da vítima apenas a partir de delivery confirmations:

* Construa uma baseline para o mesmo alvo enquanto ele está em vários locais conhecidos (casa, escritório, campus, país A vs país B, etc.).
* Para cada local, colete muitos RTTs de mensagens normais e extraia features simples como mediana, variância ou buckets de percentil.
* Durante o ataque real, compare a nova série de probes contra os clusters treinados. O artigo relata que até locais dentro da mesma cidade muitas vezes podem ser separados, com acurácia de `>80%` em um cenário de 3 locais.
* Isso funciona melhor quando o atacante controla o ambiente de envio e faz probes sob condições de rede semelhantes, porque o caminho medido inclui a rede de acesso do destinatário, a latência de wake-up e a infraestrutura do messenger.

Diferentemente dos ataques silenciosos de reaction/edit/delete acima, a inferência de localização não exige message IDs inválidos nem packets stealthy de mudança de estado. Mensagens simples com confirmações normais de delivery bastam, então a troca é menor stealth, mas maior aplicabilidade entre mensageiros.

## Exaustão de recursos stealthy

Como cada silent probe precisa ser descriptografado e confirmado, enviar continuamente toggles de reaction, edits inválidos ou packets de delete-for-everyone cria um DoS em camada de aplicação:

* Força o rádio/modem a transmitir/receber a cada segundo → drenagem de bateria perceptível, especialmente em handsets ociosos.
* Gera tráfego upstream/downstream não contabilizado que consome planos de dados móveis enquanto se mistura ao ruído de TLS/WebSocket.
* Ocupa threads de crypto e introduz jitter em recursos sensíveis à latência (VoIP, video calls) mesmo que o usuário nunca veja notificações.
* No WhatsApp, reactions inválidas aceitam muito mais dados do que um emoji normal sugeriria: medições publicadas encontraram aceitação no servidor de até cerca de `1 MB` por reaction.
* Reactions grandes demais deixam de produzir delivery receipts confiáveis quando o body cresce além de cerca de `30 bytes`, mas ainda assim são encaminhadas e processadas antes do descarte. Mantenha os bodies de reaction pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for puro drain ou transporte unilateral covert.
* Medições públicas chegaram a cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego da vítima nesse modo.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
