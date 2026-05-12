# Ataques de Side-Channel em Recebimentos de Entrega em Messengers E2EE

{{#include ../banners/hacktricks-training.md}}

Os receipts de entrega são obrigatórios em messengers modernos de criptografia ponta a ponta (E2EE) porque os clientes precisam saber quando um ciphertext foi decryptado para que possam descartar o estado de ratcheting e as chaves efêmeras. O server encaminha blobs opacos, então as confirmações de dispositivo (duplo visto) são emitidas pelo destinatário após a decrypt bem-sucedida. Medir o round-trip time (RTT) entre uma ação disparada pelo attacker e o corresponding delivery receipt expõe um canal de timing de alta resolução que leak o estado do dispositivo, a presença online e pode ser abusado para covert DoS. Deployments multi-device de "client-fanout" amplificam o leak porque cada device registrado decrypta a probe e retorna seu próprio receipt.

## Fontes de delivery receipt vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitam um delivery receipt, mas não exibam artefatos de UI na vítima. A tabela abaixo resume o comportamento confirmado empiricamente:

| Messenger | Ação | Delivery receipt | Notificação da vítima | Notas |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Texto | ● | ● | Sempre barulhento → útil apenas para bootstrap de estado. |
| | Reaction | ● | ◐ (somente se reagir a mensagem da vítima) | Self-reactions e remoções permanecem silenciosas. |
| | Edit | ● | push silencioso dependente da plataforma | Janela de edição ≈20 min; ainda há ack após expiração. |
| | Delete for everyone | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda são ack’d. |
| **Signal** | Texto | ● | ● | Mesmas limitações do WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisíveis para a vítima. |
| | Edit/Delete | ● | ○ | O server impõe janela de ~48 h, permite até 10 edits, mas pacotes tardios ainda são ack’d. |
| **Threema** | Texto | ● | ● | Os receipts multi-device são agregados, então apenas um RTT por probe se torna visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento de UI dependente da plataforma é indicado no texto. Desative read receipts se necessário, mas delivery receipts não podem ser desativados no WhatsApp ou Signal.

## Objetivos e modelos do attacker

* **G1 – Device fingerprinting:** Conte quantos receipts chegam por probe, agrupe RTTs para inferir OS/client (Android vs iOS vs desktop) e observe transições online/offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTT em alta frequência (≈1 Hz é estável) como uma série temporal e infira screen on/off, app foreground/background, horários de deslocamento vs trabalho, etc.
* **G3 – Exaustão de recursos:** Mantenha radios/CPUs de cada device da vítima acordados enviando probes silenciosas sem fim, drenando bateria/dados e degradando a qualidade de VoIP/RTC.

Dois threat actors são suficientes para descrever a superfície de abuso:

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de self-reactions, remoções de reaction ou edits/deletes repetidos ligados a IDs de mensagem existentes.
2. **Spooky stranger:** registra uma conta burner e envia reactions referenciando message IDs que nunca existiram na conversa local; WhatsApp e Signal ainda decryptam e confirmam mesmo que a UI descarte a mudança de estado, então nenhuma conversa prévia é necessária.

## Ferramentas para acesso bruto ao protocolo

Use clients que expõem o protocolo E2EE subjacente para que você possa criar pacotes fora das restrições da UI, especificar `message_id`s arbitrários e registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo do WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) permitem emitir frames brutos de `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` enquanto mantêm o estado do double-ratchet sincronizado.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado com [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expõe todos os tipos de mensagem via CLI/API. A sintaxe atual do `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para que os delivery receipts sejam realmente coletados. Exemplo de toggle de self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** A source do client Android documenta como os delivery receipts são consolidados antes de saírem do device, explicando por que o side channel tem largura de banda desprezível ali.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) traz backends de WhatsApp/Signal, usa por padrão silent delete probes e rotula `active` vs `standby` com um threshold de rolling median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é um CLI mais leve focado em WhatsApp com `--delay`, `--concurrent`, exportadores CSV/Prometheus e saída amigável ao Grafana. Trate ambos como auxiliares de reconnaissance, não como referências de protocolo; a conclusão importante é quão pouco código é necessário quando existe acesso bruto ao client.

Quando não houver tooling customizado disponível, ainda é possível disparar ações silenciosas a partir do WhatsApp Web ou Signal Desktop e fazer sniff do canal websocket/WebRTC criptografado, mas APIs brutas removem delays da UI e permitem operações inválidas.

## Creepy companion: loop de amostragem silenciosa

1. Escolha qualquer mensagem histórica que você tenha enviado no chat para que a vítima nunca veja balões de "reaction" mudando.
2. Alterne entre um emoji visível e um payload vazio de reaction (codificado como `""` nos protobufs do WhatsApp ou `--remove` no signal-cli). Cada transmissão gera um ack de dispositivo apesar de não haver delta de UI para a vítima.
3. Registre o send time e cada chegada de delivery receipt. Um loop de 1 Hz como o seguinte fornece traces de RTT por device indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam updates ilimitados de reaction, o attacker nunca precisa publicar novo conteúdo no chat nem se preocupar com janelas de edição.

## Spooky stranger: sondando números de telefone arbitrários

1. Registre uma conta nova de WhatsApp/Signal e obtenha as public identity keys do número alvo (feito automaticamente durante a configuração da sessão).
2. Monte um pacote de reaction/edit/delete que referencie um `message_id` aleatório nunca visto por nenhuma das partes (WhatsApp aceita GUIDs arbitrários de `key.id`; Signal usa timestamps em milissegundos).
3. Envie o pacote mesmo sem existir thread. Os devices da vítima decryptam, falham ao corresponder a mensagem base, descartam a mudança de estado, mas ainda assim confirmam o ciphertext recebido, enviando delivery receipts de volta ao attacker.
4. Repita continuamente para construir séries de RTT sem nunca aparecer na lista de chats da vítima.

Se primeiro você precisar descobrir quais números estão registrados ou quiser pré-popular inventories de devices em escala, encadeie isso com [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar ranges E.164 aleatórios manualmente.

Builds recentes do WhatsApp também expõem `Settings -> Privacy -> Advanced -> Block unknown account messages`. Trate isso como um limitador de throughput, não como uma correção: ele principalmente prejudica flooding sustentado apenas por strangers e é irrelevante quando você já é um contato conhecido.

## Reutilizando edits e deletes como triggers covertes

* **Repeated deletes:** Depois que uma mensagem é deleted-for-everyone uma vez, pacotes adicionais de delete referenciando o mesmo `message_id` não têm efeito de UI, mas cada device ainda os decrypta e confirma.
* **Operações fora da janela:** WhatsApp impõe janelas de delete de ~60 h / edit de ~20 min na UI; Signal impõe ~48 h. Mensagens de protocolo fabricadas fora dessas janelas são silenciosamente ignoradas no device da vítima, mas receipts são transmitidos, então attackers podem sondar indefinidamente muito depois do fim da conversa.
* **Payloads inválidos:** Corpos de edit malformados ou deletes referenciando mensagens já removidas produzem o mesmo comportamento—decrypt plus receipt, zero artefatos visíveis ao usuário.

## Amplificação multi-device e fingerprinting

* Cada device associado (phone, desktop app, browser companion) decrypta a probe independentemente e retorna seu próprio ack. Contar receipts por probe revela a contagem exata de devices.
* Se um device estiver offline, seu receipt fica enfileirado e é emitido na reconexão. Portanto, lacunas leak ciclos online/offline e até horários de deslocamento (por exemplo, os receipts do desktop param durante viagens).
* As distribuições de RTT diferem por plataforma devido ao gerenciamento de energia do OS e aos wakeups de push. Agrupe RTTs (por exemplo, k-means em features de mediana/variância) para rotular “Android handset", “iOS handset", “Electron desktop", etc.
* Como o sender precisa recuperar o inventário de chaves do destinatário antes de encryptar, o attacker também pode observar quando novos devices são pareados; um aumento súbito na contagem de devices ou um novo cluster de RTT é um forte indicador.

## Inferência comportamental a partir de traces de RTT

1. Amostre em ≥1 Hz para capturar efeitos de agendamento do OS. Com WhatsApp no iOS, RTTs <1 s correlacionam fortemente com screen-on/foreground, >1 s com throttling de screen-off/background.
2. Construa classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue rótulos em sequências para derivar horários de dormir, deslocamentos, horas de trabalho ou quando o companion desktop está ativo.
3. Correlacione probes simultâneas para cada device para ver quando os usuários alternam entre mobile e desktop, quando companions ficam offline e se o app é rate limited por push ou por socket persistente.
4. Em redes reais, evite um único threshold fixo de `1 s`. Faça bootstrap de cada device com uma pequena janela de aquecimento e mantenha uma baseline móvel (por exemplo, `threshold = 0.9 * median RTT`) para que variações de Wi-Fi/celular não derrubem o classificador.

## Inferência de localização a partir do delivery RTT

O mesmo primitive de timing pode ser reutilizado para inferir onde o destinatário está, não apenas se ele está ativo. O trabalho `Hope of Delivery` mostrou que treinar em distribuições de RTT para locais conhecidos do receptor permite que um attacker depois classifique a localização da vítima apenas pelas confirmações de entrega:

* Construa uma baseline para o mesmo alvo enquanto ele estiver em vários lugares conhecidos (casa, escritório, campus, país A vs país B, etc.).
* Para cada localização, colete muitos RTTs normais de mensagens e extraia features simples como mediana, variância ou buckets de percentis.
* Durante o ataque real, compare a nova série de probes com os clusters treinados. O paper relata que até localizações na mesma cidade muitas vezes podem ser separadas, com precisão de `>80%` em um cenário com 3 localizações.
* Isso funciona melhor quando o attacker controla o ambiente do sender e faz probes sob condições de rede semelhantes, porque o caminho medido inclui a rede de acesso do destinatário, a latência de wake-up e a infraestrutura do messenger.

Diferentemente dos ataques silenciosos de reaction/edit/delete acima, a inferência de localização não requer message IDs inválidos nem pacotes furtivos que alterem estado. Mensagens simples com confirmações normais de entrega já bastam, então a troca é menor stealth, mas aplicabilidade mais ampla entre messengers.

## Exaustão de recursos furtiva

Como cada probe silenciosa precisa ser decryptada e confirmada, enviar continuamente toggles de reaction, edits inválidos ou pacotes de delete-for-everyone cria um DoS em camada de aplicação:

* Força o rádio/modem a transmitir/receber a cada segundo → drenagem de bateria perceptível, especialmente em handsets ociosos.
* Gera tráfego upstream/downstream não medido que consome planos de dados móveis enquanto se mistura ao ruído de TLS/WebSocket.
* Ocupa threads de crypto e introduz jitter em recursos sensíveis a latência (VoIP, video calls), mesmo que o usuário nunca veja notificações.
* No WhatsApp, reactions inválidas aceitam muito mais dados do que um emoji normal sugere: medições publicadas encontraram aceitação no server de até aproximadamente `1 MB` por reaction.
* Reactions grandes demais deixam de produzir delivery receipts confiáveis quando o corpo cresce além de aproximadamente `30 bytes`, mas ainda assim são encaminhadas e processadas antes do descarte. Mantenha os corpos das reactions pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for puro drain ou transporte unidirecional covert.
* Medições públicas chegaram a cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego da vítima nesse modo.

## Referências

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
