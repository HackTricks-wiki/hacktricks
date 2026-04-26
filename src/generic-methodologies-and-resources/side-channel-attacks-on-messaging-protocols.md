# Ataques de Side-Channel de Delivery Receipt em Messengers E2EE

{{#include ../banners/hacktricks-training.md}}

Delivery receipts são obrigatórios em messengers modernos de end-to-end encrypted (E2EE) porque os clientes precisam saber quando um ciphertext foi decrypted para poderem descartar o ratcheting state e as ephemeral keys. O server encaminha opaque blobs, então as device acknowledgements (double checkmarks) são emitidas pelo destinatário após a decryption bem-sucedida. Medir o round-trip time (RTT) entre uma action disparada pelo attacker e o corresponding delivery receipt expõe um canal de timing de alta resolução que leak device state, online presence, e pode ser abusado para covert DoS. Deployments multi-device de "client-fanout" amplificam o leak because every registered device decrypts the probe and returns its own receipt.

## Sources de delivery receipt vs. sinais visíveis ao usuário

Escolha message types que sempre emitam um delivery receipt, mas não mostrem artifacts de UI no victim. A tabela abaixo resume o comportamento empiricamente confirmado:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legend: ● = always, ◐ = conditional, ○ = never. O comportamento de UI dependente da plataforma é indicado inline. Desative read receipts se necessário, mas delivery receipts não podem ser desativados no WhatsApp ou Signal.

## Objetivos e modelos do attacker

* **G1 – Device fingerprinting:** Conte quantos receipts chegam por probe, agrupe RTTs para inferir OS/client (Android vs iOS vs desktop), e observe transições online/offline.
* **G2 – Behavioral monitoring:** Trate a série de RTT de alta frequência (≈1 Hz é estável) como uma time-series e infira screen on/off, app foreground/background, commuting vs working hours, etc.
* **G3 – Resource exhaustion:** Mantenha radios/CPUs de cada device da victim acordados enviando silent probes sem fim, drenando battery/data e degradando a qualidade de VoIP/RTC.

Dois threat actors são suficientes para descrever a superfície de abuse:

1. **Creepy companion:** já compartilha um chat com a victim e abusa de self-reactions, reaction removals, ou repeated edits/deletes vinculados a message IDs existentes.
2. **Spooky stranger:** registra uma burner account e envia reactions referenciando message IDs que nunca existiram na conversa local; WhatsApp e Signal ainda decrypt e acknowledge isso mesmo que a UI descarte a state change, então nenhuma conversa prévia é necessária.

## Tooling para acesso bruto ao protocolo

Use clients que exponham o underlying E2EE protocol para que você possa craft packets fora das restrições da UI, especificar `message_id`s arbitrários e registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ou [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) permitem emitir frames brutos `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` enquanto mantêm o double-ratchet state sincronizado.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado com [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expõe every message type via CLI/API. Exemplo de toggle de self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** O source do Android client documenta como os delivery receipts são consolidados antes de sair do device, explicando por que o side channel tem bandwidth desprezível ali.
* **Turnkey PoCs:** projetos públicos como `device-activity-tracker` e `careless-whisper-python` já automatizam silent delete/reaction probes e classificação por RTT. Trate-os como helpers de reconnaissance prontos, e não como referências de protocolo; o ponto interessante é que eles confirmam que o ataque é operacionalmente simples uma vez que existe acesso bruto ao client.

Quando não houver tooling customizado disponível, ainda é possível disparar ações silenciosas a partir do WhatsApp Web ou Signal Desktop e sniffar o canal websocket/WebRTC encrypted, mas APIs brutas removem delays da UI e permitem operações inválidas.

## Creepy companion: silent sampling loop

1. Escolha qualquer historical message que você tenha authored no chat para que a victim nunca veja os balões de "reaction" mudarem.
2. Alterne entre um emoji visível e um payload de reaction vazio (codificado como `""` em WhatsApp protobufs ou `--remove` em signal-cli). Cada transmissão gera um device ack apesar de não haver delta de UI para a victim.
3. Marque o horário de envio e cada chegada de delivery receipt. Um loop de 1 Hz como o seguinte fornece traces de RTT por device indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam updates de reaction ilimitados, o attacker nunca precisa postar novo conteúdo no chat nem se preocupar com edit windows.

## Spooky stranger: probing de phone numbers arbitrários

1. Registre uma conta nova do WhatsApp/Signal e obtenha as public identity keys do número alvo (feito automaticamente durante a configuração da sessão).
2. Crie um packet de reaction/edit/delete que referencie um `message_id` aleatório nunca visto por nenhuma das partes (WhatsApp aceita GUIDs arbitrários em `key.id`; Signal usa timestamps em milissegundos).
3. Envie o packet mesmo sem existir thread. Os devices da victim decrypt it, falham em casar a base message, descartam a state change, mas ainda assim acknowledge o ciphertext de entrada, enviando device receipts de volta para o attacker.
4. Repita continuamente para construir séries de RTT sem nunca aparecer na chat list da victim.

## Reutilizando edits e deletes como triggers covertes

* **Repeated deletes:** Depois que uma message é deleted-for-everyone uma vez, packets de delete posteriores referenciando o mesmo `message_id` não têm efeito de UI, mas cada device ainda os decrypt e acknowledge.
* **Out-of-window operations:** WhatsApp aplica janelas de ~60 h para delete / ~20 min para edit na UI; Signal aplica ~48 h. Protocol messages crafted fora dessas janelas são silenciosamente ignoradas no device da victim, porém receipts continuam sendo transmitidos, então attackers podem fazer probe indefinidamente muito depois do fim da conversa.
* **Invalid payloads:** Corpos de edit malformados ou deletes referenciando mensagens já purgadas produzem o mesmo comportamento — decryption mais receipt, zero artifacts visíveis ao usuário.

## Amplificação multi-device & fingerprinting

* Cada device associado (phone, desktop app, browser companion) decrypts o probe de forma independente e retorna seu próprio ack. Contar receipts por probe revela o número exato de devices.
* Se um device estiver offline, o receipt dele fica enfileirado e é emitido na reconexão. Portanto, gaps leak ciclos online/offline e até rotinas de deslocamento (por exemplo, os receipts do desktop param durante viagens).
* As distribuições de RTT diferem por plataforma devido ao gerenciamento de energia do OS e aos push wakeups. Agrupe RTTs (por exemplo, k-means em features de mediana/variância) para rotular “Android handset", “iOS handset", “Electron desktop", etc.
* Como o sender precisa recuperar o inventário de chaves do recipient antes de encrypt, o attacker também pode observar quando novos devices são pareados; um aumento súbito no número de devices ou um novo cluster de RTT é um forte indicador.

## Inferência de comportamento a partir de traces de RTT

1. Amostre em ≥1 Hz para capturar efeitos de escalonamento do OS. Com WhatsApp no iOS, RTTs <1 s correlacionam fortemente com screen-on/foreground, e >1 s com throttling de screen-off/background.
2. Construa classificadores simples (thresholding ou two-cluster k-means) que rotulem cada RTT como "active" ou "idle". Agregue os rótulos em streaks para derivar bedtimes, commutes, work hours, ou quando o companion desktop está ativo.
3. Correlacione probes simultâneos para cada device para ver quando users trocam de mobile para desktop, quando companions ficam offline e se o app é limited por rate via push ou persistent socket.

## Inferência de localização a partir de delivery RTT

O mesmo primitive de timing pode ser reaproveitado para inferir onde o recipient está, e não apenas se ele está ativo. O trabalho `Hope of Delivery` mostrou que treinar em distribuições de RTT para localizações conhecidas do receiver permite que um attacker depois classifique a localização da victim apenas com base em delivery confirmations:

* Construa uma baseline para o mesmo target enquanto ele está em vários locais conhecidos (casa, escritório, campus, país A vs país B, etc.).
* Para cada localização, colete muitos RTTs normais de mensagens e extraia features simples como mediana, variância ou buckets de percentis.
* Durante o ataque real, compare a nova série de probes com os clusters treinados. O paper relata que até localizações dentro da mesma cidade muitas vezes podem ser separadas, com accuracy de `>80%` em um cenário de 3 localizações.
* Isso funciona melhor quando o attacker controla o sender environment e faz probes sob condições de rede semelhantes, porque o caminho medido inclui a access network do recipient, a wake-up latency e a infraestrutura do messenger.

Ao contrário dos ataques silenciosos de reaction/edit/delete acima, a inferência de localização não exige message IDs inválidos nem packets furtivos que alteram state. Mensagens simples com delivery confirmations normais são suficientes, então o tradeoff é menor stealth, mas maior aplicabilidade entre messengers.

## Resource exhaustion furtiva

Como cada silent probe precisa ser decrypted e acknowledged, enviar continuamente toggles de reaction, edits inválidos ou packets delete-for-everyone cria um DoS de application-layer:

* Força o radio/modem a transmitir/receber a cada segundo → drenagem notável de battery, especialmente em handsets ociosos.
* Gera tráfego upstream/downstream não medido que consome planos de mobile data enquanto se mistura ao ruído de TLS/WebSocket.
* Ocupa crypto threads e introduz jitter em features sensíveis à latência (VoIP, video calls) mesmo que o usuário nunca veja notifications.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
