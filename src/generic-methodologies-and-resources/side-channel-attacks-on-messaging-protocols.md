# Ataques de canal lateral de receipt de entrega em mensageiros E2EE

{{#include ../banners/hacktricks-training.md}}

Recibos de entrega são obrigatórios em mensageiros modernos end-to-end encrypted (E2EE) porque os clientes precisam saber quando um ciphertext foi decriptado para descartarem o estado do ratchet e as chaves efémeras. O servidor encaminha blobs opacos, então os acknowledgements de dispositivo (double checkmarks) são emitidos pelo destinatário após a decriptação bem-sucedida. Medir o round-trip time (RTT) entre uma ação desencadeada pelo atacante e o receipt de entrega correspondente expõe um canal de temporização de alta resolução que leaks device state, presença online, e pode ser abusado para DoS encoberto. Deployments multi-dispositivo "client-fanout" amplificam a leakage porque cada dispositivo registrado decripta a probe e retorna seu próprio receipt.

## Fontes de receipts de entrega vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitem um receipt de entrega mas não geram artefatos visíveis na UI da vítima. A tabela abaixo resume o comportamento empiricamente confirmado:

| Messenger | Ação | Recibo de entrega | Notificação da vítima | Notas |
|-----------|------|-------------------|-----------------------|-------|
| **WhatsApp** | Text message | ● | ● | Sempre ruidoso → útil apenas para bootstrap do estado. |
| | Reaction | ● | ◐ (somente se reagindo a mensagem da vítima) | Self-reactions e remoções ficam silenciosas. |
| | Edit | ● | Platform-dependent silent push | Janela de edição ≈20 min; ainda é ack’d após expirar. |
| | Delete for everyone | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda são ack’d. |
| **Signal** | Text message | ● | ● | Mesmas limitações do WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisíveis para a vítima. |
| | Edit/Delete | ● | ○ | O servidor impõe janela ~48 h, permite até 10 edits, mas pacotes tardios ainda são ack’d. |
| **Threema** | Text message | ● | ● | Recibos multi-dispositivo são agregados, então apenas um RTT por probe fica visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. Comportamento de UI dependente da plataforma é notado inline. Desative read receipts se necessário, mas delivery receipts não podem ser desligados no WhatsApp ou Signal.

## Objetivos e modelos do atacante

* **G1 – Device fingerprinting:** Conte quantos receipts chegam por probe, agrupe RTTs para inferir OS/client (Android vs iOS vs desktop) e monitore transições online/offline.
* **G2 – Behavioural monitoring:** Trate a série de RTTs de alta frequência (≈1 Hz é estável) como uma série temporal e infira tela ligada/desligada, app em foreground/background, horários de deslocamento vs trabalho, etc.
* **G3 – Resource exhaustion:** Mantenha rádios/CPUs de cada dispositivo da vítima acordados enviando probes silenciosos intermináveis, esgotando bateria/dados e degradando qualidade de VoIP/RTC.

Dois atores de ameaça são suficientes para descrever a superfície de abuso:

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de self-reactions, remoções de reaction, ou edições/deletes repetidos ligados a message IDs existentes.
2. **Spooky stranger:** registra uma conta burner e envia reactions referenciando message IDs que nunca existiram na conversa local; WhatsApp e Signal ainda os decriptam e reconhecem mesmo que a UI descarte a mudança de estado, então não é necessária conversação prévia.

## Ferramentas para acesso bruto ao protocolo

Dependa de clients que exponham o protocolo E2EE subjacente para que você possa confeccionar pacotes fora das restrições de UI, especificar `message_id`s arbitrários e logar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ou [Cobalt](https://github.com/Auties00/Cobalt) (orientado a mobile) permitem emitir frames raw `ReactionMessage`, `ProtocolMessage` (edit/delete) e `Receipt` mantendo o estado do double-ratchet em sincronia.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado com [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expõe todo tipo de mensagem via CLI/API. Exemplo de toggle de self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** O código-fonte do client Android documenta como os receipts de entrega são consolidados antes de saírem do dispositivo, explicando por que o side channel tem largura de banda negligenciável lá.

Quando ferramentas customizadas não estão disponíveis, você ainda pode disparar ações silenciosas pelo WhatsApp Web ou Signal Desktop e sniffar o websocket/WebRTC encriptado, mas APIs raw removem delays de UI e permitem operações inválidas.

## Creepy companion: loop silencioso de amostragem

1. Escolha qualquer mensagem histórica que você tenha enviado no chat para que a vítima nunca veja balões de "reaction" mudando.
2. Alterne entre um emoji visível e um payload de reaction vazio (codificado como `""` em protobufs do WhatsApp ou `--remove` no signal-cli). Cada transmissão gera um ack de dispositivo apesar de não haver delta na UI para a vítima.
3. Registre o timestamp do envio e de cada chegada de receipt de entrega. Um loop a 1 Hz como o seguinte dá traces de RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam updates ilimitados de reactions, o atacante nunca precisa postar novo conteúdo no chat nem se preocupar com janelas de edição.

## Spooky stranger: sondando números de telefone arbitrários

1. Registre uma conta nova no WhatsApp/Signal e busque as public identity keys para o número alvo (feito automaticamente durante o setup da sessão).
2. Construa um pacote de reaction/edit/delete que referencie um `message_id` aleatório nunca visto por nenhuma das partes (WhatsApp aceita GUIDs arbitrários em `key.id`; Signal usa timestamps em milissegundos).
3. Envie o pacote mesmo que não exista thread. Os dispositivos da vítima decriptam, não conseguem casar com a mensagem base, descartam a mudança de estado, mas ainda assim reconhecem o ciphertext recebido, enviando receipts de dispositivo de volta ao atacante.
4. Repita continuamente para construir séries de RTT sem nunca aparecer na lista de chats da vítima.

## Reaproveitando edits e deletes como gatilhos encobertos

* **Deletes repetidos:** Após uma mensagem ser deleted-for-everyone uma vez, deletes adicionais referenciando o mesmo `message_id` não têm efeito na UI, mas cada dispositivo ainda decripta e ack.
* **Operações fora de janela:** WhatsApp aplica janelas de ~60 h para delete / ~20 min para edit na UI; Signal aplica ~48 h. Mensagens de protocolo craftadas fora dessas janelas são silenciosamente ignoradas no dispositivo da vítima, mas receipts são transmitidos, então atacantes podem sondar indefinidamente muito tempo após a conversa ter acabado.
* **Payloads inválidos:** Corpos de edit malformed ou deletes referenciando mensagens já purgadas provocam o mesmo comportamento — decriptação mais receipt, zero artefatos visíveis ao usuário.

## Amplificação multi-dispositivo & fingerprinting

* Cada dispositivo associado (telefone, app desktop, companion em browser) decripta a probe independentemente e retorna seu próprio ack. Contar receipts por probe revela o número exato de dispositivos.
* Se um dispositivo está offline, seu receipt é enfileirado e emitido ao reconectar. Gaps portanto leak online/offline cycles e até horários de deslocamento (por exemplo, receipts do desktop param durante viagem).
* Distribuições de RTT diferem por plataforma devido ao power management do OS e wakeups de push. Agrupe RTTs (por exemplo, k-means em features median/variance) para rotular “Android handset”, “iOS handset”, “Electron desktop”, etc.
* Como o remetente precisa recuperar o inventário de chaves do destinatário antes de encriptar, o atacante também pode observar quando novos dispositivos são pareados; um aumento súbito no número de dispositivos ou um novo cluster de RTT é um forte indicador.

## Inferência de comportamento a partir de traces de RTT

1. Amostre a ≥1 Hz para capturar efeitos de scheduling do OS. Com WhatsApp no iOS, RTTs <1 s correlacionam fortemente com tela ligada/foreground; >1 s com throttling de tela off/background.
2. Construa classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue rótulos em streaks para derivar horários de sono, deslocamentos, horas de trabalho, ou quando o companion desktop está ativo.
3. Correlacione probes simultâneos para cada dispositivo para ver quando usuários mudam de mobile para desktop, quando companions ficam offline, e se o app é rate limited por push vs socket persistente.

## Exaustão de recursos stealthy

Porque cada probe silencioso deve ser decriptado e acknowledged, enviar continuamente toggles de reaction, edits inválidos, ou pacotes delete-for-everyone cria um DoS a nível de aplicação:

* Força o rádio/modem a transmitir/receber a cada segundo → drain de bateria perceptível, especialmente em handsets ociosos.
* Gera tráfego upstream/downstream não medido que consome planos de dados móveis enquanto se mistura ao ruído TLS/WebSocket.
* Ocupa threads de crypto e introduz jitter em features sensíveis a latência (VoIP, video calls) apesar do usuário nunca ver notificações.

## Referências

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
