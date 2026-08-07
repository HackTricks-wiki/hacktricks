# Ataques de Side-Channel de Confirmações de Entrega em Messengers E2EE

{{#include ../banners/hacktricks-training.md}}

As confirmações de entrega são obrigatórias em messengers modernos com criptografia end-to-end (E2EE), pois os clientes precisam saber quando um ciphertext foi descriptografado para poder descartar o estado do ratchet e as chaves efêmeras. O servidor encaminha blobs opacos, portanto as confirmações dos dispositivos (duplas marcas de verificação) são emitidas pelo destinatário após a descriptografia bem-sucedida. Medir o tempo de ida e volta (RTT) entre uma ação acionada pelo atacante e a confirmação de entrega correspondente expõe um canal de temporização de alta resolução que faz leak do estado do dispositivo e da presença online, além de poder ser abusado para DoS encoberto. Implantações "client-fanout" com múltiplos dispositivos amplificam o leak, pois cada dispositivo registrado descriptografa a sonda e retorna sua própria confirmação.<sup>[[1]](#references)</sup>

## Fontes de confirmações de entrega vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitam uma confirmação de entrega, mas não exibam artefatos de UI para a vítima. A tabela abaixo resume o comportamento confirmado empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Ação | Confirmação de entrega | Notificação da vítima | Observações |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensagem de texto | ● | ● | Sempre gera ruído → útil apenas para inicializar o estado. |
| | Reação | ● | ◐ (somente ao reagir à mensagem da vítima) | Autorreação e remoção permanecem silenciosas. |
| | Edição | ● | Push silencioso dependente da plataforma | Janela de edição ≈20 min; ainda recebe ack após a expiração. |
| | Apagar para todos | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda recebem ack. |
| **Signal** | Mensagem de texto | ● | ● | Mesmas limitações do WhatsApp. |
| | Reação | ● | ◐ | Autorreação invisível para a vítima. |
| | Edição/Exclusão | ● | ○ | O servidor impõe uma janela de ~48 h e permite até 10 edições, mas pacotes atrasados ainda recebem ack. |
| **Threema** | Mensagem de texto | ● | ● | As confirmações de múltiplos dispositivos são agregadas, portanto apenas um RTT por sonda fica visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento da UI dependente da plataforma é indicado nas observações. Desative as confirmações de leitura se necessário, mas as confirmações de entrega não podem ser desativadas no WhatsApp ou no Signal.<sup>[[1]](#references)</sup>

## Objetivos e modelos do atacante

* **G1 – Fingerprinting de dispositivos:** Conte quantas confirmações chegam por sonda, agrupe RTTs para inferir o sistema operacional/cliente (Android vs iOS vs desktop) e monitore transições online/offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTT de alta frequência (≈1 Hz é estável) como uma série temporal e infira tela ligada/desligada, aplicativo em primeiro/segundo plano, deslocamentos vs horários de trabalho etc.
* **G3 – Exaustão de recursos:** Mantenha rádios/CPUs de todos os dispositivos da vítima ativos enviando sondas silenciosas intermináveis, drenando bateria/dados e degradando a qualidade de VoIP/RTC.<sup>[[1]](#references)</sup>

Dois threat actors são suficientes para descrever a superfície de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de autoreações, remoções de reações ou edições/exclusões repetidas associadas a IDs de mensagens existentes.
2. **Spooky stranger:** registra uma conta descartável e envia reações referenciando IDs de mensagens que nunca existiram na conversa local; WhatsApp e Signal ainda as descriptografam e confirmam, embora a UI descarte a alteração de estado, portanto nenhuma conversa anterior é necessária.

## Ferramentas para acesso ao protocolo bruto

Use clientes que exponham o protocolo E2EE subjacente para que você possa criar pacotes fora das restrições da UI, especificar `message_id`s arbitrários e registrar timestamps precisos:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protocolo WhatsApp Web) ou [Cobalt](https://github.com/Auties00/Cobalt) (orientado a dispositivos móveis) permitem emitir frames brutos `ReactionMessage`, `ProtocolMessage` (edição/exclusão) e `Receipt`, mantendo o estado do double-ratchet sincronizado.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combinado com [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expõe cada tipo de mensagem por CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> A sintaxe atual do `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para que as confirmações de entrega sejam realmente coletadas.<sup>[[6]](#references)</sup> Exemplo de alternância de autorreação:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** O código-fonte do cliente Android documenta como as confirmações de entrega são consolidadas antes de sair do dispositivo, explicando por que o side channel tem largura de banda insignificante nesse caso.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inclui backends para WhatsApp/Signal, usa sondas silenciosas de exclusão por padrão e classifica `active` vs `standby` com um limite baseado na mediana móvel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é uma CLI mais leve, focada no WhatsApp, com `--delay`, `--concurrent`, exportadores CSV/Prometheus e saída compatível com Grafana.<sup>[[9]](#references)</sup> Trate ambas como ferramentas auxiliares de reconnaissance, não como referências de protocolo; o ponto principal é perceber como pouco código é necessário quando existe acesso ao cliente bruto.

Quando as ferramentas personalizadas não estiverem disponíveis, ainda é possível acionar ações silenciosas pelo WhatsApp Web ou Signal Desktop e farejar o canal websocket/WebRTC criptografado, mas as APIs brutas removem atrasos da UI e permitem operações inválidas.

## Creepy companion: loop de amostragem silencioso

1. Escolha qualquer mensagem histórica que você tenha enviado no chat para que a vítima nunca veja alterações nos balões de "reação".
2. Alterne entre um emoji visível e um payload de reação vazio (codificado como `""` nos protobufs do WhatsApp ou como `--remove` no signal-cli). Cada transmissão gera um ack do dispositivo, apesar de não haver alteração na UI da vítima.
3. Registre o horário de envio e a chegada de cada confirmação de entrega. Um loop de 1 Hz como o seguinte fornece rastreamentos de RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam atualizações ilimitadas de reações, o atacante nunca precisa publicar novo conteúdo no chat nem se preocupar com janelas de edição.<sup>[[1]](#references)</sup>

## Spooky stranger: sondagem de números de telefone arbitrários

1. Registre uma nova conta do WhatsApp/Signal e obtenha as chaves públicas de identidade do número-alvo (isso é feito automaticamente durante a configuração da sessão).
2. Crie um pacote de reação/edição/exclusão que faça referência a um `message_id` aleatório nunca visto por nenhuma das partes (o WhatsApp aceita GUIDs `key.id` arbitrários; o Signal usa timestamps em milissegundos).
3. Envie o pacote mesmo que não exista nenhuma thread. Os dispositivos da vítima o descriptografam, não conseguem associá-lo à mensagem-base, descartam a alteração de estado, mas ainda confirmam o ciphertext recebido, enviando confirmações do dispositivo de volta ao atacante.
4. Repita continuamente para criar séries de RTT sem jamais aparecer na lista de chats da vítima.<sup>[[1]](#references)</sup>

Se primeiro precisar descobrir quais números estão registrados ou quiser pré-carregar inventários de dispositivos em escala, encadeie isso com [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar manualmente intervalos E.164 aleatórios.

Trabalhos publicados sobre contact-discovery mostraram por que isso é operacionalmente importante: com tabelas precisas de prefixos telefônicos e recursos modestos, pesquisadores conseguiram consultar aproximadamente `10%` dos números móveis dos EUA no WhatsApp e `100%` no Signal antes de passar à sondagem direcionada.<sup>[[11]](#references)</sup> Na prática, filtrar primeiro as contas ativas mantém o orçamento de sondas silenciosas concentrado em números que realmente descriptografarão os pacotes.

Versões recentes do WhatsApp também expõem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trate isso como um limitador de throughput, não como uma correção: ele afeta principalmente flooding sustentado apenas por strangers e é irrelevante quando você já é um contato conhecido.

## Reciclagem de edições e exclusões como gatilhos encobertos

* **Exclusões repetidas:** Depois que uma mensagem é apagada para todos uma vez, outros pacotes de exclusão referenciando o mesmo `message_id` não têm efeito na UI, mas cada dispositivo ainda os descriptografa e confirma.
* **Operações fora da janela:** O WhatsApp impõe janelas de ~60 h para exclusão e ~20 min para edição na UI; o Signal impõe ~48 h. Mensagens de protocolo criadas fora dessas janelas são ignoradas silenciosamente no dispositivo da vítima, mas as confirmações são transmitidas, permitindo que os atacantes façam sondagens indefinidamente, muito depois do fim da conversa.
* **Payloads inválidos:** Corpos de edição malformados ou exclusões referentes a mensagens já removidas produzem o mesmo comportamento: descriptografia e confirmação, sem artefatos visíveis ao usuário.<sup>[[1]](#references)</sup>

## Amplificação e fingerprinting de múltiplos dispositivos

* Cada dispositivo associado (telefone, aplicativo desktop, companion de navegador) descriptografa a sonda independentemente e retorna seu próprio ack. Contar as confirmações por sonda revela a quantidade exata de dispositivos.
* Se um dispositivo estiver offline, sua confirmação será enfileirada e emitida ao reconectar. Portanto, as lacunas fazem leak dos ciclos online/offline e até dos horários de deslocamento (por exemplo, as confirmações do desktop param durante uma viagem).
* As distribuições de RTT diferem por plataforma devido ao gerenciamento de energia do sistema operacional e aos wakeups de push. Agrupe os RTTs (por exemplo, usando k-means sobre recursos de mediana/variância) para classificar “Android handset”, “iOS handset”, “Electron desktop” etc.
* Como o remetente precisa obter o inventário de chaves do destinatário antes de criptografar, o atacante também pode observar quando novos dispositivos são pareados; um aumento repentino na quantidade de dispositivos ou um novo cluster de RTT é um forte indicador.<sup>[[1]](#references)</sup>

## Cadência de amostragem, enfileiramento e confirmações acumuladas

* **Tolerância a bursts do WhatsApp:** Medições publicadas relataram que o WhatsApp aceitava bursts de reações silenciosas tão rápidos quanto uma sonda a cada `50 ms`, sem enfileiramento evidente no servidor. Isso é útil para bursts curtos de calibração, contagem rápida de dispositivos ou aumento veloz de um ataque de drenagem.
* **Enfileiramento prolongado no Signal:** O Signal tolerou bursts curtos, mas começou a enfileirar tráfego sustentado de várias sondas por segundo. Para monitoramento de longa duração, mantenha a cadência em torno de `1 Hz` (ou menor), para que cada confirmação ainda reflita o estado atual do dispositivo, em vez de drenar um backlog.
* **Artefatos de reconexão:** Quando um dispositivo volta a ficar online, alguns clientes agrupam ou descarregam rapidamente várias confirmações atrasadas. Trate esses bursts de confirmações como um marcador de transição de estado, não como amostras independentes de RTT; caso contrário, seu clustering / classificador `active` vs `idle` sofrerá overfitting com o ruído da reconexão.<sup>[[1]](#references)</sup>

## Inferência de comportamento a partir de rastreamentos de RTT

1. Faça amostragens a ≥1 Hz para capturar efeitos do agendamento do sistema operacional. Com o WhatsApp no iOS, RTTs <1 s apresentam forte correlação com tela ligada/primeiro plano, enquanto RTTs >1 s correspondem a limitação em tela desligada/segundo plano.
2. Crie classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue os rótulos em sequências para derivar horários de sono, deslocamentos, horários de trabalho ou quando o companion desktop está ativo.
3. Correlacione sondas simultâneas direcionadas a cada dispositivo para observar quando os usuários mudam do celular para o desktop, quando os companions ficam offline e se o aplicativo está sofrendo rate limiting por push ou por socket persistente.
4. Em redes reais, evite um limite fixo de `1 s`. Inicialize cada dispositivo com uma breve janela de aquecimento e mantenha uma baseline móvel (por exemplo, `threshold = 0.9 * median RTT`) para que variações de Wi-Fi/rede celular não destruam seu classificador.<sup>[[1]](#references)</sup>

## Inferência de localização a partir do RTT de entrega

A mesma primitiva de temporização pode ser reutilizada para inferir onde o destinatário está, e não apenas se ele está ativo. O trabalho `Hope of Delivery` mostrou que o treinamento com distribuições de RTT para localizações conhecidas permite que um atacante posteriormente classifique a localização da vítima apenas a partir das confirmações de entrega:<sup>[[2]](#references)</sup>

* Crie uma baseline para o mesmo alvo enquanto ele estiver em vários locais conhecidos (casa, escritório, campus, país A vs país B etc.).
* Para cada localização, colete muitos RTTs de mensagens normais e extraia recursos simples, como mediana, variância ou intervalos de percentis.
* Durante o ataque real, compare a nova série de sondas com os clusters treinados. O artigo relata que até mesmo localizações na mesma cidade podem frequentemente ser diferenciadas, com precisão `>80%` em um cenário com 3 localizações.
* Isso funciona melhor quando o atacante controla o ambiente do remetente e faz sondagens sob condições de rede semelhantes, pois o caminho medido inclui a rede de acesso do destinatário, a latência do wake-up e a infraestrutura do messenger.<sup>[[2]](#references)</sup>

Ao contrário dos ataques silenciosos de reação/edição/exclusão acima, a inferência de localização não exige IDs de mensagens inválidos nem pacotes furtivos que alterem o estado. Mensagens comuns com confirmações normais de entrega são suficientes; a contrapartida é menor stealth, mas aplicabilidade mais ampla entre messengers.

## Exaustão furtiva de recursos

Como cada sonda silenciosa precisa ser descriptografada e confirmada, o envio contínuo de alternâncias de reação, edições inválidas ou pacotes de apagar para todos cria um DoS na camada de aplicação:<sup>[[1]](#references)</sup>

* Força o rádio/modem a transmitir/receber a cada segundo → consumo perceptível de bateria, especialmente em aparelhos ociosos.
* Gera tráfego upstream/downstream não contabilizado que consome planos de dados móveis enquanto se mistura ao ruído de TLS/WebSocket.
* Ocupa threads de criptografia e introduz jitter em recursos sensíveis à latência (VoIP, chamadas de vídeo), mesmo que o usuário nunca veja notificações.
* No WhatsApp, reações inválidas aceitam muito mais dados do que um emoji normal sugere: medições publicadas encontraram aceitação no servidor de até aproximadamente `1 MB` por reação.
* Reações grandes deixam de produzir confirmações de entrega confiáveis quando o corpo ultrapassa aproximadamente `30 bytes`, mas ainda são encaminhadas e processadas antes do descarte. Mantenha os corpos das reações pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for drenagem pura ou transporte unidirecional encoberto.
* Medições públicas alcançaram cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego da vítima nesse modo.

## Referências

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
