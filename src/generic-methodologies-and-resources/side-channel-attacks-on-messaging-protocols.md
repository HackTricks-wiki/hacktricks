# Ataques Side-Channel de Recibos de Entrega em Messengers E2EE

Os recibos de entrega são obrigatórios nos messengers modernos com criptografia ponta a ponta (E2EE), porque os clientes precisam saber quando um ciphertext foi descriptografado para poder descartar o estado do ratchet e as chaves efêmeras. O servidor encaminha blobs opacos, portanto os acknowledgements dos dispositivos (duplas marcas de verificação) são emitidos pelo destinatário após a descriptografia bem-sucedida. Medir o tempo de ida e volta (RTT) entre uma ação acionada pelo atacante e o recibo de entrega correspondente expõe um canal de temporização de alta resolução que vaza o estado do dispositivo e a presença online, podendo ser abusado para DoS encoberto. Implantações multi-device do tipo "client-fanout" ampliam o vazamento, porque cada dispositivo registrado descriptografa o probe e retorna seu próprio recibo.<sup>[[1]](#references)</sup>

## Fontes de recibos de entrega vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitam um recibo de entrega, mas não exibam artefatos de UI para a vítima. A tabela abaixo resume o comportamento confirmado empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Ação | Recibo de entrega | Notificação da vítima | Observações |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensagem de texto | ● | ● | Sempre gera ruído → útil apenas para inicializar o estado. |
| | Reaction | ● | ◐ (apenas ao reagir à mensagem da vítima) | Self-reactions e remoções permanecem silenciosas. |
| | Edit | ● | Push silencioso dependente da plataforma | Janela de edição ≈20 min; ainda recebe ack após a expiração. |
| | Delete for everyone | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda recebem ack. |
| **Signal** | Mensagem de texto | ● | ● | Mesmas limitações do WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions são invisíveis para a vítima. |
| | Edit/Delete | ● | ○ | O servidor aplica uma janela de ~48 h e permite até 10 edições, mas pacotes atrasados ainda recebem ack. |
| **Threema** | Mensagem de texto | ● | ● | Os recibos multi-device são agregados, portanto apenas um RTT por probe fica visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento da UI dependente da plataforma é indicado inline. Desative os read receipts se necessário, mas os recibos de entrega não podem ser desativados no WhatsApp ou no Signal.<sup>[[1]](#references)</sup>

## Objetivos e modelos do atacante

* **G1 – Device fingerprinting:** Conte quantos recibos chegam por probe, agrupe RTTs para inferir o OS/cliente (Android vs iOS vs desktop) e observe transições online/offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTTs de alta frequência (≈1 Hz é estável) como uma série temporal e infira tela ligada/desligada, app em foreground/background, horários de deslocamento vs trabalho etc.
* **G3 – Esgotamento de recursos:** Mantenha os rádios/CPUs de todos os dispositivos da vítima ativos enviando probes silenciosos intermináveis, consumindo bateria/dados e degradando a qualidade de videochamadas.<sup>[[1]](#references)</sup>

Dois threat actors são suficientes para descrever a superfície de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de self-reactions, remoções de reactions ou edições/deleções repetidas vinculadas a IDs de mensagens existentes.
2. **Spooky stranger:** registra uma conta descartável e envia reactions referenciando IDs de mensagens que nunca existiram na conversa local; WhatsApp e Signal ainda as descriptografam e confirmam, mesmo que a UI descarte a mudança de estado, portanto nenhuma conversa anterior é necessária.

## Tooling para acesso ao protocolo bruto

Dependa de clientes que exponham uma parte suficiente do protocolo E2EE subjacente para criar pacotes suportados fora das restrições da UI e registrar timestamps precisos; IDs de mensagens arbitrários exigem a verificação de cada implementação:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multi-device do WhatsApp Web) documenta o envio e o recebimento de recibos de entrega; [Cobalt](https://github.com/Auties00/Cobalt) (API não oficial Java/Kotlin para Web e mobile) documenta operações de mensagens como reagir, editar e deletar. Use as APIs documentadas em vez de presumir que cada frame interno esteja exposto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expõe interfaces CLI, JSON-RPC e D-Bus, enquanto [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) é uma biblioteca Java para comunicação com o Signal.<sup>[[5]](#references)[[7]](#references)</sup> A sintaxe atual do `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para que as atualizações do protocolo continuem sendo processadas.<sup>[[6]](#references)</sup> Exemplo de alternância de self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** As medições do paper Careless Whisper constataram que os recibos de entrega são sincronizados entre dispositivos, portanto apenas um recibo por mensagem é exposto mesmo em uma configuração multi-device.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inclui backends para WhatsApp/Signal, usa probes silenciosos de deleção por padrão e classifica `active` vs `standby` com um limiar de mediana móvel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é uma CLI mais leve, focada primeiro no WhatsApp, com `--delay`, `--concurrent`, exporters CSV/Prometheus e saída compatível com Grafana.<sup>[[9]](#references)</sup> Trate ambos como auxiliares de reconnaissance, não como referências de protocolo; o ponto importante é quão pouco código é necessário quando existe acesso bruto ao cliente.

Quando o tooling personalizado não estiver disponível, clientes oficiais ou ferramentas de desenvolvedor do navegador ainda podem acionar ações silenciosas e expor a temporização do tráfego criptografado; APIs brutas removem atrasos da UI e permitem operações inválidas.<sup>[[1]](#references)</sup>

## Creepy companion: loop de amostragem silenciosa

1. Escolha qualquer mensagem histórica que você tenha escrito no chat, para que a vítima nunca veja os balões de "reaction" mudarem.
2. Alterne entre um emoji visível e um payload de reaction vazio (codificado como `""` nos protobufs do WhatsApp ou como `--remove` no signal-cli). Cada transmissão produz um ack do dispositivo, apesar de não haver alteração na UI da vítima.
3. Registre o horário de envio e a chegada de cada recibo de entrega. Um loop de 1 Hz como o seguinte fornece traces de RTT por dispositivo indefinidamente:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Como WhatsApp/Signal aceitam atualizações ilimitadas de reactions, o atacante nunca precisa publicar novo conteúdo no chat nem se preocupar com janelas de edição.<sup>[[1]](#references)</sup>

## Spooky stranger: sondagem de números de telefone arbitrários

1. Registre uma nova conta do WhatsApp/Signal e obtenha as chaves públicas de identidade do número-alvo (isso é feito automaticamente durante a configuração da sessão).
2. Crie um pacote de reaction que referencie um `message_id` aleatório nunca visto por nenhuma das partes; o paper informa que WhatsApp e Signal aceitam essas reactions e ainda geram recibos de entrega.<sup>[[1]](#references)</sup>
3. Envie o pacote mesmo que não exista uma thread. Os dispositivos da vítima o descriptografam, não conseguem associá-lo à mensagem base, descartam a mudança de estado, mas ainda confirmam o ciphertext recebido, enviando recibos dos dispositivos de volta ao atacante.
4. Repita continuamente para criar séries de RTT sem uma conversa anterior ou notificação visível.<sup>[[1]](#references)</sup>

Se primeiro precisar descobrir quais números estão registrados ou quiser pré-carregar inventários de dispositivos em escala, encadeie isso com [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar manualmente intervalos aleatórios de E.164.

Trabalhos publicados sobre contact-discovery mostraram por que isso é operacionalmente importante: com tabelas precisas de prefixos telefônicos e recursos modestos, pesquisadores conseguiram consultar aproximadamente `10%` dos números móveis dos EUA no WhatsApp e `100%` no Signal antes de passar à sondagem direcionada.<sup>[[11]](#references)</sup> Na prática, filtrar primeiro as contas ativas mantém o orçamento de silent probes concentrado nos números que realmente descriptografarão os pacotes.

Versões recentes do WhatsApp também expõem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trate isso como um limitador de throughput: a documentação do tracker informa que o WhatsApp bloqueia mensagens em alto volume de contas desconhecidas, mas não divulga o limiar; portanto, isso não impede totalmente as probe reactions.<sup>[[8]](#references)</sup>

## Reciclagem de edits e deletes como gatilhos encobertos

* **Deleções repetidas:** Depois que uma mensagem é deletada para todos uma vez, pacotes adicionais de deleção que referenciem o mesmo `message_id` não têm efeito na UI, mas cada dispositivo ainda os descriptografa e confirma.
* **Operações fora da janela:** O WhatsApp aplica janelas de ~60 h para deleção / ~20 min para edição na UI; o Signal aplica ~48 h. Mensagens de protocolo criadas fora dessas janelas são ignoradas silenciosamente no dispositivo da vítima, mas os recibos são transmitidos; assim, os atacantes podem sondar indefinidamente muito depois do fim da conversa.
* **Payloads inválidos:** O paper informa que mensagens inválidas ainda podem ser confirmadas; o comportamento exato para corpos malformados ou IDs expurgados depende da implementação, portanto teste antes de depender disso.<sup>[[1]](#references)</sup>

## Amplificação multi-device e fingerprinting

* No WhatsApp e no Signal, cada dispositivo associado (telefone, app desktop, companion de navegador) descriptografa o probe independentemente e retorna seu próprio ack. Contar os recibos por probe revela a quantidade exata de dispositivos.<sup>[[1]](#references)</sup>
* Se um dispositivo estiver offline, seu recibo será enfileirado e emitido ao reconectar. As lacunas, portanto, vazam ciclos online/offline e até rotinas de deslocamento (por exemplo, os recibos do desktop param durante uma viagem).
* As distribuições de RTT diferem por plataforma e ambiente, porque OS, modelo, cliente e condições de rede afetam a temporização. Agrupe os RTTs (por exemplo, k-means sobre recursos de mediana/variância) para rotular “aparelho Android”, “aparelho iOS”, “desktop Electron” etc.
* Como o remetente precisa obter o inventário de chaves do destinatário antes de criptografar, o atacante também pode observar quando novos dispositivos são associados; um aumento repentino na quantidade de dispositivos ou um novo cluster de RTT é um forte indicador.<sup>[[1]](#references)</sup>

## Cadência de amostragem, enfileiramento e recibos acumulados

* **Tolerância a bursts do WhatsApp:** Medições publicadas informaram que o WhatsApp aceitava bursts de silent reactions de até um probe a cada `50 ms` sem enfileiramento evidente no servidor. Isso é útil para bursts curtos de calibração, contagem rápida de dispositivos ou aumento veloz de um drain attack.
* **Enfileiramento de longa duração no Signal:** O Signal tolerou bursts curtos, mas começou a enfileirar tráfego sustentado de vários probes por segundo. Para monitoramento de longa duração, mantenha a cadência próxima de `1 Hz` (ou inferior), para que cada recibo ainda reflita o estado atual do dispositivo em vez de drenar um backlog.
* **Artefatos de reconexão:** Quando um dispositivo volta a ficar online, alguns clientes agrupam ou liberam rapidamente vários recibos atrasados. Trate esses bursts de recibos como marcadores de transição de estado, não como amostras independentes de RTT; caso contrário, seu clustering / classificador `active` vs `idle` sofrerá overfitting devido ao ruído de reconexão.<sup>[[1]](#references)</sup>

## Inferência de comportamento a partir de traces de RTT

1. Faça amostras a ≥1 Hz para capturar efeitos do agendamento do OS. No WhatsApp para iOS, RTTs <1 s têm forte correlação com tela ligada/foreground, enquanto RTTs >1 s correspondem a throttling de tela desligada/background.
2. Crie classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue os rótulos em sequências para obter horários de sono, deslocamentos, horas de trabalho ou períodos em que o companion desktop está ativo.
3. Correlacione probes simultâneos direcionados a cada dispositivo para observar quando os usuários alternam do mobile para o desktop, quando os companions ficam offline e se o app sofre rate limiting por push ou socket persistente.
4. Em redes reais, evite um único limiar fixo de `1 s`. Inicialize cada dispositivo com uma breve janela de aquecimento e mantenha uma baseline móvel (por exemplo, a PoC device-activity-tracker usa `threshold = 0.9 * median RTT`), para que a variação entre Wi-Fi/celular não invalide seu classificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferência de localização a partir do RTT de entrega

A mesma primitiva de temporização pode ser reutilizada para inferir onde o destinatário está, não apenas se está ativo. O trabalho `Hope of Delivery` mostrou que o treinamento com distribuições de RTT para localizações conhecidas do receptor permite que um atacante classifique posteriormente a localização da vítima apenas pelas confirmações de entrega:<sup>[[2]](#references)</sup>

* Crie uma baseline para o mesmo alvo enquanto ele estiver em vários locais conhecidos (casa, escritório, campus, país A vs país B etc.).
* Para cada localização, colete muitos RTTs de mensagens normais e extraia recursos simples, como mediana, variância ou buckets de percentis.
* Durante o ataque real, compare a nova série de probes com os clusters treinados. O paper informa que até localizações na mesma cidade podem frequentemente ser separadas, com precisão `>80%` em uma configuração com 3 localizações.
* Isso funciona melhor quando o atacante controla o ambiente do remetente e faz probes sob condições de rede semelhantes, porque o caminho medido inclui a rede de acesso do destinatário, a latência de wake-up e a infraestrutura do messenger.<sup>[[2]](#references)</sup>

Diferentemente dos ataques silenciosos de reaction/edit/delete acima, a inferência de localização não exige IDs de mensagens inválidos nem pacotes furtivos que alterem o estado. Mensagens comuns com confirmações normais de entrega são suficientes; o tradeoff é menor stealth, mas maior aplicabilidade entre messengers.

## Esgotamento furtivo de recursos

Como todo silent probe precisa ser descriptografado e confirmado, o envio contínuo de alternâncias de reactions, edits inválidos ou pacotes de delete-for-everyone cria um DoS na camada de aplicação:<sup>[[1]](#references)</sup>

* Força o rádio/modem a transmitir/receber a cada segundo → consumo perceptível de bateria, especialmente em aparelhos ociosos.
* Gera tráfego upstream/downstream que consome planos de dados móveis e pode competir com recursos sensíveis à latência, como videochamadas.<sup>[[1]](#references)</sup>
* Payloads inválidos maiores adicionam trabalho de processamento, mas o paper informa que a criptografia em si representa uma parte insignificante do custo de bateria.<sup>[[1]](#references)</sup>
* No WhatsApp, reactions inválidas aceitam muito mais dados do que um emoji normal sugere: medições publicadas constataram aceitação no servidor de até aproximadamente `1 MB` por reaction.
* Reactions grandes deixam de produzir recibos de entrega confiáveis quando o corpo ultrapassa aproximadamente `30 bytes`, mas ainda são encaminhadas e processadas antes do descarte. Mantenha os corpos das reactions pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for puro drain ou transporte encoberto unidirecional.
* Medições públicas alcançaram cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego da vítima nesse modo.

## References

- [1] [Careless Whisper: Explorando recibos de entrega silenciosos para monitorar usuários em Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extraindo localizações de usuários a partir de Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Página de manual do signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Como bloquear grandes volumes de mensagens desconhecidas | Central de Ajuda do WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos os números são dos EUA: abuso em larga escala do Contact Discovery em Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
