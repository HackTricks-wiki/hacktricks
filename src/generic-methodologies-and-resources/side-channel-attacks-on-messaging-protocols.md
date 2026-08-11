# Ataques de Side-Channel de Recibos de Entrega em Mensageiros E2EE

{{#include ../banners/hacktricks-training.md}}

Os recibos de entrega são obrigatórios em mensageiros modernos com criptografia end-to-end (E2EE), porque os clientes precisam saber quando um ciphertext foi decriptado para poder descartar o estado do ratchet e as chaves efêmeras. O servidor encaminha blobs opacos, portanto os acknowledgements do dispositivo (duplas marcas de verificação) são emitidos pelo destinatário após a decriptação bem-sucedida. Medir o tempo de ida e volta (RTT) entre uma ação acionada pelo atacante e o recibo de entrega correspondente expõe um canal de temporização de alta resolução que vaza o estado do dispositivo e a presença online, além de poder ser abusado para DoS encoberto. Implantações "client-fanout" com múltiplos dispositivos amplificam o vazamento, porque cada dispositivo registrado decripta o probe e retorna seu próprio recibo.<sup>[[1]](#references)</sup>

## Fontes de recibos de entrega vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre emitam um recibo de entrega, mas não apresentem artefatos na UI da vítima. A tabela abaixo resume o comportamento confirmado empiricamente:<sup>[[1]](#references)</sup>

| Messenger | Ação | Recibo de entrega | Notificação da vítima | Observações |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensagem de texto | ● | ● | Sempre gera ruído → útil apenas para inicializar o estado. |
| | Reação | ● | ◐ (somente ao reagir à mensagem da vítima) | Auto-reações e remoções permanecem silenciosas. |
| | Edição | ● | Push silencioso dependente da plataforma | Janela de edição ≈20 min; ainda recebe ack após a expiração. |
| | Excluir para todos | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda recebem ack. |
| **Signal** | Mensagem de texto | ● | ● | Mesmas limitações do WhatsApp. |
| | Reação | ● | ◐ | Auto-reações são invisíveis para a vítima. |
| | Edição/Exclusão | ● | ○ | O servidor impõe uma janela de ~48 h e permite até 10 edições, mas pacotes tardios ainda recebem ack. |
| **Threema** | Mensagem de texto | ● | ● | Os recibos de múltiplos dispositivos são agregados, portanto apenas um RTT por probe se torna visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento da UI dependente da plataforma é indicado inline. Desative os recibos de leitura se necessário, mas os recibos de entrega não podem ser desativados no WhatsApp ou no Signal.<sup>[[1]](#references)</sup>

## Objetivos e modelos do atacante

* **G1 – Fingerprinting de dispositivos:** Conte quantos recibos chegam por probe, agrupe os RTTs para inferir o SO/cliente (Android vs iOS vs desktop) e observe transições online/offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTTs de alta frequência (≈1 Hz é estável) como uma série temporal e infira tela ligada/desligada, aplicativo em primeiro plano/segundo plano, horários de deslocamento versus trabalho etc.
* **G3 – Exaustão de recursos:** Mantenha rádios/CPUs de todos os dispositivos da vítima ativos enviando probes silenciosos intermináveis, drenando bateria/dados e degradando a qualidade de videochamadas.<sup>[[1]](#references)</sup>

Dois threat actors são suficientes para descrever a superfície de abuso:<sup>[[1]](#references)</sup>

1. **Creepy companion:** já compartilha um chat com a vítima e abusa de auto-reações, remoções de reações ou edições/exclusões repetidas vinculadas a IDs de mensagens existentes.
2. **Spooky stranger:** registra uma conta burner e envia reações referenciando IDs de mensagens que nunca existiram na conversa local; WhatsApp e Signal ainda decriptam e reconhecem essas mensagens, embora a UI descarte a alteração de estado, portanto nenhuma conversa anterior é necessária.

## Ferramentas para acesso ao protocolo raw

Use clientes que exponham o suficiente do protocolo E2EE subjacente para criar pacotes suportados fora das restrições da UI e registrar timestamps precisos; IDs de mensagens arbitrários exigem verificar cada implementação:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidevice do WhatsApp Web) documenta o envio e o recebimento de recibos de entrega; [Cobalt](https://github.com/Auties00/Cobalt) (API não oficial Java/Kotlin para Web e mobile) documenta operações de mensagens como reagir, editar e excluir. Use as APIs documentadas em vez de presumir que todo frame interno esteja exposto.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expõe interfaces CLI, JSON-RPC e D-Bus, enquanto [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) é uma biblioteca Java para comunicação com o Signal.<sup>[[5]](#references)[[7]](#references)</sup> A sintaxe atual do `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para que as atualizações do protocolo continuem sendo processadas.<sup>[[6]](#references)</sup> Exemplo de alternância de auto-reação:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** As medições do artigo Careless Whisper constataram que os recibos de entrega são sincronizados entre dispositivos, portanto apenas um recibo por mensagem é exposto mesmo em uma configuração com múltiplos dispositivos.<sup>[[1]](#references)</sup>
* **PoCs turnkey:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inclui backends de WhatsApp/Signal, usa probes silenciosos de exclusão por padrão e classifica `active` versus `standby` com um limite baseado na mediana móvel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é uma CLI mais leve, focada primeiro no WhatsApp, com `--delay`, `--concurrent`, exporters CSV/Prometheus e saída compatível com Grafana.<sup>[[9]](#references)</sup> Trate ambos como auxiliares de reconnaissance, não como referências de protocolo; o ponto importante é a pouca quantidade de código necessária quando existe acesso ao cliente raw.

Quando as ferramentas customizadas não estiverem disponíveis, clientes oficiais ou ferramentas de desenvolvedor do navegador ainda podem acionar ações silenciosas e expor a temporização do tráfego criptografado; APIs raw removem atrasos da UI e permitem operações inválidas.<sup>[[1]](#references)</sup>

## Creepy companion: loop de amostragem silencioso

1. Escolha qualquer mensagem histórica que você tenha enviado no chat para que a vítima nunca veja balões de "reação" mudarem.
2. Alterne entre um emoji visível e um payload de reação vazio (codificado como `""` nos protobufs do WhatsApp ou como `--remove` no signal-cli). Cada transmissão gera um ack do dispositivo apesar de não haver alteração na UI da vítima.
3. Registre o horário de envio e a chegada de cada recibo de entrega. Um loop de 1 Hz como o seguinte fornece traces de RTT por dispositivo indefinidamente:
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

1. Registre uma conta nova do WhatsApp/Signal e obtenha as chaves públicas de identidade do número-alvo (feito automaticamente durante a configuração da sessão).
2. Crie um pacote de reação que referencie um `message_id` aleatório nunca visto por nenhuma das partes; o artigo relata que WhatsApp e Signal aceitam essas reações e ainda geram recibos de entrega.<sup>[[1]](#references)</sup>
3. Envie o pacote mesmo que não exista uma thread. Os dispositivos da vítima o decriptam, não conseguem associá-lo à mensagem-base, descartam a alteração de estado, mas ainda reconhecem o ciphertext recebido, enviando recibos do dispositivo de volta ao atacante.
4. Repita continuamente para criar séries de RTT sem uma conversa anterior ou uma notificação visível.<sup>[[1]](#references)</sup>

Se primeiro precisar descobrir quais números estão registrados ou quiser pré-popular inventários de dispositivos em escala, encadeie isto com [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar manualmente intervalos aleatórios de E.164.

Trabalhos publicados sobre contact-discovery mostraram por que isso é operacionalmente importante: com tabelas precisas de prefixos telefônicos e recursos modestos, pesquisadores conseguiram consultar aproximadamente `10%` dos números móveis dos EUA no WhatsApp e `100%` no Signal antes de prosseguir para a sondagem direcionada.<sup>[[11]](#references)</sup> Na prática, filtrar primeiro as contas ativas mantém o orçamento de silent probes concentrado nos números que realmente decriptarão os pacotes.

Versões recentes do WhatsApp também expõem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trate isso como um limitador de throughput: a documentação do tracker afirma que o WhatsApp bloqueia grandes volumes de mensagens de contas desconhecidas, mas não divulga o limite; portanto, isso não impede completamente as reações de sondagem.<sup>[[8]](#references)</sup>

## Reciclagem de edições e exclusões como gatilhos encobertos

* **Exclusões repetidas:** Depois que uma mensagem é excluída para todos uma vez, pacotes de exclusão posteriores referenciando o mesmo `message_id` não têm efeito na UI, mas todos os dispositivos ainda os decriptam e reconhecem.
* **Operações fora da janela:** O WhatsApp impõe janelas de ~60 h para exclusão / ~20 min para edição na UI; o Signal impõe ~48 h. Mensagens de protocolo criadas fora dessas janelas são silenciosamente ignoradas no dispositivo da vítima, mas os recibos são transmitidos, permitindo que os atacantes façam sondagens indefinidamente muito depois do fim da conversa.
* **Payloads inválidos:** O artigo relata que mensagens inválidas ainda podem ser reconhecidas; o comportamento exato para corpos malformados ou IDs removidos depende da implementação, portanto teste antes de confiar nisso.<sup>[[1]](#references)</sup>

## Amplificação e fingerprinting de múltiplos dispositivos

* No WhatsApp e no Signal, cada dispositivo associado (telefone, aplicativo desktop, companion do navegador) decripta o probe de forma independente e retorna seu próprio ack. Contar os recibos por probe revela a quantidade exata de dispositivos.<sup>[[1]](#references)</sup>
* Se um dispositivo estiver offline, seu recibo fica enfileirado e é emitido após a reconexão. Portanto, as lacunas vazam ciclos online/offline e até horários de deslocamento (por exemplo, os recibos do desktop param durante viagens).
* As distribuições de RTT diferem por plataforma e ambiente, porque o SO, o modelo, o cliente e as condições de rede afetam a temporização. Agrupe os RTTs (por exemplo, k-means sobre recursos de mediana/variância) para classificar “Android handset", “iOS handset", “Electron desktop" etc.
* Como o remetente precisa obter o inventário de chaves do destinatário antes de criptografar, o atacante também pode observar quando novos dispositivos são associados; um aumento repentino na quantidade de dispositivos ou um novo cluster de RTT é um forte indicador.<sup>[[1]](#references)</sup>

## Cadência de amostragem, enfileiramento e recibos acumulados

* **Tolerância a bursts do WhatsApp:** Medições publicadas relataram que o WhatsApp aceitou bursts de reações silenciosas tão rápidos quanto um probe a cada `50 ms` sem enfileiramento óbvio no servidor. Isso é útil para bursts curtos de calibração, contagem rápida de dispositivos ou aumento rápido de um drain attack.
* **Enfileiramento de longo prazo no Signal:** O Signal tolerou bursts curtos, mas começou a enfileirar tráfego sustentado de vários probes por segundo. Para monitoramento de longa duração, mantenha a cadência em torno de `1 Hz` (ou menor) para que cada recibo ainda reflita o estado atual do dispositivo, em vez de drenar um backlog.
* **Artefatos de reconexão:** Quando um dispositivo volta a ficar online, alguns clientes agrupam ou descarregam rapidamente vários recibos atrasados. Trate esses bursts de recibos como um marcador de transição de estado, não como amostras independentes de RTT; caso contrário, seu clustering / classificador `active` versus `idle` fará overfitting ao ruído da reconexão.<sup>[[1]](#references)</sup>

## Inferência comportamental a partir de traces de RTT

1. Faça amostragens a ≥1 Hz para capturar efeitos do agendamento do SO. Com o WhatsApp no iOS, RTTs <1 s têm forte correlação com tela ligada/primeiro plano, enquanto >1 s se correlacionam com tela desligada/segundo plano e throttling.
2. Crie classificadores simples (thresholding ou k-means de dois clusters) que rotulem cada RTT como "active" ou "idle". Agregue os rótulos em sequências para derivar horários de sono, deslocamentos, horas de trabalho ou quando o companion desktop está ativo.
3. Correlacione probes simultâneos direcionados a cada dispositivo para observar quando os usuários mudam do mobile para o desktop, quando companions ficam offline e se o aplicativo está limitado por push ou por socket persistente.
4. Em redes reais, evite um único limite fixo de `1 s`. Faça o bootstrap de cada dispositivo com uma breve janela de aquecimento e mantenha uma baseline móvel (por exemplo, a PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) para que variações de Wi-Fi/celular não destruam seu classificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferência de localização a partir do RTT de entrega

A mesma primitiva de temporização pode ser reutilizada para inferir onde o destinatário está, não apenas se está ativo. O trabalho `Hope of Delivery` mostrou que treinar sobre distribuições de RTT para localizações conhecidas do receptor permite que um atacante classifique posteriormente a localização da vítima apenas a partir das confirmações de entrega:<sup>[[2]](#references)</sup>

* Crie uma baseline para o mesmo alvo enquanto ele estiver em vários locais conhecidos (casa, escritório, campus, país A versus país B etc.).
* Para cada localização, colete muitos RTTs de mensagens normais e extraia recursos simples, como mediana, variância ou buckets de percentis.
* Durante o ataque real, compare a nova série de probes com os clusters treinados. O artigo relata que até localizações dentro da mesma cidade podem frequentemente ser separadas, com precisão `>80%` em um cenário com 3 localizações.
* Isso funciona melhor quando o atacante controla o ambiente do remetente e faz os probes sob condições de rede semelhantes, porque o caminho medido inclui a rede de acesso do destinatário, a latência de wake-up e a infraestrutura do messenger.<sup>[[2]](#references)</sup>

Diferentemente dos ataques silenciosos de reação/edição/exclusão acima, a inferência de localização não exige IDs de mensagens inválidos nem pacotes furtivos que alterem o estado. Mensagens comuns com confirmações normais de entrega são suficientes, portanto o trade-off é menor stealth, mas aplicabilidade mais ampla entre messengers.

## Exaustão furtiva de recursos

Como todo probe silencioso precisa ser decriptado e reconhecido, o envio contínuo de alternâncias de reação, edições inválidas ou pacotes de exclusão para todos cria um DoS na camada de aplicação:<sup>[[1]](#references)</sup>

* Força o rádio/modem a transmitir/receber a cada segundo → dreno perceptível de bateria, especialmente em handsets ociosos.
* Gera tráfego upstream/downstream que consome planos de dados móveis e pode competir com recursos sensíveis à latência, como videochamadas.<sup>[[1]](#references)</sup>
* Payloads inválidos grandes adicionam trabalho de processamento, mas o artigo relata que a criptografia em si representa uma parte insignificante do custo de bateria.<sup>[[1]](#references)</sup>
* No WhatsApp, reações inválidas aceitam muito mais dados do que um emoji normal sugere: medições publicadas constataram aceitação no servidor de até aproximadamente `1 MB` por reação.
* Reações oversized deixam de produzir recibos de entrega confiáveis quando o corpo ultrapassa aproximadamente `30 bytes`, mas ainda são encaminhadas e processadas antes do descarte. Mantenha os corpos das reações pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for drenagem pura ou transporte encoberto unidirecional.
* Medições públicas alcançaram cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego da vítima nesse modo.

## References

- [1] [Sussurro descuidado: explorando recibos de entrega silenciosos para monitorar usuários em mensageiros instantâneos móveis](https://arxiv.org/html/2411.11194v4)
- [2] [Esperança de entrega: extraindo localizações de usuários a partir de mensageiros instantâneos móveis](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [página de manual do signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Como bloquear grandes volumes de mensagens desconhecidas | Central de Ajuda do WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Todos os números são dos EUA: abuso em larga escala da descoberta de contatos em mensageiros móveis](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
