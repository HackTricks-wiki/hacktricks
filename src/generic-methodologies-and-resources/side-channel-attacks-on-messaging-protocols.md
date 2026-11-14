# Ataques de Side-Channel por Confirmações de Entrega em Mensageiros E2EE

{{#include ../banners/hacktricks-training.md}}

As confirmações de entrega são obrigatórias nos mensageiros modernos com criptografia ponta a ponta (E2EE), pois os clientes precisam saber quando um ciphertext foi descriptografado para poder descartar o estado de ratcheting e as chaves efêmeras. O servidor encaminha blobs opacos, então os dispositivos do destinatário enviam confirmações (dois tiques) após a descriptografia bem-sucedida. Medir o tempo de ida e volta (RTT) entre uma ação iniciada pelo atacante e a confirmação de entrega correspondente expõe um canal temporal de alta resolução que vaza o estado do dispositivo e a presença online, podendo também ser abusado para DoS encoberto. Implantações com vários dispositivos e “client-fanout” ampliam o leak, pois cada dispositivo registrado descriptografa a probe e retorna sua própria confirmação.<sup>[[1]](#references)</sup>

## Fontes de confirmações de entrega vs. sinais visíveis ao usuário

Escolha tipos de mensagem que sempre gerem uma confirmação de entrega, mas não criem artefatos de UI para a vítima. A tabela abaixo resume o comportamento confirmado empiricamente:<sup>[[1]](#references)</sup>

| Mensageiro | Ação | Confirmação de entrega | Notificação à vítima | Observações |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Mensagem de texto | ● | ● | Sempre gera ruído → útil apenas para inicializar o estado. |
| | Reação | ● | ◐ (somente ao reagir a uma mensagem da vítima) | Auto-reações e remoções permanecem silenciosas. |
| | Edição | ● | Push silencioso, dependendo da plataforma | Janela de edição ≈20 min; ainda recebe confirmação após o prazo. |
| | Apagar para todos | ● | ○ | A UI permite ~60 h, mas pacotes posteriores ainda recebem confirmação. |
| **Signal** | Mensagem de texto | ● | ● | Mesmas limitações do WhatsApp. |
| | Reação | ● | ◐ | Auto-reações são invisíveis para a vítima. |
| | Editar/Apagar | ● | ○ | O servidor impõe uma janela de ~48 h e permite até 10 edições, mas pacotes tardios ainda recebem confirmação. |
| **Threema** | Mensagem de texto | ● | ● | As confirmações de vários dispositivos são agregadas, então apenas um RTT por probe fica visível. |

Legenda: ● = sempre, ◐ = condicional, ○ = nunca. O comportamento da UI que depende da plataforma é indicado nas observações. Desative as confirmações de leitura se necessário, mas as confirmações de entrega não podem ser desativadas no WhatsApp ou no Signal.<sup>[[1]](#references)</sup>

## Objetivos e modelos do atacante

* **G1 – Fingerprinting de dispositivos:** Conte quantas confirmações chegam por probe, agrupe os RTTs para inferir o sistema operacional/cliente (Android vs iOS vs desktop) e observe transições entre online e offline.
* **G2 – Monitoramento comportamental:** Trate a série de RTTs de alta frequência (≈1 Hz é estável) como uma série temporal e infira se a tela está ligada/desligada, se o app está em primeiro plano/segundo plano, horários de deslocamento vs trabalho etc.
* **G3 – Esgotamento de recursos:** Mantenha os rádios/CPUs de todos os dispositivos da vítima ativos enviando probes silenciosas sem fim, consumindo bateria/dados e degradando a qualidade das chamadas de vídeo.<sup>[[1]](#references)</sup>

Dois tipos de agentes de ameaça são suficientes para descrever a superfície de abuso:<sup>[[1]](#references)</sup>

1. **Companheiro sinistro:** já compartilha um chat com a vítima e abusa de auto-reações, remoções de reação ou edições/exclusões repetidas vinculadas a IDs de mensagens existentes.
2. **Estranho sinistro:** registra uma conta burner e envia reações que fazem referência a IDs de mensagens que nunca existiram na conversa local; o WhatsApp e o Signal ainda as descriptografam e confirmam, mesmo que a UI descarte a alteração de estado, portanto não é necessária uma conversa prévia.

## Ferramentas para acesso bruto ao protocolo

Use clientes que exponham o suficiente do protocolo E2EE subjacente para criar pacotes compatíveis fora das restrições da UI e registrar timestamps precisos; IDs de mensagem arbitrários exigem verificar cada implementação:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, API multidevice do WhatsApp Web) documenta o envio e o recebimento de confirmações de entrega; [Cobalt](https://github.com/Auties00/Cobalt) (API não oficial para Web e dispositivos móveis em Java/Kotlin) documenta operações de mensagem, como reagir, editar e apagar. Use as APIs documentadas em vez de presumir que todos os frames internos estão expostos.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) expõe interfaces CLI, JSON-RPC e D-Bus, enquanto [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) é uma biblioteca Java para comunicação com o Signal.<sup>[[5]](#references)[[7]](#references)</sup> A sintaxe atual de `signal-cli` usa `sendReaction RECIPIENT --target-author --target-timestamp`; mantenha `receive` ou `daemon` em execução para continuar processando as atualizações do protocolo.<sup>[[6]](#references)</sup> Exemplo de alternância de auto-reação:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** As medições no artigo Careless Whisper constataram que os comprovantes de entrega são sincronizados entre dispositivos, portanto apenas um comprovante por mensagem é exposto mesmo em uma configuração com vários dispositivos.<sup>[[1]](#references)</sup>
* **PoCs prontas para uso:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) inclui backends para WhatsApp/Signal, usa probes de exclusão silenciosa por padrão e classifica como `active` ou `standby` com um limite baseado na mediana móvel (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) é uma CLI mais leve, voltada primeiro para WhatsApp, com `--delay`, `--concurrent`, exportadores CSV/Prometheus e saída compatível com Grafana.<sup>[[9]](#references)</sup> Trate ambas como ferramentas auxiliares de reconhecimento, não como referências de protocolo; o principal a reter é quão pouco código é necessário quando há acesso direto ao cliente.

Quando ferramentas personalizadas não estão disponíveis, clientes oficiais ou ferramentas de desenvolvedor do navegador ainda podem disparar ações silenciosas e expor a temporização do tráfego criptografado; APIs brutas removem atrasos da interface e permitem operações inválidas.<sup>[[1]](#references)</sup>

## Companheiro assustador: loop de amostragem silenciosa

1. Escolha qualquer mensagem antiga que você tenha escrito no chat, para que a vítima nunca veja as bolhas de "reação" mudarem.
2. Alterne entre um emoji visível e um payload de reação vazio (codificado como `""` nos protobufs do WhatsApp ou como `--remove` no signal-cli). Cada transmissão gera um ack do dispositivo, apesar de não haver mudança na interface visível para a vítima.
3. Registre o horário do envio e a chegada de cada comprovante de entrega. Um loop de 1 Hz, como o seguinte, fornece rastros de RTT por dispositivo indefinidamente:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Como o WhatsApp/Signal aceita atualizações ilimitadas de reações, o atacante nunca precisa publicar novo conteúdo no chat nem se preocupar com janelas de edição.<sup>[[1]](#references)</sup>

## Estranho misterioso: sondando números de telefone arbitrários

1. Registre uma conta nova no WhatsApp/Signal e obtenha as chaves de identidade públicas do número-alvo (isso é feito automaticamente durante a configuração da sessão).
2. Crie um pacote de reação que faça referência a um `message_id` aleatório, nunca visto por nenhuma das partes; o artigo relata que tanto o WhatsApp quanto o Signal aceitam essas reações e ainda geram recibos de entrega.<sup>[[1]](#references)</sup>
3. Envie o pacote mesmo que não exista uma conversa. Os dispositivos da vítima o descriptografam, não conseguem encontrar a mensagem-base, descartam a alteração de estado, mas ainda confirmam o recebimento do texto cifrado, enviando recibos do dispositivo de volta ao atacante.
4. Repita continuamente para criar séries de RTT sem uma conversa prévia ou notificação visível.<sup>[[1]](#references)</sup>

Se primeiro precisar descobrir quais números estão registrados ou quiser pré-carregar inventários de dispositivos em escala, encadeie isso com [descoberta de contatos / oráculos de registro](../pentesting-web/registration-vulnerabilities.md) em vez de adivinhar manualmente intervalos aleatórios de E.164.

Pesquisas publicadas sobre descoberta de contatos mostraram a importância disso na prática: com tabelas precisas de prefixos telefônicos e recursos modestos, pesquisadores conseguiram consultar cerca de `10%` dos números de celular dos EUA no WhatsApp e `100%` no Signal antes de passar à sondagem direcionada.<sup>[[11]](#references)</sup> Na prática, filtrar primeiro as contas ativas mantém seu orçamento de sondagens silenciosas focado em números que realmente descriptografarão os pacotes.

Versões recentes do WhatsApp também oferecem `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Trate isso como um limitador de vazão: a documentação do rastreador informa que o WhatsApp bloqueia mensagens em alto volume de contas desconhecidas, mas não divulga o limite, portanto isso não impede totalmente as reações de sondagem.<sup>[[8]](#references)</sup>

## Reciclagem de edições e exclusões como gatilhos encobertos

* **Exclusões repetidas:** Depois que uma mensagem é excluída para todos, novos pacotes de exclusão que façam referência ao mesmo `message_id` não têm efeito na interface, mas todos os dispositivos ainda os descriptografam e confirmam o recebimento.
* **Operações fora da janela:** O WhatsApp impõe janelas de ~60 h para exclusão e ~20 min para edição na interface; o Signal impõe ~48 h. Mensagens de protocolo criadas fora dessas janelas são ignoradas silenciosamente no dispositivo da vítima, mas os recibos ainda são transmitidos, permitindo que os atacantes sondem indefinidamente, muito depois do fim da conversa.
* **Payloads inválidos:** O artigo relata que mensagens inválidas ainda podem ser confirmadas; o comportamento exato para corpos malformados ou IDs removidos depende da implementação, portanto teste antes de confiar nisso.<sup>[[1]](#references)</sup>

## Amplificação multi-dispositivo e fingerprinting

* No WhatsApp e no Signal, cada dispositivo associado (telefone, aplicativo para desktop, navegador companheiro) descriptografa a sondagem de forma independente e retorna seu próprio ACK. Contar os recibos por sondagem revela o número exato de dispositivos.<sup>[[1]](#references)</sup>
* Se um dispositivo estiver offline, seu recibo fica na fila e é enviado quando ele se reconectar. Portanto, as lacunas revelam ciclos online/offline e até horários de deslocamento (por exemplo, os recibos do desktop param durante viagens).
* As distribuições de RTT diferem conforme a plataforma e o ambiente, pois o sistema operacional, o modelo, o cliente e as condições da rede afetam o tempo. Agrupe os RTTs (por exemplo, com k-means sobre recursos de mediana/variância) para classificar “aparelho Android”, “aparelho iOS”, “desktop Electron” etc.
* Como o remetente precisa obter o inventário de chaves do destinatário antes de criptografar, o atacante também pode observar quando novos dispositivos são pareados; um aumento repentino na quantidade de dispositivos ou um novo agrupamento de RTT é um forte indicador.<sup>[[1]](#references)</sup>

**Fingerprinting a partir de recibos enfileirados:** Envie várias sondagens com IDs de mensagem distintos enquanto o dispositivo-alvo estiver offline. Quando ele se reconectar, correlacione os IDs nos recibos de entrega retornados e verifique se eles vêm separados ou agrupados em um único recibo, e se os IDs agrupados mantêm ou invertem a ordem de envio. Nos clientes testados, o WhatsApp para Android/iOS retornou recibos de entrega separados, enquanto Web, Windows e macOS os agrupou; o macOS inverteu a ordem dos IDs agrupados. O Signal Desktop agrupou os recibos, ao contrário de seus clientes móveis. Isso pode classificar um cliente que está se reconectando mesmo quando as distribuições de RTT se sobrepõem. Não confunda recibos de entrega com recibos de leitura, cujas regras de agrupamento são diferentes.<sup>[[1]](#references)</sup>

Para uma sondagem distinta do WhatsApp que lê **recargas de prekey do lado do servidor** sem entregar mensagens, consulte [Esgotamento do pacote de prekeys e canal lateral de recarga](whatsapp-prekey-bundle-side-channel.md).

## Cadência de amostragem, enfileiramento e recibos agrupados

* **Tolerância do WhatsApp a rajadas:** Medições publicadas relataram que o WhatsApp aceitou rajadas de reações silenciosas de até uma sondagem a cada `50 ms`, sem enfileiramento evidente do lado do servidor. Isso é útil para breves rajadas de calibração, contagem rápida de dispositivos ou para acelerar um ataque de esgotamento.
* **Enfileiramento prolongado no Signal:** O Signal tolerou rajadas curtas, mas começou a enfileirar tráfego sustentado de várias sondagens por segundo. Para monitoramento prolongado, mantenha a cadência em torno de `1 Hz` (ou menos), para que cada recibo ainda reflita o estado atual do dispositivo, em vez de esvaziar uma fila acumulada.
* **Artefatos de reconexão:** Quando um dispositivo volta a ficar online, alguns clientes agrupam ou enviam rapidamente vários recibos atrasados. Trate essas rajadas de recibos como um marcador de transição de estado, não como amostras de RTT independentes, ou seu agrupamento / classificador de `active` vs `idle` se ajustará demais ao ruído da reconexão.<sup>[[1]](#references)</sup>

## Inferência de comportamento a partir de rastros de RTT

1. Faça amostragens a ≥1 Hz para capturar os efeitos do agendamento do sistema operacional. No WhatsApp para iOS, RTTs <1 s têm forte correlação com a tela ligada/aplicativo em primeiro plano; RTTs >1 s, com tela desligada/limitação em segundo plano.
2. Crie classificadores simples (limiar ou k-means de dois agrupamentos) que rotulem cada RTT como "ativo" ou "ocioso". Agrupe os rótulos em sequências para deduzir horários de dormir, deslocamentos, expediente ou quando o aplicativo companheiro no desktop está ativo.
3. Correlacione sondagens simultâneas direcionadas a cada dispositivo para descobrir quando os usuários alternam do celular para o desktop, quando os dispositivos companheiros ficam offline e se o aplicativo sofre limitação de taxa por push ou por socket persistente.
4. Em redes reais, evite um único limiar fixo de `1 s`. Inicialize cada dispositivo com uma breve janela de aquecimento e mantenha uma linha de base móvel (por exemplo, a PoC device-activity-tracker usa `threshold = 0.9 * median RTT`) para que a variação entre Wi-Fi e rede celular não comprometa o classificador.<sup>[[1]](#references)[[8]](#references)</sup>

## Inferência de localização a partir do RTT de entrega

O mesmo recurso de temporização pode ser reutilizado para inferir onde está o destinatário, e não apenas se está ativo. O trabalho `Hope of Delivery` mostrou que, ao treinar com distribuições de RTT de locais conhecidos do destinatário, um atacante pode depois classificar a localização da vítima apenas com confirmações de entrega:<sup>[[2]](#references)</sup>

* Crie uma linha de base para o mesmo alvo enquanto ele estiver em vários locais conhecidos (casa, escritório, campus, país A versus país B etc.).
* Para cada local, colete muitos RTTs de mensagens normais e extraia recursos simples, como mediana, variância ou faixas de percentis.
* Durante o ataque real, compare a nova série de sondagens com os agrupamentos treinados. O artigo relata que muitas vezes é possível diferenciar até mesmo locais na mesma cidade, com precisão `>80%` em um cenário com 3 locais.
* Isso funciona melhor quando o atacante controla o ambiente do remetente e faz sondagens em condições de rede semelhantes, pois o caminho medido inclui a rede de acesso do destinatário, a latência de ativação e a infraestrutura do mensageiro.<sup>[[2]](#references)</sup>

Ao contrário dos ataques silenciosos de reação/edição/exclusão acima, a inferência de localização não exige IDs de mensagem inválidos nem pacotes furtivos que alterem o estado. Mensagens comuns com confirmações normais de entrega são suficientes; a contrapartida é menor furtividade, mas maior aplicabilidade a diferentes mensageiros.

## Esgotamento furtivo de recursos

Como cada sondagem silenciosa precisa ser descriptografada e confirmada, o envio contínuo de alternâncias de reação, edições inválidas ou pacotes de exclusão para todos cria um DoS na camada de aplicação:<sup>[[1]](#references)</sup>

* Força o rádio/modem a transmitir/receber a cada segundo → consumo perceptível de bateria, especialmente em aparelhos ociosos.
* Gera tráfego de saída/entrada que consome os planos de dados móveis e pode competir com recursos sensíveis à latência, como chamadas de vídeo.<sup>[[1]](#references)</sup>
* Payloads inválidos grandes aumentam o trabalho de processamento, mas o artigo relata que a criptografia em si representa uma parte insignificante do custo de bateria.<sup>[[1]](#references)</sup>
* No WhatsApp, reações inválidas aceitam muito mais dados do que um emoji normal sugere: medições publicadas encontraram aceitação do lado do servidor de até cerca de `1 MB` por reação.
* Reações grandes demais deixam de produzir recibos de entrega confiáveis quando o corpo ultrapassa cerca de `30 bytes`, mas ainda são encaminhadas e processadas antes de serem descartadas. Mantenha os corpos das reações pequenos quando precisar de ACKs; aumente-os apenas quando o objetivo for esgotamento puro ou transporte encoberto unidirecional.
* Medições públicas chegaram a cerca de `3.7 MB/s` (`~13.3 GB/h`) de tráfego para a vítima nesse modo.



## References

- [1] [Sussurro descuidado: explorando recibos silenciosos de entrega para monitorar usuários em mensageiros instantâneos móveis](https://arxiv.org/html/2411.11194v4)
- [2] [Esperança de entrega: extraindo localizações de usuários de mensageiros instantâneos móveis](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
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
